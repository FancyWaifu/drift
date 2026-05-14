//! Batched UDP send path.
//!
//! On Linux, `sendmmsg(2)` lets us ship an array of packets
//! in one syscall. For a transport with many small outgoing
//! packets, this is a 3-10x throughput win versus per-packet
//! `sendto`. We expose it as a fallback-capable helper:
//!
//!   * Linux: raw `libc::sendmmsg` via the socket's raw fd,
//!     driven off `tokio::net::UdpSocket::async_io`.
//!   * Everything else: sequential `send_to` calls.
//!
//! The API is a single function `send_batch` that takes a
//! slice of `(bytes, dest_addr)` tuples. Callers construct
//! the batch and decide batching policy; nothing in this
//! module imposes a batching discipline.
//!
//! NOTE: this is send-side batching, not GSO segmentation.
//! True GSO (`UDP_SEGMENT` cmsg) would let the kernel split
//! one large buffer into MTU-sized datagrams, but it
//! requires all packets in the batch to share a destination
//! and size. DRIFT's outgoing packets are per-peer and can
//! have varying sizes, so `sendmmsg` without GSO is the
//! right primitive for us — still one syscall per batch,
//! no constraint on homogeneous destinations.

use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Send a batch of `(bytes, destination)` pairs. Returns
/// the number of packets successfully handed off to the
/// kernel. On Linux uses `sendmmsg(2)`; on other platforms
/// falls back to a loop of `send_to` calls.
///
/// Wired into `UdpPacketIO::send_to_batch` (which any caller
/// hits via the `PacketIO::send_to_batch` trait method) — for
/// large batches Linux gets one syscall per call; small
/// batches still use the per-packet path because the
/// sendmmsg setup overhead dominates below ~3 items.
pub(crate) async fn send_batch(
    socket: &UdpSocket,
    packets: &[(Vec<u8>, SocketAddr)],
) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    #[cfg(target_os = "linux")]
    {
        linux::send_batch_mmsg(socket, packets).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        send_batch_fallback(socket, packets).await
    }
}

#[cfg(not(target_os = "linux"))]
async fn send_batch_fallback(
    socket: &UdpSocket,
    packets: &[(Vec<u8>, SocketAddr)],
) -> io::Result<usize> {
    let mut sent = 0;
    for (bytes, dst) in packets {
        socket.send_to(bytes, *dst).await?;
        sent += 1;
    }
    Ok(sent)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::mem::MaybeUninit;
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    pub(super) async fn send_batch_mmsg(
        socket: &UdpSocket,
        packets: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<usize> {
        // Construction of iovec/mmsghdr (which wrap raw
        // pointers) must NOT cross the await point or the
        // returned future is `!Send` — and async-trait fns
        // require `Send` futures. So we do all the libc
        // bookkeeping inside the sync closure, where the
        // pointers' lifetimes are bounded by one syscall.
        // The closure may run multiple times if `async_io`
        // sees EAGAIN — fine, it just rebuilds.
        socket
            .async_io(Interest::WRITABLE, || {
                let n = packets.len();
                let mut addrs: Vec<libc::sockaddr_storage> = (0..n)
                    .map(|_| unsafe { MaybeUninit::zeroed().assume_init() })
                    .collect();
                let mut addr_lens: Vec<libc::socklen_t> = vec![0; n];
                let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(n);
                let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(n);

                for (i, (bytes, dst)) in packets.iter().enumerate() {
                    let len = encode_sockaddr(&mut addrs[i], dst);
                    addr_lens[i] = len;
                    iovecs.push(libc::iovec {
                        iov_base: bytes.as_ptr() as *mut _,
                        iov_len: bytes.len(),
                    });
                }
                for i in 0..n {
                    // `libc::msghdr` has private padding fields on
                    // some targets (notably musl on aarch64), which
                    // means struct-literal initialization is a hard
                    // compile error there. Zero the struct then
                    // fill in the public fields — works uniformly.
                    let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
                    msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut _;
                    msg_hdr.msg_namelen = addr_lens[i];
                    msg_hdr.msg_iov = &mut iovecs[i];
                    msg_hdr.msg_iovlen = 1;
                    msg_hdr.msg_control = std::ptr::null_mut();
                    msg_hdr.msg_controllen = 0;
                    msg_hdr.msg_flags = 0;

                    let mut mm: libc::mmsghdr = unsafe { std::mem::zeroed() };
                    mm.msg_hdr = msg_hdr;
                    mm.msg_len = 0;
                    msgs.push(mm);
                }

                let fd = socket.as_raw_fd();
                let rc =
                    unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as _, 0) };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(rc as usize)
                }
            })
            .await
    }

    fn encode_sockaddr(storage: &mut libc::sockaddr_storage, addr: &SocketAddr) -> libc::socklen_t {
        match addr {
            SocketAddr::V4(v4) => {
                let sin: &mut libc::sockaddr_in =
                    unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in) };
                sin.sin_family = libc::AF_INET as _;
                sin.sin_port = v4.port().to_be();
                sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(v6) => {
                let sin6: &mut libc::sockaddr_in6 =
                    unsafe { &mut *(storage as *mut _ as *mut libc::sockaddr_in6) };
                sin6.sin6_family = libc::AF_INET6 as _;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_flowinfo = v6.flowinfo();
                sin6.sin6_addr.s6_addr = v6.ip().octets();
                sin6.sin6_scope_id = v6.scope_id();
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }
}

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
/// Receive into `buf` and split the result into per-packet
/// `(offset, length, src)` tuples in `out`. On Linux this
/// reads via `recvmsg` and parses the `UDP_GRO` cmsg (if
/// the kernel coalesced same-flow packets) to recover each
/// original segment. Without GRO (kernel < 5.0, or no cmsg
/// returned because no coalescing happened) the call yields
/// a single segment — same behavior as `recv_from`.
///
/// Caller must `out.clear()` before each invocation; this
/// function only pushes.
#[cfg(target_os = "linux")]
pub(crate) async fn recv_batch_gro(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
    out: &mut Vec<(usize, usize, std::net::SocketAddr)>,
) -> std::io::Result<()> {
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    let (n, src, gso_size) = socket
        .async_io(Interest::READABLE, || {
            let mut addr_storage: libc::sockaddr_storage =
                unsafe { MaybeUninit::zeroed().assume_init() };
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            // Enough cmsg space for one UDP_GRO segment-size
            // entry (u16). 64 bytes is plenty.
            let mut cmsg_buf = [0u8; 64];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut addr_storage as *mut _ as *mut _;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
            msg.msg_controllen = cmsg_buf.len() as _;

            let fd = socket.as_raw_fd();
            let rc = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let n = rc as usize;
            let src = decode_sockaddr(&addr_storage, msg.msg_namelen)?;

            // Walk cmsgs to find UDP_GRO. If found, every
            // segment in `buf[..n]` is `gso_size` bytes
            // except possibly the last (which is the
            // remainder n % gso_size).
            let mut gso_size: Option<u16> = None;
            unsafe {
                let mut cmsg_ptr = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg_ptr.is_null() {
                    let level = (*cmsg_ptr).cmsg_level;
                    let typ = (*cmsg_ptr).cmsg_type;
                    if level == libc::SOL_UDP && typ == libc::UDP_GRO {
                        let data_ptr = libc::CMSG_DATA(cmsg_ptr) as *const u16;
                        let sz = std::ptr::read_unaligned(data_ptr);
                        if sz > 0 {
                            gso_size = Some(sz);
                        }
                    }
                    cmsg_ptr = libc::CMSG_NXTHDR(&msg, cmsg_ptr);
                }
            }
            Ok((n, src, gso_size))
        })
        .await?;

    // Split buf[..n] into segments and push tuples.
    match gso_size {
        Some(sz) if (sz as usize) < n => {
            let sz = sz as usize;
            let mut off = 0usize;
            while off + sz <= n {
                out.push((off, sz, src));
                off += sz;
            }
            if off < n {
                out.push((off, n - off, src));
            }
        }
        _ => {
            // No GRO cmsg, or single segment ≤ sz: one packet.
            out.push((0, n, src));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decode_sockaddr(
    storage: &libc::sockaddr_storage,
    namelen: libc::socklen_t,
) -> std::io::Result<std::net::SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    let _ = namelen;
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        f => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown sockaddr family {}", f),
        )),
    }
}

pub(crate) async fn send_batch(
    socket: &UdpSocket,
    packets: &[(Vec<u8>, SocketAddr)],
) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    #[cfg(target_os = "linux")]
    {
        // GSO (UDP_SEGMENT cmsg) is dramatically cheaper than
        // sendmmsg when packets share destination AND size: one
        // skb, one network-stack traversal, kernel/NIC chunks
        // into MTU-sized datagrams. Common case for drift-vpn
        // (one peer, MTU-bounded TUN packets) hits this fast
        // path. Mixed-size or multi-dest batches fall through
        // to sendmmsg (still one syscall, just N skbs).
        if linux::try_send_batch_gso(socket, packets).await? {
            return Ok(packets.len());
        }
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::Interest;

    /// Process-wide flag: once GSO returns EOPNOTSUPP /
    /// ENOTSUPP, never try it again (kernel too old, or
    /// IPv6-on-some-veth quirks). Atomic so multiple worker
    /// tasks can read it lock-free.
    static GSO_BROKEN: AtomicBool = AtomicBool::new(false);

    /// Try to ship the whole batch via UDP_SEGMENT (GSO) in a
    /// single sendmsg. Requirements:
    ///   * ≥ 2 packets
    ///   * all packets to the same destination
    ///   * all packets the same size, EXCEPT optionally the
    ///     last (kernel's GSO contract)
    ///   * segment size fits in u16 (≤ 65535 bytes)
    ///   * total size ≤ 64 KiB (kernel UDP_SEGMENT limit)
    ///
    /// Returns Ok(true) if the GSO call succeeded (caller can
    /// skip sendmmsg), Ok(false) if conditions not met or GSO
    /// is broken on this kernel.
    pub(super) async fn try_send_batch_gso(
        socket: &UdpSocket,
        packets: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<bool> {
        if GSO_BROKEN.load(Ordering::Relaxed) {
            return Ok(false);
        }
        if packets.len() < 2 {
            return Ok(false);
        }
        let dst = packets[0].1;
        let seg_size = packets[0].0.len();
        if seg_size == 0 || seg_size > u16::MAX as usize {
            return Ok(false);
        }
        // All-but-last must equal seg_size; last must be ≤ seg_size.
        let last_idx = packets.len() - 1;
        for (i, (b, d)) in packets.iter().enumerate() {
            if *d != dst {
                return Ok(false);
            }
            if i < last_idx && b.len() != seg_size {
                return Ok(false);
            }
            if i == last_idx && b.len() > seg_size {
                return Ok(false);
            }
        }
        let total_len: usize = packets.iter().map(|(b, _)| b.len()).sum();
        if total_len > 65_535 {
            return Ok(false);
        }

        // Concatenate into one contiguous buffer. (We can avoid
        // this with iovec-per-segment + UDP_SEGMENT, but kernel
        // wants iov_len == total_len for a single skb; multi-iov
        // forces N skbs which defeats the point.)
        let mut buf = Vec::with_capacity(total_len);
        for (b, _) in packets {
            buf.extend_from_slice(b);
        }
        let nsent = packets.len();

        let result: io::Result<()> = socket
            .async_io(Interest::WRITABLE, || {
                let mut addr_storage: libc::sockaddr_storage =
                    unsafe { MaybeUninit::zeroed().assume_init() };
                let addr_len = encode_sockaddr(&mut addr_storage, &dst);

                let mut iov = libc::iovec {
                    iov_base: buf.as_ptr() as *mut _,
                    iov_len: buf.len(),
                };

                // Control message buffer for one UDP_SEGMENT
                // cmsg carrying a u16 segment size.
                let cmsg_space =
                    unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
                let mut cmsg_buf = vec![0u8; cmsg_space];

                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_name = &mut addr_storage as *mut _ as *mut _;
                msg.msg_namelen = addr_len;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
                msg.msg_controllen = cmsg_buf.len() as _;

                unsafe {
                    let cmsg_ptr = libc::CMSG_FIRSTHDR(&msg);
                    if cmsg_ptr.is_null() {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "CMSG_FIRSTHDR returned null",
                        ));
                    }
                    (*cmsg_ptr).cmsg_level = libc::SOL_UDP;
                    (*cmsg_ptr).cmsg_type = libc::UDP_SEGMENT;
                    (*cmsg_ptr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
                    let data_ptr = libc::CMSG_DATA(cmsg_ptr) as *mut u16;
                    *data_ptr = seg_size as u16;
                }

                let fd = socket.as_raw_fd();
                let rc = unsafe { libc::sendmsg(fd, &msg, 0) };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            })
            .await;

        match result {
            Ok(()) => Ok(true),
            Err(e) => {
                // Mark GSO as permanently broken on persistent
                // kernel-side errors so we stop paying the per-call
                // detection cost. Transient errors (EAGAIN handled
                // by async_io, EINTR, ENOBUFS) shouldn't get here.
                let kind = e.raw_os_error();
                if matches!(
                    kind,
                    Some(libc::EOPNOTSUPP) | Some(libc::ENOTSUP) | Some(libc::EINVAL)
                ) {
                    GSO_BROKEN.store(true, Ordering::Relaxed);
                    tracing::warn!(
                        error = %e,
                        "UDP GSO failed; falling back to sendmmsg for this and future batches"
                    );
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

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
                let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as _, 0) };
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

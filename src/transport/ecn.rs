//! Explicit Congestion Notification (ECN, RFC 3168) plumbing.
//!
//! When `TransportConfig::enable_ecn` is true, DRIFT marks all
//! outgoing packets as `ECT(0)` (the "I support ECN" codepoint)
//! and reads the TOS / Traffic Class byte off incoming packets
//! to detect `CE` marks (the "congestion experienced" codepoint).
//! A CE mark is treated by the stream layer as a *gentle*
//! congestion signal — cwnd shrinks by 15% (RFC 8511) instead of
//! the 50% multiplicative decrease that an actual loss event
//! would cause, since the bottleneck is telling us "I'm filling
//! up" rather than "I overflowed."
//!
//! Why is this useful? On an ECN-capable path, we get the
//! congestion signal *before* the bottleneck queue overflows,
//! so we avoid the self-induced loss step that loss-based CC
//! relies on. The catch: a lot of the public internet bleaches
//! ECN bits (middleboxes that strip the codepoint), so the
//! benefit is path-dependent. Datacenters and modern transit
//! generally honor ECN; cellular and consumer broadband often
//! don't. This is why the feature is opt-in.
//!
//! Platform support:
//!   - **Linux**: full. Outbound ECT(0) via IP_TOS / IPV6_TCLASS,
//!     inbound CE detection via `recvmsg` + IP_RECVTOS cmsg.
//!   - **macOS / *BSD**: outbound ECT(0) only. Inbound cmsg is
//!     supported by the kernel but the syscall plumbing is more
//!     fragile, so this module falls back to plain `recv_from`
//!     and surfaces a `false` CE mark on every packet.
//!   - **Windows / other**: no-op. `enable_ecn = true` is
//!     accepted but doesn't change behavior.

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// ECT(0) — RFC 3168 codepoint that says "I support ECN".
/// We always mark outgoing packets with this; the bottleneck
/// router can then upgrade it to `CE` (0x03) if it would
/// otherwise drop the packet.
const ECN_ECT0: libc::c_int = 0x02;

/// Mask for the ECN bits in the IPv4 TOS / IPv6 Traffic Class
/// byte. The other 6 bits are DSCP and we don't touch them.
#[allow(dead_code)]
const ECN_MASK: u8 = 0x03;

/// `CE` codepoint. A router has marked this packet to indicate
/// it would have been dropped under congestion.
#[allow(dead_code)]
const ECN_CE: u8 = 0x03;

/// Set the relevant socket options to enable ECN on `socket`.
/// Best-effort: a platform that doesn't support a particular
/// option just silently leaves it unset rather than failing the
/// whole bind.
pub(crate) fn enable_ecn(socket: &UdpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let local = socket.local_addr()?;

    // Outbound: tell the kernel to set IP_TOS / IPV6_TCLASS to
    // ECT(0) on all packets sent through this socket. This is
    // the only way to *originate* ECN-aware traffic.
    let one: libc::c_int = ECN_ECT0;
    if local.is_ipv4() {
        unsafe {
            // Ignore failure — older kernels may reject; we still
            // run, just without ECN.
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &one as *const _ as *const _,
                std::mem::size_of_val(&one) as _,
            );
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                &one as *const _ as *const _,
                std::mem::size_of_val(&one) as _,
            );
        }
    }

    // Inbound: ask the kernel to deliver the TOS / TCLASS byte
    // alongside each packet via a control message, so we can
    // read CE marks. Only meaningfully wired up on Linux below.
    #[cfg(target_os = "linux")]
    {
        let on: libc::c_int = 1;
        if local.is_ipv4() {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_RECVTOS,
                    &on as *const _ as *const _,
                    std::mem::size_of_val(&on) as _,
                );
            }
        } else {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVTCLASS,
                    &on as *const _ as *const _,
                    std::mem::size_of_val(&on) as _,
                );
            }
        }
    }

    Ok(())
}

/// Verify that the kernel actually applied the ECT(0) outbound
/// mark, by reading IP_TOS / IPV6_TCLASS back via `getsockopt`.
/// Used by tests + the public `is_ecn_enabled` accessor so
/// callers can confirm their config landed.
#[allow(dead_code)]
pub(crate) fn ecn_outbound_active(socket: &UdpSocket) -> bool {
    let fd = socket.as_raw_fd();
    let Ok(local) = socket.local_addr() else {
        return false;
    };
    let mut val: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as _;
    let rc = if local.is_ipv4() {
        unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &mut val as *mut _ as *mut _,
                &mut len,
            )
        }
    } else {
        unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_TCLASS,
                &mut val as *mut _ as *mut _,
                &mut len,
            )
        }
    };
    rc == 0 && (val as u8) & ECN_MASK == ECN_ECT0 as u8
}

/// Async receive that returns the TOS / Traffic Class byte
/// alongside the payload, on platforms that support it. On
/// non-Linux Unix the cmsg path is bypassed and `tos = 0` is
/// returned for every packet (no CE detection).
///
/// Returns `(bytes_read, source_addr, tos_byte)`.
#[cfg(target_os = "linux")]
pub(crate) async fn recv_with_tos(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, u8)> {
    use std::mem::MaybeUninit;
    socket
        .async_io(Interest::READABLE, || {
            let fd = socket.as_raw_fd();
            // Storage for source address.
            let mut src: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            // 64 bytes is more than enough for a single
            // IP_TOS cmsg (which is 1 byte of payload + cmsg
            // header overhead).
            let mut cmsg_buf = [MaybeUninit::<u8>::uninit(); 64];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut src as *mut _ as *mut _;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
            msg.msg_controllen = cmsg_buf.len() as _;

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;

            // Walk the cmsg list looking for IP_TOS / IPV6_TCLASS.
            let mut tos: u8 = 0;
            let mut cmsg_ptr = unsafe { libc_cmsg_firsthdr(&msg) };
            while !cmsg_ptr.is_null() {
                let cmsg = unsafe { &*cmsg_ptr };
                if (cmsg.cmsg_level == libc::IPPROTO_IP
                    && (cmsg.cmsg_type == libc::IP_TOS || cmsg.cmsg_type == libc::IP_RECVTOS))
                    || (cmsg.cmsg_level == libc::IPPROTO_IPV6
                        && cmsg.cmsg_type == libc::IPV6_TCLASS)
                {
                    let data_ptr = unsafe { libc_cmsg_data(cmsg_ptr) };
                    if !data_ptr.is_null() {
                        // The kernel writes either a u8 (IP_TOS)
                        // or a c_int (IPV6_TCLASS). Read the low
                        // byte and mask out the DSCP bits.
                        tos = unsafe { *data_ptr } & ECN_MASK;
                    }
                }
                cmsg_ptr = unsafe { libc_cmsg_nxthdr(&msg, cmsg_ptr) };
            }

            // Decode the source address into a SocketAddr.
            let src_addr = sockaddr_storage_to_socket_addr(&src, msg.msg_namelen);
            match src_addr {
                Some(addr) => Ok((n, addr, tos)),
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unrecognized address family",
                )),
            }
        })
        .await
}

/// Non-Linux fallback: no CE detection.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub(crate) async fn recv_with_tos(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, u8)> {
    let (n, src) = socket.recv_from(buf).await?;
    Ok((n, src, 0))
}

/// Did the kernel mark this packet as having experienced
/// congestion?
#[allow(dead_code)]
pub(crate) fn is_ce(tos: u8) -> bool {
    tos & ECN_MASK == ECN_CE
}

#[cfg(target_os = "linux")]
unsafe fn libc_cmsg_firsthdr(msg: *const libc::msghdr) -> *mut libc::cmsghdr {
    libc::CMSG_FIRSTHDR(msg)
}

#[cfg(target_os = "linux")]
unsafe fn libc_cmsg_nxthdr(
    msg: *const libc::msghdr,
    cmsg: *const libc::cmsghdr,
) -> *mut libc::cmsghdr {
    libc::CMSG_NXTHDR(msg, cmsg)
}

#[cfg(target_os = "linux")]
unsafe fn libc_cmsg_data(cmsg: *const libc::cmsghdr) -> *const u8 {
    libc::CMSG_DATA(cmsg)
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match storage.ss_family as i32 {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            let sin: &libc::sockaddr_in =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = u32::from_be(sin.sin_addr.s_addr);
            let port = u16::from_be(sin.sin_port);
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

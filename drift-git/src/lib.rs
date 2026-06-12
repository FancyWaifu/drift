//! Shared types for `git-remote-drift` (helper) and
//! `drift-git-server` (daemon).
//!
//! Two pieces:
//!
//! 1. **URL parsing.** Git invokes `git-remote-drift drift
//!    drift://<peerhex>@<host>:<port>/<path>`. We parse that into
//!    its three logical parts: peer pubkey, wire transport URL,
//!    and repo path on the server.
//!
//! 2. **Handshake envelope.** When the helper opens a stream to
//!    the server, the first thing it sends is a small text
//!    header naming the git service and the repo path. The
//!    server reads that, validates ACL, and either spawns the
//!    requested git subprocess or sends an error and closes.
//!    Everything after the handshake is raw pack-protocol bytes.

use anyhow::{anyhow, Result};

// The serving daemon, in two flavors. `server.rs` (the bin) is a thin
// dispatcher into one of these.
#[cfg(feature = "native")]
pub mod native_server;

// Portable (no-tokio) serving daemon on drift_proto_std::Session.
// Only compiled for the portable build; the helper stays native.
#[cfg(all(feature = "portable", not(feature = "native")))]
pub mod portable_server;

// ─── URL parsing ──────────────────────────────────────────────────
//
// The user-facing URL we register with git is:
//
//     drift://<peerhex>@<host>:<port>/<repo-path>
//
// Where `<host>:<port>` is the wire-level address the DRIFT
// transport listens on. Default scheme is UDP. Future versions
// can support `drift+tls://...` etc., but v1 keeps it simple.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftGitUrl {
    /// Server's static pubkey (hex, 64 chars → 32 bytes).
    pub peer_pub: [u8; 32],
    /// Underlying DRIFT URL the server is listening on (e.g.
    /// `udp://1.2.3.4:9000`). v1 always uses `udp://`.
    pub wire_url: String,
    /// Repo path on the server (e.g. `/srv/git/myrepo.git`).
    /// Always begins with `/`.
    pub repo_path: String,
}

impl DriftGitUrl {
    /// Parse `drift[+<scheme>]://<peerhex>@<host>:<port>/<repo-path>`.
    ///
    /// Bare `drift://` defaults to UDP. `drift+tcp://`, `drift+tls://`,
    /// `drift+ws://`, `drift+http://`, `drift+onion://` all dispatch
    /// through DRIFT's URL registry to the matching adapter.
    pub fn parse(url: &str) -> Result<Self> {
        // Pull off `drift://` or `drift+<scheme>://`.
        let (wire_scheme, body) = if let Some(rest) = url.strip_prefix("drift+") {
            // rest = "<scheme>://<peerhex>@host:port/path"
            let scheme_end = rest.find("://").ok_or_else(|| {
                anyhow!("malformed URL: drift+<scheme>:// expected, got {:?}", url)
            })?;
            let scheme = &rest[..scheme_end];
            let body = &rest[scheme_end + 3..];
            if scheme.is_empty() {
                return Err(anyhow!(
                    "drift+:// missing transport scheme (try drift+tcp://, drift+tls://, drift+ws://, …)"
                ));
            }
            (scheme.to_string(), body)
        } else {
            let body = url
                .strip_prefix("drift://")
                .ok_or_else(|| anyhow!("URL must start with drift:// or drift+<scheme>://"))?;
            ("udp".to_string(), body)
        };

        let at_idx = body.find('@').ok_or_else(|| {
            anyhow!("URL missing `@` separator (need <peerhex>@<host>:<port>/<path>)")
        })?;
        let (peer_hex, rest) = body.split_at(at_idx);
        let rest = &rest[1..]; // skip '@'
        if peer_hex.len() != 64 {
            return Err(anyhow!(
                "peer pubkey must be 64 hex chars (got {})",
                peer_hex.len()
            ));
        }
        let peer_bytes =
            hex::decode(peer_hex).map_err(|e| anyhow!("invalid hex in peer pubkey: {}", e))?;
        let mut peer_pub = [0u8; 32];
        peer_pub.copy_from_slice(&peer_bytes);

        let slash_idx = rest
            .find('/')
            .ok_or_else(|| anyhow!("URL missing repo path (need /<repo-path> after host:port)"))?;
        let host_port = &rest[..slash_idx];
        let repo_path = &rest[slash_idx..]; // keep leading slash

        let wire_url = format!("{}://{}", wire_scheme, host_port);
        Ok(Self {
            peer_pub,
            wire_url,
            repo_path: repo_path.to_string(),
        })
    }
}

// ─── Stream handshake envelope ────────────────────────────────────
//
// The first thing a helper sends on each new DRIFT stream is a
// short, line-based request. Format:
//
//     drift-git/1\n
//     <service-name>\n
//     <repo-path>\n
//     \n
//
// Server reply on success:
//
//     drift-git/1 ok\n
//     \n
//
// On failure:
//
//     drift-git/1 err <reason>\n
//     \n
//
// After a success reply, both sides switch to raw pack-protocol
// bytes — the server's stdout becomes the stream, and the
// client's bytes flow back into the server's stdin. End-of-stream
// (`recv()` returns None) signals EOF in either direction.

pub(crate) const PROTO_TAG: &str = "drift-git/1";

/// Service the helper wants the server to expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitService {
    /// `git-upload-pack` — server-side handler for `git fetch` /
    /// `git clone`. Server *sends* objects.
    UploadPack,
    /// `git-receive-pack` — server-side handler for `git push`.
    /// Server *receives* objects.
    ReceivePack,
}

impl GitService {
    pub fn from_wire(s: &str) -> Result<Self> {
        match s {
            "git-upload-pack" => Ok(Self::UploadPack),
            "git-receive-pack" => Ok(Self::ReceivePack),
            other => Err(anyhow!("unknown git service {:?}", other)),
        }
    }

    pub fn binary_name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    pub fn is_write(self) -> bool {
        matches!(self, Self::ReceivePack)
    }
}

/// Build the request envelope a helper sends as the first chunk
/// on a freshly-opened stream.
pub fn build_request(service: GitService, repo_path: &str) -> Vec<u8> {
    let s = format!(
        "{}\n{}\n{}\n\n",
        PROTO_TAG,
        service.binary_name(),
        repo_path
    );
    s.into_bytes()
}

/// Parse the request envelope on the server side from a buffer
/// of bytes that the client sent. Returns the parsed service +
/// repo path, plus the byte count consumed (so any trailing
/// pack-protocol bytes already read can be replayed into the
/// child's stdin).
pub fn parse_request(buf: &[u8]) -> Result<(GitService, String, usize)> {
    // Look for the terminating blank line (\n\n).
    let term = buf
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| anyhow!("incomplete handshake (no terminating blank line)"))?;
    let head =
        std::str::from_utf8(&buf[..term]).map_err(|_| anyhow!("non-UTF-8 handshake header"))?;
    let mut lines = head.lines();
    let tag = lines.next().ok_or_else(|| anyhow!("empty handshake"))?;
    if tag != PROTO_TAG {
        return Err(anyhow!(
            "unsupported protocol tag {:?} (this server speaks {})",
            tag,
            PROTO_TAG
        ));
    }
    let service_str = lines
        .next()
        .ok_or_else(|| anyhow!("handshake missing service line"))?;
    let repo_path = lines
        .next()
        .ok_or_else(|| anyhow!("handshake missing repo-path line"))?;
    let service = GitService::from_wire(service_str)?;
    Ok((service, repo_path.to_string(), term + 2))
}

/// Server's success reply — sent verbatim on the stream right
/// after the child process is spawned.
pub fn build_ok_reply() -> Vec<u8> {
    format!("{} ok\n\n", PROTO_TAG).into_bytes()
}

// ─── Framing for the byte tunnel ─────────────────────────────────
//
// DRIFT streams don't have half-close: calling `Stream::close()`
// tears down both directions. Git's pack protocol needs each
// side to be able to signal "I've finished sending; you keep
// going" — the helper finishes uploading the pack, then waits
// for the server's report-status. Without half-close, we need
// a tiny in-band framing marker.
//
// Every chunk on the stream after the handshake reply is one of:
//
//   [0x00, ...bytes] — DATA; payload is the bytes after the tag
//   [0x01]           — END_OF_DATA; this side has no more bytes
//                      to send; receiver should treat it as EOF
//                      on its read pipe but keep writing.
//
// The handshake bytes (request + reply) are *not* framed — they
// flow as raw bytes on the freshly-opened stream. Framing kicks
// in immediately after the handshake terminator.

pub(crate) const FRAME_DATA: u8 = 0x00;
pub(crate) const FRAME_EOD: u8 = 0x01;

/// Wrap a payload in a DATA frame ready for `Stream::send`.
pub fn frame_data(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(FRAME_DATA);
    buf.extend_from_slice(payload);
    buf
}

/// Build the END_OF_DATA marker.
pub fn frame_eod() -> Vec<u8> {
    vec![FRAME_EOD]
}

/// What a peer just received on a tunnel chunk.
pub enum Frame<'a> {
    Data(&'a [u8]),
    EndOfData,
    Unknown(u8),
}

/// Parse a single DRIFT-stream chunk into a frame view.
pub fn parse_frame(chunk: &[u8]) -> Frame<'_> {
    match chunk.first() {
        None => Frame::Unknown(0xff), // empty chunks shouldn't happen
        Some(&FRAME_DATA) => Frame::Data(&chunk[1..]),
        Some(&FRAME_EOD) => Frame::EndOfData,
        Some(&other) => Frame::Unknown(other),
    }
}

/// Server's error reply.
pub fn build_err_reply(reason: &str) -> Vec<u8> {
    format!("{} err {}\n\n", PROTO_TAG, reason).into_bytes()
}

/// Parse the server's reply on the helper side. Returns `Ok(())`
/// on a success reply, `Err(reason)` on error. `consumed` is the
/// byte count consumed (the stream may have buffered pack-
/// protocol bytes after).
pub fn parse_reply(buf: &[u8]) -> Result<usize> {
    let term = buf
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| anyhow!("incomplete reply"))?;
    let head = std::str::from_utf8(&buf[..term]).map_err(|_| anyhow!("non-UTF-8 reply"))?;
    let first = head.lines().next().unwrap_or("");
    if first == format!("{} ok", PROTO_TAG) {
        Ok(term + 2)
    } else if let Some(reason) = first.strip_prefix(&format!("{} err ", PROTO_TAG)) {
        Err(anyhow!("server rejected request: {}", reason))
    } else {
        Err(anyhow!("malformed reply: {:?}", first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_happy() {
        let u = DriftGitUrl::parse(
            "drift://aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899@127.0.0.1:9000/srv/git/foo.git",
        )
        .unwrap();
        assert_eq!(u.wire_url, "udp://127.0.0.1:9000");
        assert_eq!(u.repo_path, "/srv/git/foo.git");
        assert_eq!(u.peer_pub[0], 0xaa);
        assert_eq!(u.peer_pub[31], 0x99);
    }

    #[test]
    fn parse_url_rejects_bad_hex_length() {
        assert!(DriftGitUrl::parse("drift://abc@127.0.0.1:9000/x").is_err());
    }

    #[test]
    fn parse_url_drift_plus_tcp() {
        let u = DriftGitUrl::parse(
            "drift+tcp://aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899@127.0.0.1:9000/r.git",
        )
        .unwrap();
        assert_eq!(u.wire_url, "tcp://127.0.0.1:9000");
    }

    #[test]
    fn parse_url_drift_plus_tls() {
        let u = DriftGitUrl::parse(
            "drift+tls://aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899@127.0.0.1:9000/r.git",
        )
        .unwrap();
        assert_eq!(u.wire_url, "tls://127.0.0.1:9000");
    }

    #[test]
    fn parse_url_drift_plus_ws() {
        let u = DriftGitUrl::parse(
            "drift+ws://aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899@127.0.0.1:9000/r.git",
        )
        .unwrap();
        assert_eq!(u.wire_url, "ws://127.0.0.1:9000");
    }

    #[test]
    fn parse_url_rejects_drift_plus_empty_scheme() {
        assert!(DriftGitUrl::parse(
            "drift+://aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899@127.0.0.1:9000/r.git"
        )
        .is_err());
    }

    #[test]
    fn handshake_round_trip() {
        let req = build_request(GitService::ReceivePack, "/srv/git/foo.git");
        let (svc, path, n) = parse_request(&req).unwrap();
        assert_eq!(svc, GitService::ReceivePack);
        assert_eq!(path, "/srv/git/foo.git");
        assert_eq!(n, req.len());
    }

    #[test]
    fn handshake_with_trailing_bytes() {
        let mut buf = build_request(GitService::UploadPack, "/repo");
        buf.extend_from_slice(b"PACK\x00\x01");
        let (svc, path, n) = parse_request(&buf).unwrap();
        assert_eq!(svc, GitService::UploadPack);
        assert_eq!(path, "/repo");
        // Trailing pack bytes shouldn't be consumed.
        assert_eq!(&buf[n..], b"PACK\x00\x01");
    }

    #[test]
    fn ok_reply_round_trip() {
        let ok = build_ok_reply();
        let n = parse_reply(&ok).unwrap();
        assert_eq!(n, ok.len());
    }

    #[test]
    fn err_reply_round_trip() {
        let err = build_err_reply("no such repo");
        let parsed = parse_reply(&err);
        assert!(parsed.is_err());
        assert!(format!("{}", parsed.unwrap_err()).contains("no such repo"));
    }
}

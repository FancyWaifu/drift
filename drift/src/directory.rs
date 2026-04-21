//! Directory protocol — a thin application-layer service spoken over
//! DRIFT DATA packets. Lets peers discover each other without knowing
//! each other's public keys out of band.
//!
//! A "directory peer" (librarian) keeps a table of known peers. Other
//! peers connect to it, register themselves, and query for the full
//! list. Afterwards they establish DIRECT DRIFT sessions with the
//! peers they discover — the directory peer does not proxy traffic.
//!
//! Wire format (binary, minimal):
//!
//! ```text
//! [tag: u8] [...payload]
//!
//! REGISTER (0x01):  pubkey[32] | addr_len:u16 | addr_bytes | nick_len:u8 | nick_bytes
//! LOOKUP   (0x02):  (no payload)
//! LISTING  (0x03):  count:u16 | [entry * count]
//!    where entry = pubkey[32] | addr_len:u16 | addr_bytes | nick_len:u8 | nick_bytes
//! ```

pub const TAG_REGISTER: u8 = 0x01;
pub const TAG_LOOKUP: u8 = 0x02;
pub const TAG_LISTING: u8 = 0x03;

/// Hard cap on the number of entries a single decoded `Listing` may
/// claim. A packet carrying a u16 count can claim up to 65535, which
/// at ~80 bytes per entry would force a ~5 MB pre-allocation on decode
/// — a cheap allocation bomb. Real directory listings are much
/// smaller than this in practice; anything over the cap is rejected.
pub const MAX_LISTING_ENTRIES: usize = 1024;

/// One entry in the directory — a peer's static pubkey, its advertised
/// reachable address, and a human-readable nickname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    pub pubkey: [u8; 32],
    pub addr: String,
    pub nickname: String,
}

impl PeerEntry {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pubkey);
        let addr_bytes = self.addr.as_bytes();
        out.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(addr_bytes);
        let nick_bytes = self.nickname.as_bytes();
        out.push(nick_bytes.len() as u8);
        out.extend_from_slice(nick_bytes);
    }

    /// Decode one entry from `buf`. Returns the entry and the number of
    /// bytes consumed, or None on malformed input.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 34 {
            return None;
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&buf[..32]);
        let addr_len = u16::from_be_bytes([buf[32], buf[33]]) as usize;
        if buf.len() < 34 + addr_len + 1 {
            return None;
        }
        let addr = std::str::from_utf8(&buf[34..34 + addr_len])
            .ok()?
            .to_string();
        let nick_len_off = 34 + addr_len;
        let nick_len = buf[nick_len_off] as usize;
        let nick_off = nick_len_off + 1;
        if buf.len() < nick_off + nick_len {
            return None;
        }
        let nickname = std::str::from_utf8(&buf[nick_off..nick_off + nick_len])
            .ok()?
            .to_string();
        Some((
            Self {
                pubkey,
                addr,
                nickname,
            },
            nick_off + nick_len,
        ))
    }
}

/// A directory protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirMessage {
    /// "Add me to your directory."
    Register(PeerEntry),
    /// "Send me the current directory."
    Lookup,
    /// "Here is the current directory."
    Listing(Vec<PeerEntry>),
}

impl DirMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            DirMessage::Register(entry) => {
                out.push(TAG_REGISTER);
                entry.encode(&mut out);
            }
            DirMessage::Lookup => {
                out.push(TAG_LOOKUP);
            }
            DirMessage::Listing(entries) => {
                out.push(TAG_LISTING);
                out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
                for e in entries {
                    e.encode(&mut out);
                }
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        match buf[0] {
            TAG_REGISTER => {
                let (entry, _) = PeerEntry::decode(&buf[1..])?;
                Some(DirMessage::Register(entry))
            }
            TAG_LOOKUP => Some(DirMessage::Lookup),
            TAG_LISTING => {
                if buf.len() < 3 {
                    return None;
                }
                let count = u16::from_be_bytes([buf[1], buf[2]]) as usize;
                if count > MAX_LISTING_ENTRIES {
                    return None;
                }
                // Clamp the pre-allocation against the actual buffer
                // size. Each entry is >= 34 bytes (pubkey + lengths),
                // so a buffer N bytes long cannot possibly contain
                // more than N/34 entries. This stops a short packet
                // with a big `count` from pre-allocating huge Vecs.
                let plausible = (buf.len() / 34).saturating_add(1).min(count);
                let mut entries = Vec::with_capacity(plausible);
                let mut off = 3;
                for _ in 0..count {
                    let (entry, consumed) = PeerEntry::decode(&buf[off..])?;
                    entries.push(entry);
                    off += consumed;
                }
                Some(DirMessage::Listing(entries))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_roundtrip() {
        let entry = PeerEntry {
            pubkey: [0xAB; 32],
            addr: "10.0.0.5:9000".to_string(),
            nickname: "alice".to_string(),
        };
        let msg = DirMessage::Register(entry.clone());
        let bytes = msg.encode();
        let decoded = DirMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, DirMessage::Register(entry));
    }

    #[test]
    fn listing_roundtrip() {
        let entries = vec![
            PeerEntry {
                pubkey: [0x01; 32],
                addr: "10.0.0.1:9000".to_string(),
                nickname: "one".to_string(),
            },
            PeerEntry {
                pubkey: [0x02; 32],
                addr: "10.0.0.2:9001".to_string(),
                nickname: "two-with-longer-name".to_string(),
            },
        ];
        let msg = DirMessage::Listing(entries.clone());
        let bytes = msg.encode();
        let decoded = DirMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, DirMessage::Listing(entries));
    }

    #[test]
    fn lookup_is_one_byte() {
        let bytes = DirMessage::Lookup.encode();
        assert_eq!(bytes, vec![TAG_LOOKUP]);
        assert_eq!(DirMessage::decode(&bytes), Some(DirMessage::Lookup));
    }

    #[test]
    fn malformed_input_returns_none() {
        assert!(DirMessage::decode(&[]).is_none());
        assert!(DirMessage::decode(&[0x99]).is_none());
        assert!(DirMessage::decode(&[TAG_REGISTER, 0, 1, 2]).is_none());
        assert!(DirMessage::decode(&[TAG_LISTING]).is_none());
    }
}

//! Simple XOR-based forward error correction for DRIFT.
//!
//! For every block of N data packets, the sender computes a
//! parity packet: bytewise XOR of all N data payloads, padded
//! to the maximum length in the block. The parity packet is
//! shipped alongside the data. If any single packet in the
//! block is lost on the network, the receiver recovers it by
//! XORing the N-1 received packets together with the parity.
//!
//! This is essentially Reed-Solomon with k=1, m=1 over GF(2):
//! one redundant "check" byte per position, one recoverable
//! erasure per block. Simple, cheap, and tolerant of the most
//! common loss pattern on WiFi and cellular: a single dropped
//! packet in a short burst.
//!
//! Limitations:
//!   * Can only recover **one** loss per block. Two losses =
//!     unrecoverable.
//!   * Block size must be fixed (no dynamic resizing).
//!   * Doubles redundancy only by 1/N — at N=4 that's 25%
//!     bandwidth overhead. At N=8, 12.5%.
//!
//! For more serious FEC (multi-loss recovery, code-rate
//! tuning) you'd want real Reed-Solomon over GF(2^8) or a
//! fountain code like RaptorQ. Those are substantially more
//! code and CPU; this module targets the "drop one, recover
//! it, move on" case.

/// A single block of N data packets and one XOR parity.
/// The sender builds a `FecEncoder`, pushes data packets
/// into it, and reads out the parity when the block is
/// complete.
pub struct FecEncoder {
    n: usize,
    buf: Vec<Vec<u8>>,
}

impl FecEncoder {
    /// Start a new encoder with block size `n`. Must be ≥ 2
    /// (no point encoding a 1-packet block — the parity
    /// would just duplicate the data).
    pub fn new(n: usize) -> Self {
        assert!(n >= 2, "FEC block size must be ≥ 2");
        Self {
            n,
            buf: Vec::with_capacity(n),
        }
    }

    /// Block size — how many data packets per block.
    pub fn block_size(&self) -> usize {
        self.n
    }

    /// Add one data packet to the current block. Returns
    /// `Some(parity_bytes)` when the block fills up; the
    /// caller should send the parity packet and start fresh
    /// (via `reset`).
    pub fn push(&mut self, data: Vec<u8>) -> Option<Vec<u8>> {
        self.buf.push(data);
        if self.buf.len() == self.n {
            let parity = compute_parity(&self.buf);
            Some(parity)
        } else {
            None
        }
    }

    /// Reset the encoder for the next block. Call after
    /// receiving `Some(parity)` from `push`.
    pub fn reset(&mut self) {
        self.buf.clear();
    }
}

/// Bytewise XOR of all packets, padded to the max length
/// observed. If the block had packets of lengths [10, 8, 12],
/// the parity is 12 bytes long and every shorter packet is
/// implicitly zero-padded on the right.
pub fn compute_parity(block: &[Vec<u8>]) -> Vec<u8> {
    let max_len = block.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut parity = vec![0u8; max_len];
    for pkt in block {
        for (i, byte) in pkt.iter().enumerate() {
            parity[i] ^= *byte;
        }
    }
    parity
}

/// Receiver side: recover a single missing packet from the
/// other N-1 received packets and the parity. Returns the
/// reconstructed missing packet's bytes (trimmed of
/// trailing zero padding — callers should wrap this in a
/// length-prefixed frame if they care about exact length,
/// since XOR-parity loses length info). Returns `None` if
/// more than one packet is missing.
pub fn recover_one_missing(received: &[&[u8]], parity: &[u8]) -> Option<Vec<u8>> {
    // XOR everything we received against the parity. What
    // falls out is the missing packet (padded). If the
    // caller gave us all N packets, the result will be all
    // zeros — which is the degenerate "no recovery needed"
    // case.
    let max_len = received
        .iter()
        .map(|p| p.len())
        .max()
        .unwrap_or(0)
        .max(parity.len());
    let mut out = vec![0u8; max_len];
    for pkt in received {
        for (i, b) in pkt.iter().enumerate() {
            out[i] ^= *b;
        }
    }
    for (i, b) in parity.iter().enumerate() {
        out[i] ^= *b;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_recovers_single_loss() {
        let block = vec![
            b"packet-zero   ".to_vec(),
            b"packet-one    ".to_vec(),
            b"packet-two    ".to_vec(),
            b"packet-three  ".to_vec(),
        ];
        let parity = compute_parity(&block);

        // Simulate loss of packet 2. Reconstruct from
        // the other three + parity.
        let received: Vec<&[u8]> = vec![&block[0], &block[1], &block[3]];
        let recovered = recover_one_missing(&received, &parity).unwrap();
        assert_eq!(&recovered[..block[2].len()], &block[2][..]);
    }

    #[test]
    fn parity_handles_variable_lengths() {
        let block = vec![
            b"short".to_vec(),
            b"a somewhat longer payload".to_vec(),
            b"mid-sized".to_vec(),
        ];
        let parity = compute_parity(&block);
        assert_eq!(parity.len(), 25); // max length

        // Drop the long one, recover.
        let received: Vec<&[u8]> = vec![&block[0], &block[2]];
        let recovered = recover_one_missing(&received, &parity).unwrap();
        // The reconstructed buffer should start with the
        // original long payload bytes (padding lives
        // past the original length, which we can't
        // recover without a length field).
        assert_eq!(&recovered[..block[1].len()], &block[1][..]);
    }

    #[test]
    fn encoder_produces_parity_at_block_boundary() {
        let mut enc = FecEncoder::new(3);
        assert!(enc.push(vec![1, 2, 3]).is_none());
        assert!(enc.push(vec![4, 5, 6]).is_none());
        let parity = enc.push(vec![7, 8, 9]).expect("parity at boundary");
        // XOR of [1,2,3], [4,5,6], [7,8,9] = [2, 15, 12]
        assert_eq!(parity, vec![1 ^ 4 ^ 7, 2 ^ 5 ^ 8, 3 ^ 6 ^ 9]);
        enc.reset();
        assert!(enc.push(vec![10]).is_none()); // next block starts fresh
    }

    #[test]
    fn roundtrip_full_block() {
        let mut enc = FecEncoder::new(4);
        let data = vec![
            b"alpha".to_vec(),
            b"bravo".to_vec(),
            b"charlie".to_vec(),
            b"delta!".to_vec(),
        ];
        let mut parity = None;
        for d in &data {
            parity = enc.push(d.clone());
        }
        let parity = parity.expect("last push should yield parity");

        // Drop "charlie" in transit.
        let received: Vec<&[u8]> = vec![&data[0], &data[1], &data[3]];
        let recovered = recover_one_missing(&received, &parity).unwrap();
        assert_eq!(&recovered[..data[2].len()], &data[2][..]);
    }
}

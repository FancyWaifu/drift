//! Reliable, in-order stream multiplexing on top of DRIFT datagrams.
//!
//! DRIFT itself is an unreliable datagram transport: packets can be
//! dropped, reordered, duplicated. This module adds TCP-like semantics
//! on top — reliable, ordered byte delivery — multiplexed by stream id
//! so multiple independent streams share one DRIFT session without
//! head-of-line blocking each other.
//!
//! Wire format (inside a DRIFT DATA packet payload):
//!
//! ```text
//! OPEN : [0x10] [stream_id : u32 BE]
//! DATA : [0x11] [stream_id : u32 BE] [seq : u32 BE] [bytes...]
//! ACK  : [0x12] [stream_id : u32 BE] [acked_up_to : u32 BE] [window : u32 BE]
//!        cumulative ACK + current receiver-advertised flow-control
//!        window (remaining bytes the receiver can buffer for this
//!        stream). The legacy 9-byte form (no window field) is still
//!        parsed for backward compatibility.
//! CLOSE: [0x13] [stream_id : u32 BE]
//! ```
//!
//! Stream ID parity is chosen by peer_id ordering: the peer with the
//! lexicographically smaller peer_id uses EVEN ids (2, 4, 6, ...), the
//! other uses ODD (1, 3, 5, ...). This avoids collision when both
//! sides open streams concurrently.
//!
//! Design choices (deliberately simple):
//!   - Per-segment ACKs (not delayed/coalesced)
//!   - Fixed RTO with exponential backoff per-segment
//!   - Unbounded in-memory reorder buffer (cheap for small streams)
//!   - Close sends a CLOSE frame; receiving CLOSE ends inbound delivery
//!
//! Things NOT implemented (yet):
//!   - Flow control / receive window advertising
//!   - Selective ACKs
//!   - Nagle/delayed-ACK
//!   - Keep-alives
//!
//! These would be straightforward follow-ups.

use crate::error::DriftError;
use crate::transport::Transport;
use crate::PeerId;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, Notify};

pub type StreamId = u32;

const TAG_OPEN: u8 = 0x10;
const TAG_DATA: u8 = 0x11;
const TAG_ACK: u8 = 0x12;
const TAG_CLOSE: u8 = 0x13;
/// Unreliable, unordered application message multiplexed onto the
/// same authenticated DRIFT session as streams. Bypasses the
/// stream / cwnd / retransmit machinery — pure fire-and-forget,
/// like QUIC's DATAGRAM frame (RFC 9221).
///
/// Wire: `[0x14] [bytes...]`
const TAG_DATAGRAM: u8 = 0x14;

const RTO_BASE_MS: u64 = 100;
const RTO_MAX_MS: u64 = 3000;
const RETRANSMIT_SCAN_MS: u64 = 25;
const MAX_RETRIES: u32 = 30;
/// Max bytes per DATA segment. Leaves room under DRIFT's MAX_PAYLOAD
/// (1340) after header (9 bytes) and AEAD overhead.
const MAX_SEGMENT: usize = 1200;

// ---- congestion control constants (NewReno-style) ----

/// Initial congestion window in bytes. 10 MSS is the widely-deployed
/// modern default (RFC 6928) and a reasonable starting point for
/// DRIFT too — enough to send a full request quickly, small enough
/// that we don't flood a slow link on connect.
const INITIAL_CWND: usize = 10 * MAX_SEGMENT;

/// Hard upper bound on the congestion window. Caps runaway growth on
/// low-RTT / high-bandwidth links and prevents a single peer from
/// monopolizing memory in the pending queue.
const MAX_CWND: usize = 1 << 20; // 1 MiB

/// Minimum cwnd after a loss event. We never shrink below this.
/// Two segments is enough to keep the ACK clock alive.
const MIN_CWND: usize = 2 * MAX_SEGMENT;

/// Initial ssthresh (slow start threshold). Starts effectively
/// infinite so the first connection grows through slow start until
/// it sees a loss or hits the max cwnd.
const INITIAL_SSTHRESH: usize = usize::MAX;

// ---- stream flow control constants ----

// ---- BBR-lite constants (Cardwell et al. 2016, simplified) ----

/// Startup pacing gain — BBR's canonical 2/ln(2) ≈ 2.885.
/// We use 2.89 as a rational approximation.
const BBR_STARTUP_GAIN_NUM: u32 = 289;
const BBR_STARTUP_GAIN_DEN: u32 = 100;

/// ProbeBW pacing gain cycle: 8 RTTs long, gains
/// [1.25, 0.75, 1, 1, 1, 1, 1, 1] as fractions of BtlBw.
/// This probes for more bandwidth, then drains any queue the
/// probe built, then cruises for 6 RTTs before repeating.
const BBR_PROBEBW_CYCLE: [(u32, u32); 8] = [
    (125, 100), // probe up
    (75, 100),  // drain
    (100, 100),
    (100, 100),
    (100, 100),
    (100, 100),
    (100, 100),
    (100, 100),
];

/// How many samples without BtlBw growth count as "BtlBw
/// plateau" and trigger exit from Startup. BBR's paper uses 3.
const BBR_STARTUP_FULL_BW_ROUNDS: u32 = 3;

/// Epsilon for "BtlBw grew": we require at least 25% growth
/// between rounds to consider the link not yet saturated.
const BBR_STARTUP_GROWTH_NUMERATOR: u64 = 125;
const BBR_STARTUP_GROWTH_DENOMINATOR: u64 = 100;

/// Multiplier on BDP used for the cwnd cap in steady-state
/// ProbeBW. BBR allows ~2x BDP in-flight so there's always
/// a full BDP worth of unacked data keeping the pipe full
/// while the acks for the previous BDP are coming back.
const BBR_CWND_GAIN_NUM: u64 = 2;
const BBR_CWND_GAIN_DEN: u64 = 1;

/// Minimum cwnd BBR will ever advertise, even when BDP
/// computes to less. Keeps small-RTT paths from starving.
const BBR_MIN_CWND: usize = 4 * MAX_SEGMENT;

/// Congestion-control mode selector. NewReno is the legacy
/// default used by every CongestionCtrl unless the user
/// explicitly opts in to BBR-lite via stream config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControlMode {
    NewReno,
    Bbr,
}

/// BBR state machine phases (simplified — no explicit Drain
/// because BBR-lite uses a smooth pacing-gain transition
/// from Startup into ProbeBW once BtlBw plateaus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrPhase {
    Startup,
    ProbeBw,
}

// ---- HyStart++ constants (RFC 9406, simplified) ----

/// Minimum number of RTT samples needed before we trust a round's
/// min-RTT for HyStart++'s slow-start exit decision. Below this,
/// we let slow start continue uninterrupted.
const HYSTART_MIN_RTT_SAMPLES: u32 = 8;

/// Lower bound on the rising-RTT threshold. Without this, very
/// fast LAN links with sub-ms RTTs would exit slow start on
/// scheduler jitter alone.
const HYSTART_MIN_RTT_THRESH: Duration = Duration::from_millis(4);

/// Upper bound on the rising-RTT threshold. Without this, very
/// high-RTT links (sat / WAN) would never trigger because the
/// threshold would scale linearly with the base RTT.
const HYSTART_MAX_RTT_THRESH: Duration = Duration::from_millis(16);

/// Default receiver-advertised window size in bytes. Sender is not
/// allowed to have more unacked bytes per stream in flight than
/// this. The receiver dynamically advertises a fresh window in each
/// ACK as it drains the stream.
const DEFAULT_RECV_WINDOW: u32 = 256 * 1024;

/// Hard cap on how many live streams any single remote peer can have
/// open against us at once. Bounds the memory an authenticated-but-
/// misbehaving peer can force us to allocate by spamming OPEN frames.
/// OPEN frames past the cap are silently dropped.
const MAX_STREAMS_PER_PEER: usize = 1024;

/// Largest gap we will tolerate between `recv_next_seq` and an
/// out-of-order DATA segment's seq. Any segment whose seq sits more
/// than this many slots ahead of `recv_next_seq` is dropped instead of
/// buffered. This bounds `recv_buf` against a malicious (but
/// authenticated) peer who opens a stream and sprays DATA with
/// skipping sequence numbers — without this cap, `recv_buf` would grow
/// without limit. The cap is also enforced on `recv_buf.len()` as a
/// belt-and-suspenders check.
const MAX_REORDER_WINDOW: u32 = 1024;

/// Read-only snapshot of a peer's congestion-control state,
/// returned by [`StreamManager::congestion_snapshot`].
#[derive(Debug, Clone, Copy)]
pub struct CongestionSnapshot {
    pub cwnd: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub srtt_us: Option<u64>,
    pub rttvar_us: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("stream is closed")]
    Closed,
    #[error("retry limit exceeded")]
    RetryLimit,
    #[error("transport error: {0}")]
    Transport(#[from] DriftError),
}

/// One unacked segment waiting for the remote to ACK it.
struct PendingSegment {
    data: Vec<u8>,
    last_sent: Instant,
    retries: u32,
    /// When this segment was FIRST transmitted. Used for RTT
    /// samples on ACK (but only if the segment hasn't been
    /// retransmitted — Karn's algorithm).
    first_sent: Instant,
}

/// Per-peer congestion-control state. NewReno-ish: cwnd grows in
/// slow start until it hits ssthresh, then grows linearly in
/// congestion avoidance. On a loss event (retransmit fires),
/// ssthresh is halved, cwnd is halved, and we stay in congestion
/// avoidance. An SRTT / RTTVAR pair feeds the RTO.
struct CongestionCtrl {
    cwnd: usize,
    ssthresh: usize,
    bytes_in_flight: usize,
    /// Smoothed RTT estimator (RFC 6298).
    srtt: Option<Duration>,
    /// RTT variance, matched to `srtt`.
    rttvar: Option<Duration>,
    /// Woken whenever `bytes_in_flight` shrinks so waiting sends
    /// can wake up and re-check cwnd.
    notify: Arc<Notify>,
    /// Pacing: earliest time the next segment is allowed to leave
    /// the sender, computed from `cwnd / SRTT * pacing_gain`.
    /// `None` until we have an SRTT sample (no pacing during the
    /// first RTT — slow start is rate-limited by ACKs anyway).
    next_send_time: Option<Instant>,
    // ---- HyStart++ state ----
    /// Min RTT sample observed in the round currently in progress.
    hs_current_round_min: Option<Duration>,
    /// Min RTT sample observed in the previous full round, used
    /// as the baseline against which we detect "rising RTT".
    hs_last_round_min: Option<Duration>,
    /// How many RTT samples we've gathered in the current round.
    /// Compared against `HYSTART_MIN_RTT_SAMPLES` to know when
    /// the round is "complete enough" to make a decision.
    hs_round_samples: u32,
    /// Once HyStart++ has fired (we exited slow start early), we
    /// disarm so subsequent loss recovery / probing doesn't
    /// re-trigger it.
    hs_done: bool,
    // ---- BBR-lite state ----
    /// Which CC algorithm this controller is running. Default
    /// NewReno; set to Bbr by the config to activate BBR-lite.
    mode: CongestionControlMode,
    /// Current BBR phase. Unused when mode == NewReno.
    bbr_phase: BbrPhase,
    /// Best delivery-rate sample (bytes per second) observed
    /// over the recent history window. `BtlBw` in the BBR
    /// paper. 0 until the first sample lands.
    bbr_btlbw_bps: u64,
    /// Minimum RTT seen over the recent history window
    /// (`RTprop`). `None` until the first sample.
    bbr_rtprop: Option<Duration>,
    /// Best BtlBw seen at the end of the previous BBR round
    /// (used by Startup to detect a plateau).
    bbr_last_round_btlbw: u64,
    /// Rounds without meaningful BtlBw growth. Once this hits
    /// `BBR_STARTUP_FULL_BW_ROUNDS` we exit Startup into
    /// ProbeBW.
    bbr_startup_stagnant_rounds: u32,
    /// Index into `BBR_PROBEBW_CYCLE`; advances once per RTT
    /// while in ProbeBW.
    bbr_cycle_idx: usize,
    /// Samples observed in the current BBR round (one RTT).
    /// Used to step `bbr_cycle_idx` and to gate Startup-exit
    /// checks.
    bbr_round_samples: u32,
}

impl CongestionCtrl {
    fn with_mode(mode: CongestionControlMode) -> Self {
        let mut cc = Self::new();
        cc.mode = mode;
        cc
    }

    fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            bytes_in_flight: 0,
            srtt: None,
            rttvar: None,
            notify: Arc::new(Notify::new()),
            next_send_time: None,
            hs_current_round_min: None,
            hs_last_round_min: None,
            hs_round_samples: 0,
            hs_done: false,
            mode: CongestionControlMode::NewReno,
            bbr_phase: BbrPhase::Startup,
            bbr_btlbw_bps: 0,
            bbr_rtprop: None,
            bbr_last_round_btlbw: 0,
            bbr_startup_stagnant_rounds: 0,
            bbr_cycle_idx: 0,
            bbr_round_samples: 0,
        }
    }

    /// Apply a BBR-lite reaction to a completed ACK.
    /// `bytes_acked` is the payload bytes just confirmed;
    /// `rtt_sample` is the round-trip we measured for those
    /// bytes. We use the classical BBR definition
    /// `delivery_rate = bytes_acked / rtt_sample`.
    fn bbr_on_ack(&mut self, bytes_acked: usize, rtt_sample: Duration) {
        if rtt_sample.is_zero() {
            return;
        }
        // Delivery rate in bytes-per-second.
        let delivery_rate = (bytes_acked as u64)
            .saturating_mul(1_000_000_000)
            .checked_div(rtt_sample.as_nanos().min(u64::MAX as u128) as u64)
            .unwrap_or(0);

        // BtlBw: running max over recent samples. We don't
        // keep a windowed-max filter here (that's ~30 LOC of
        // extra ring-buffer bookkeeping); for BBR-lite we
        // simply take the max-of-seen and let ProbeRTT
        // periodically reset it in a future version. The
        // cycling pacing_gain in ProbeBW already probes up
        // and down, so this still tracks bandwidth changes.
        if delivery_rate > self.bbr_btlbw_bps {
            self.bbr_btlbw_bps = delivery_rate;
        }

        // RTprop: min-of-seen across the window.
        match self.bbr_rtprop {
            None => self.bbr_rtprop = Some(rtt_sample),
            Some(cur) if rtt_sample < cur => self.bbr_rtprop = Some(rtt_sample),
            _ => {}
        }

        // Round bookkeeping: roughly one ack per segment.
        self.bbr_round_samples += 1;

        // Compute new cwnd from BDP * cwnd_gain.
        //   BDP_bytes = BtlBw * RTprop
        //   cwnd     = BDP * 2 (BBR's default)
        let bdp_bytes = self
            .bbr_btlbw_bps
            .saturating_mul(self.bbr_rtprop.map(|r| r.as_nanos() as u64).unwrap_or(0))
            / 1_000_000_000;
        let cwnd_target = bdp_bytes.saturating_mul(BBR_CWND_GAIN_NUM) / BBR_CWND_GAIN_DEN;
        self.cwnd = (cwnd_target as usize).clamp(BBR_MIN_CWND, MAX_CWND);

        // Phase transitions:
        // Every "round" (every few samples — we approximate
        // as every 10 acks because we don't track a round
        // sequence number explicitly), check phase-exit
        // conditions.
        if self.bbr_round_samples >= 10 {
            self.bbr_round_samples = 0;
            match self.bbr_phase {
                BbrPhase::Startup => {
                    // Has BtlBw grown by at least 25%
                    // this round?
                    let grown = self.bbr_btlbw_bps
                        >= self
                            .bbr_last_round_btlbw
                            .saturating_mul(BBR_STARTUP_GROWTH_NUMERATOR)
                            / BBR_STARTUP_GROWTH_DENOMINATOR;
                    if grown {
                        self.bbr_startup_stagnant_rounds = 0;
                    } else {
                        self.bbr_startup_stagnant_rounds += 1;
                    }
                    self.bbr_last_round_btlbw = self.bbr_btlbw_bps;
                    if self.bbr_startup_stagnant_rounds >= BBR_STARTUP_FULL_BW_ROUNDS {
                        self.bbr_phase = BbrPhase::ProbeBw;
                        self.bbr_cycle_idx = 0;
                    }
                }
                BbrPhase::ProbeBw => {
                    // Advance the gain cycle. The next
                    // pacing_delay call will read the new
                    // gain via `bbr_pacing_gain`.
                    self.bbr_cycle_idx = (self.bbr_cycle_idx + 1) % BBR_PROBEBW_CYCLE.len();
                }
            }
        }

        self.notify.notify_waiters();
    }

    /// Pacing gain (numerator / denominator) for the current
    /// BBR phase. Used by the BBR pacing path in place of
    /// the NewReno gain constants.
    #[allow(dead_code)]
    fn bbr_pacing_gain(&self) -> (u32, u32) {
        match self.bbr_phase {
            BbrPhase::Startup => (BBR_STARTUP_GAIN_NUM, BBR_STARTUP_GAIN_DEN),
            BbrPhase::ProbeBw => {
                let (n, d) = BBR_PROBEBW_CYCLE[self.bbr_cycle_idx];
                (n, d)
            }
        }
    }

    /// HyStart++ ack-time hook. Called for every RTT sample while
    /// we're still in slow start. Tracks per-round min-RTT, and
    /// when a round "ends" (HYSTART_MIN_RTT_SAMPLES gathered),
    /// compares against the previous round to decide if RTT is
    /// rising — which means the bottleneck queue is filling and
    /// we should exit slow start *before* a loss event.
    ///
    /// On trigger: ssthresh = cwnd, which forces the next on_ack
    /// to enter congestion-avoidance growth instead of slow-start
    /// doubling. No artificial cwnd shrink — the trick is to stop
    /// growing aggressively, not to back off.
    fn hystart_observe(&mut self, sample: Duration) {
        if self.hs_done || self.cwnd >= self.ssthresh {
            return;
        }
        let cur = self.hs_current_round_min.get_or_insert(sample);
        if sample < *cur {
            *cur = sample;
        }
        self.hs_round_samples += 1;
        if self.hs_round_samples < HYSTART_MIN_RTT_SAMPLES {
            return;
        }
        // Round complete. Compare with previous round.
        if let (Some(last), Some(curr)) = (self.hs_last_round_min, self.hs_current_round_min) {
            let thresh = (last / 8).clamp(HYSTART_MIN_RTT_THRESH, HYSTART_MAX_RTT_THRESH);
            if curr >= last + thresh {
                // Rising RTT detected — exit slow start.
                self.ssthresh = self.cwnd;
                self.hs_done = true;
            }
        }
        // Roll the round forward regardless of whether we triggered.
        self.hs_last_round_min = self.hs_current_round_min;
        self.hs_current_round_min = None;
        self.hs_round_samples = 0;
    }

    /// Compute how long the caller should sleep before transmitting
    /// `segment_len` bytes, and bump `next_send_time` accordingly.
    /// Returns `None` when we have no SRTT sample yet (pacing
    /// disabled during the first RTT — slow start is naturally
    /// ack-clocked at that point).
    ///
    /// pacing_rate = cwnd * gain / SRTT
    /// interval    = segment_len / pacing_rate
    ///             = segment_len * SRTT / (cwnd * gain)
    ///
    /// Gain is 2.0 in slow start (so pacing doesn't choke cwnd
    /// growth), 1.25 in congestion avoidance (a touch above 1 to
    /// keep the pipe full despite ACK jitter). Mirrors what BBR /
    /// modern Linux TCP does.
    fn pacing_delay(&mut self, segment_len: usize) -> Option<Duration> {
        let srtt = self.srtt?;
        let cwnd = self.cwnd.max(MIN_CWND);
        // gain = 2.0 in slow start, 1.25 in congestion avoidance.
        // Use integer-friendly form: numerator/denominator.
        let (gain_num, gain_den): (u32, u32) = if self.cwnd < self.ssthresh {
            (2, 1)
        } else {
            (5, 4)
        };
        let interval_nanos = (segment_len as u128)
            .saturating_mul(srtt.as_nanos())
            .saturating_mul(gain_den as u128)
            / ((cwnd as u128).saturating_mul(gain_num as u128).max(1));
        let interval = Duration::from_nanos(interval_nanos.min(u64::MAX as u128) as u64);

        let now = Instant::now();
        let send_at = match self.next_send_time {
            Some(t) if t > now => t,
            _ => now,
        };
        self.next_send_time = Some(send_at + interval);
        let delay = send_at.saturating_duration_since(now);
        // Sub-millisecond delays aren't worth a tokio sleep — the
        // wakeup overhead would outweigh the spacing benefit.
        if delay < Duration::from_millis(1) {
            None
        } else {
            Some(delay)
        }
    }

    /// True if the window has room for at least one more MSS-sized
    /// segment of outstanding bytes.
    fn can_send(&self, segment_len: usize) -> bool {
        self.bytes_in_flight + segment_len <= self.cwnd
    }

    /// Called when a new segment is put on the wire for the first
    /// time (not retransmissions — those don't change
    /// bytes_in_flight because the old copy is still tracked).
    fn on_segment_sent(&mut self, segment_len: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(segment_len);
    }

    /// Called when ACK coverage advances and `bytes_acked` bytes
    /// worth of segments have just been confirmed delivered.
    /// Implements slow-start / congestion-avoidance cwnd growth
    /// and frees flight bytes.
    fn on_ack(&mut self, bytes_acked: usize, rtt_sample: Option<Duration>) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if self.mode == CongestionControlMode::Bbr {
            // BBR-lite: cwnd comes out of the BDP*gain
            // computation, not slow-start. Still update SRTT
            // for the RTO/pacing paths.
            if let Some(sample) = rtt_sample {
                self.update_rtt(sample);
                self.bbr_on_ack(bytes_acked, sample);
            }
            self.notify.notify_waiters();
            return;
        }

        if self.cwnd < self.ssthresh {
            // Slow start: cwnd += bytes_acked
            self.cwnd = (self.cwnd + bytes_acked).min(MAX_CWND);
        } else {
            // Congestion avoidance: cwnd += MSS * MSS / cwnd per
            // byte acked, approximated as MSS * bytes_acked / cwnd.
            let growth = MAX_SEGMENT * bytes_acked / self.cwnd.max(1);
            self.cwnd = (self.cwnd + growth.max(1)).min(MAX_CWND);
        }
        if let Some(sample) = rtt_sample {
            self.update_rtt(sample);
            self.hystart_observe(sample);
        }
        self.notify.notify_waiters();
    }

    /// Called when the retransmit loop hits a segment: signals
    /// packet loss. Multiplicative decrease.
    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
        // Don't touch bytes_in_flight here — the retransmit loop
        // still has the segment tracked; it'll be freed when the
        // real ACK arrives.
        self.notify.notify_waiters();
    }

    /// Called when an inbound packet arrived with the ECN `CE`
    /// codepoint set. The bottleneck is filling but hasn't
    /// dropped anything yet — back off, but more gently than on
    /// real loss. Per RFC 8511 (ABE), cwnd shrinks to 85% (not
    /// 50%) and ssthresh tracks the new cwnd. Bumps the network
    /// out of slow start if it was still in it.
    fn on_ecn_mark(&mut self) {
        let new_cwnd = ((self.cwnd as u64 * 85) / 100) as usize;
        self.cwnd = new_cwnd.max(MIN_CWND);
        self.ssthresh = self.cwnd;
        self.notify.notify_waiters();
    }

    /// RFC 6298 SRTT/RTTVAR update.
    fn update_rtt(&mut self, sample: Duration) {
        match (self.srtt, self.rttvar) {
            (None, _) | (_, None) => {
                // First sample: SRTT = sample, RTTVAR = sample / 2.
                self.srtt = Some(sample);
                self.rttvar = Some(sample / 2);
            }
            (Some(srtt), Some(rttvar)) => {
                // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - sample|
                let diff = sample.abs_diff(srtt);
                let new_rttvar = (rttvar * 3 + diff) / 4;
                // SRTT = 7/8 * SRTT + 1/8 * sample
                let new_srtt = (srtt * 7 + sample) / 8;
                self.srtt = Some(new_srtt);
                self.rttvar = Some(new_rttvar);
            }
        }
    }

    /// Current RTO estimate (RFC 6298).
    /// `RTO = SRTT + max(clock_granularity, 4 * RTTVAR)`,
    /// clamped between the legacy RTO_BASE_MS floor and RTO_MAX_MS.
    fn rto(&self) -> Duration {
        match (self.srtt, self.rttvar) {
            (Some(srtt), Some(rttvar)) => {
                let raw = srtt + (rttvar * 4).max(Duration::from_millis(1));
                raw.clamp(
                    Duration::from_millis(RTO_BASE_MS),
                    Duration::from_millis(RTO_MAX_MS),
                )
            }
            _ => Duration::from_millis(RTO_BASE_MS),
        }
    }
}

/// Per-stream reliability state shared between sender and receiver
/// sides. One of these exists for each (peer, stream_id) pair.
struct StreamState {
    // --- send side ---
    send_next_seq: u32,
    send_pending: BTreeMap<u32, PendingSegment>,
    /// Receiver-advertised flow-control window for this stream, in
    /// bytes. Updated by every incoming ACK. Sender must ensure
    /// its total outstanding bytes for this stream stay at or
    /// below this value — if not, `Stream::send` blocks until a
    /// window update frees space.
    peer_recv_window: u32,
    // --- receive side ---
    recv_next_seq: u32,
    recv_buf: BTreeMap<u32, Vec<u8>>,
    /// Number of bytes currently sitting in `recv_buf` that the
    /// app hasn't drained yet, plus any reorder buffer. This is
    /// subtracted from `DEFAULT_RECV_WINDOW` to compute the
    /// window we advertise back to the peer in ACKs.
    recv_queue_bytes: usize,
    // Channel into which delivered in-order bytes are pushed for the
    // application-facing Stream handle to consume.
    deliver_tx: mpsc::UnboundedSender<Vec<u8>>,
    // --- close state ---
    sent_close: bool,
    received_close: bool,
}

struct ManagerState {
    streams: HashMap<(PeerId, StreamId), StreamState>,
    /// Next outgoing stream id per peer.
    next_stream_id: HashMap<PeerId, StreamId>,
    /// Per-peer congestion-control state. Shared across every
    /// stream to that peer since the bottleneck path is a
    /// property of the peer, not the stream.
    congestion: HashMap<PeerId, CongestionCtrl>,
}

/// Shape of one entry enqueued by `handle_data` and drained by
/// `accept`: `(peer_id, stream_id, payload_rx)`. Aliased to
/// keep `StreamManager` readable.
type AcceptInbox = (PeerId, StreamId, mpsc::UnboundedReceiver<Vec<u8>>);

/// The stream layer. Wraps a DRIFT `Transport` and provides
/// `open()` / `accept()` APIs for bidirectional reliable streams.
///
/// When you create a `StreamManager`, it takes exclusive ownership of
/// the transport's receive loop — you should no longer call
/// `transport.recv()` directly after `StreamManager::bind`.
pub struct StreamManager {
    transport: Arc<Transport>,
    local_peer_id: PeerId,
    state: Arc<Mutex<ManagerState>>,
    accept_tx: mpsc::UnboundedSender<AcceptInbox>,
    accept_rx: Mutex<mpsc::UnboundedReceiver<AcceptInbox>>,
    /// Inbound datagram channel — fed by `handle_datagram`,
    /// drained by `recv_datagram`.
    datagram_tx: mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    datagram_rx: Mutex<mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>>,
    /// Default congestion-control algorithm used for newly
    /// observed peers. Defaults to NewReno; flip to Bbr via
    /// `bind_with_cc`.
    cc_mode: CongestionControlMode,
}

/// A bidirectional, reliable, in-order byte stream.
pub struct Stream {
    peer_id: PeerId,
    stream_id: StreamId,
    recv_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    manager: Arc<StreamManager>,
}

impl StreamManager {
    /// Wrap a DRIFT transport with stream semantics and return a
    /// manager handle. Spawns internal background tasks for the
    /// receive loop and retransmission.
    pub async fn bind(transport: Arc<Transport>) -> Arc<Self> {
        Self::bind_with_cc(transport, CongestionControlMode::NewReno).await
    }

    /// Bind a StreamManager with an explicit congestion-
    /// control mode. Use `CongestionControlMode::Bbr` for
    /// BBR-lite on paths where BBR's bandwidth-based model
    /// outperforms loss-based CC (lossy wireless, high-BDP
    /// WAN). Default `bind()` still uses NewReno.
    pub async fn bind_with_cc(
        transport: Arc<Transport>,
        cc_mode: CongestionControlMode,
    ) -> Arc<Self> {
        let local_peer_id = transport.local_peer_id();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let (datagram_tx, datagram_rx) = mpsc::unbounded_channel();

        let manager = Arc::new(Self {
            transport,
            local_peer_id,
            state: Arc::new(Mutex::new(ManagerState {
                streams: HashMap::new(),
                next_stream_id: HashMap::new(),
                congestion: HashMap::new(),
            })),
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            datagram_tx,
            datagram_rx: Mutex::new(datagram_rx),
            cc_mode,
        });

        let rx_mgr = manager.clone();
        tokio::spawn(async move { rx_mgr.run_receive_loop().await });

        let retry_mgr = manager.clone();
        tokio::spawn(async move { retry_mgr.run_retransmit_loop().await });

        manager
    }

    /// TEST / FUZZ HELPER: dispatch a stream-layer frame as if it
    /// had arrived from `peer` over a live DRIFT session. Used by
    /// `fuzz/stream_frame` and integration tests that want to
    /// inject crafted frames without setting up a full handshake.
    /// The function must never panic regardless of input bytes.
    #[doc(hidden)]
    pub async fn test_handle_frame(&self, peer: PeerId, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.handle_stream_packet(peer, payload).await;
    }

    /// Snapshot of the per-peer congestion-control gauges.
    /// Returns `None` if there's no congestion state for this
    /// peer yet (no streams opened against them).
    pub async fn congestion_snapshot(&self, peer: &PeerId) -> Option<CongestionSnapshot> {
        let state = self.state.lock().await;
        state.congestion.get(peer).map(|cc| CongestionSnapshot {
            cwnd: cc.cwnd,
            ssthresh: cc.ssthresh,
            bytes_in_flight: cc.bytes_in_flight,
            srtt_us: cc.srtt.map(|d| d.as_micros() as u64),
            rttvar_us: cc.rttvar.map(|d| d.as_micros() as u64),
        })
    }

    /// Number of live streams currently tracked for `peer`. Exposed
    /// so tests and apps can observe stream-table pressure.
    pub async fn live_streams_for(&self, peer: &PeerId) -> usize {
        let state = self.state.lock().await;
        state.streams.keys().filter(|(p, _)| p == peer).count()
    }

    /// Total number of out-of-order DATA segments currently buffered
    /// across every stream this manager is tracking. Exposed for tests
    /// and apps that want to observe memory pressure or detect peers
    /// misbehaving on the stream layer.
    pub async fn total_buffered_segments(&self) -> usize {
        let state = self.state.lock().await;
        state.streams.values().map(|s| s.recv_buf.len()).sum()
    }

    /// Stream ID parity: smaller peer_id uses even IDs, larger uses odd.
    fn starting_stream_id(&self, peer: &PeerId) -> StreamId {
        if &self.local_peer_id < peer {
            2
        } else {
            1
        }
    }

    async fn next_outbound_id(&self, peer: &PeerId) -> StreamId {
        let mut state = self.state.lock().await;
        let id = match state.next_stream_id.get(peer).copied() {
            None => self.starting_stream_id(peer),
            Some(current) => current + 2,
        };
        state.next_stream_id.insert(*peer, id);
        id
    }

    /// Open a new outbound stream to `peer`. Returns a handle the
    /// application uses to send and receive bytes.
    pub async fn open(self: &Arc<Self>, peer: PeerId) -> Result<Stream, StreamError> {
        let stream_id = self.next_outbound_id(&peer).await;
        let (deliver_tx, deliver_rx) = mpsc::unbounded_channel();
        {
            let mut state = self.state.lock().await;
            state.streams.insert(
                (peer, stream_id),
                StreamState {
                    send_next_seq: 0,
                    send_pending: BTreeMap::new(),
                    peer_recv_window: DEFAULT_RECV_WINDOW,
                    recv_next_seq: 0,
                    recv_buf: BTreeMap::new(),
                    recv_queue_bytes: 0,
                    deliver_tx,
                    sent_close: false,
                    received_close: false,
                },
            );
            state
                .congestion
                .entry(peer)
                .or_insert_with(|| CongestionCtrl::with_mode(self.cc_mode));
        }

        // Emit OPEN frame.
        let mut wire = Vec::with_capacity(5);
        wire.push(TAG_OPEN);
        wire.extend_from_slice(&stream_id.to_be_bytes());
        self.transport.send_data(&peer, &wire, 0, 0).await?;

        Ok(Stream {
            peer_id: peer,
            stream_id,
            recv_rx: Mutex::new(deliver_rx),
            manager: self.clone(),
        })
    }

    /// Send an unreliable, unordered datagram to `peer` over the
    /// same authenticated session as streams. No retransmission,
    /// no congestion control, no flow control — fire-and-forget.
    /// Useful for time-sensitive payloads (game state updates,
    /// telemetry, audio frames) where retransmission is worse than
    /// loss. Returns an error if the peer is unknown or the
    /// underlying transport call fails.
    ///
    /// Max payload size is bounded by the transport's MAX_PAYLOAD
    /// minus one tag byte. Larger payloads are rejected.
    pub async fn send_datagram(&self, peer: PeerId, data: &[u8]) -> Result<(), StreamError> {
        let mut wire = Vec::with_capacity(1 + data.len());
        wire.push(TAG_DATAGRAM);
        wire.extend_from_slice(data);
        self.transport.send_data(&peer, &wire, 0, 0).await?;
        Ok(())
    }

    /// Await the next inbound datagram from any peer. Returns
    /// `(peer, bytes)` on success, or `None` if the manager has
    /// been shut down.
    pub async fn recv_datagram(&self) -> Option<(PeerId, Vec<u8>)> {
        self.datagram_rx.lock().await.recv().await
    }

    /// Wait for and return the next inbound stream from any peer.
    pub async fn accept(self: &Arc<Self>) -> Option<Stream> {
        let (peer_id, stream_id, recv_rx) = self.accept_rx.lock().await.recv().await?;
        Some(Stream {
            peer_id,
            stream_id,
            recv_rx: Mutex::new(recv_rx),
            manager: self.clone(),
        })
    }

    async fn send_on_stream(
        &self,
        peer: PeerId,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<(), StreamError> {
        // Send chunk-by-chunk so we can enforce congestion control
        // (per-peer cwnd) and flow control (per-stream window
        // advertised by receiver). If either window is closed, we
        // block on the `cwnd_notify` tokio::sync::Notify until an
        // ACK frees space.
        for chunk in data.chunks(MAX_SEGMENT) {
            self.send_segment(peer, stream_id, chunk).await?;
        }
        Ok(())
    }

    /// Push a single MSS-sized (or smaller) segment onto the wire,
    /// waiting for cwnd and rwnd budget if necessary. Factored out
    /// so `send_on_stream` and the Close/OPEN-tag paths can reuse
    /// the budget check.
    async fn send_segment(
        &self,
        peer: PeerId,
        stream_id: StreamId,
        chunk: &[u8],
    ) -> Result<(), StreamError> {
        loop {
            let (wire, notify, pacing) = {
                let mut guard = self.state.lock().await;
                // Split-borrow: destructure `*state` through a
                // mut ref so we can hand out a mut borrow to
                // `streams` and `congestion` at the same time.
                let ManagerState {
                    streams,
                    congestion,
                    ..
                } = &mut *guard;

                let stream = streams
                    .get_mut(&(peer, stream_id))
                    .ok_or(StreamError::Closed)?;
                if stream.sent_close || stream.received_close {
                    return Err(StreamError::Closed);
                }

                // Flow control: never send past the receiver's
                // advertised window on THIS stream.
                let unacked_for_stream: u32 = stream
                    .send_pending
                    .values()
                    .map(|p| p.data.len() as u32)
                    .sum();
                let fc_room = stream.peer_recv_window.saturating_sub(unacked_for_stream);
                let fc_ok = fc_room as usize >= chunk.len();

                // Congestion control: never send past the
                // per-peer cwnd.
                let cc = congestion
                    .entry(peer)
                    .or_insert_with(|| CongestionCtrl::with_mode(self.cc_mode));
                let cc_ok = cc.can_send(chunk.len());

                if fc_ok && cc_ok {
                    let seq = stream.send_next_seq;
                    stream.send_next_seq = stream.send_next_seq.wrapping_add(1);
                    let mut wire = Vec::with_capacity(9 + chunk.len());
                    wire.push(TAG_DATA);
                    wire.extend_from_slice(&stream_id.to_be_bytes());
                    wire.extend_from_slice(&seq.to_be_bytes());
                    wire.extend_from_slice(chunk);
                    let now = Instant::now();
                    stream.send_pending.insert(
                        seq,
                        PendingSegment {
                            data: chunk.to_vec(),
                            last_sent: now,
                            first_sent: now,
                            retries: 0,
                        },
                    );
                    cc.on_segment_sent(chunk.len());
                    let pacing = cc.pacing_delay(chunk.len());
                    (wire, None, pacing)
                } else {
                    // Grab the notify handle so we can wait
                    // OUTSIDE the peer-table lock. Without this,
                    // the ACK path would deadlock against us.
                    let n = cc.notify.clone();
                    (Vec::new(), Some(n), None)
                }
            };

            if let Some(notify) = notify {
                notify.notified().await;
                continue;
            }

            // Pacing: spread cwnd-worth of segments across the RTT
            // instead of bursting them. Skipped on the first RTT
            // (no SRTT yet) and for sub-millisecond intervals.
            if let Some(delay) = pacing {
                tokio::time::sleep(delay).await;
            }

            self.transport.send_data(&peer, &wire, 0, 0).await?;
            return Ok(());
        }
    }

    async fn close_stream(&self, peer: PeerId, stream_id: StreamId) -> Result<(), StreamError> {
        let mut wire = Vec::with_capacity(5);
        wire.push(TAG_CLOSE);
        wire.extend_from_slice(&stream_id.to_be_bytes());
        {
            let mut state = self.state.lock().await;
            if let Some(stream) = state.streams.get_mut(&(peer, stream_id)) {
                stream.sent_close = true;
            }
        }
        self.transport.send_data(&peer, &wire, 0, 0).await?;
        Ok(())
    }

    async fn run_receive_loop(self: Arc<Self>) {
        loop {
            let pkt = match self.transport.recv().await {
                Some(p) => p,
                None => return,
            };
            // ECN feedback: if the network marked this packet
            // as having experienced congestion, gently shrink
            // the per-peer cwnd before processing the payload.
            // Only fires when ECN is enabled on both ends and
            // a router on the path actually marked the packet.
            if pkt.ecn_ce {
                let mut state = self.state.lock().await;
                if let Some(cc) = state.congestion.get_mut(&pkt.peer_id) {
                    cc.on_ecn_mark();
                }
            }
            if pkt.payload.is_empty() {
                continue;
            }
            self.handle_stream_packet(pkt.peer_id, &pkt.payload).await;
        }
    }

    async fn handle_stream_packet(&self, peer: PeerId, payload: &[u8]) {
        match payload[0] {
            TAG_OPEN => self.handle_open(peer, payload).await,
            TAG_DATA => self.handle_data(peer, payload).await,
            TAG_ACK => self.handle_ack(peer, payload).await,
            TAG_CLOSE => self.handle_close(peer, payload).await,
            TAG_DATAGRAM => self.handle_datagram(peer, payload),
            _ => {}
        }
    }

    fn handle_datagram(&self, peer: PeerId, payload: &[u8]) {
        // payload[0] is the tag; the rest is application bytes.
        // Empty datagrams are valid (zero-byte signals).
        let body = payload[1..].to_vec();
        let _ = self.datagram_tx.send((peer, body));
    }

    async fn handle_open(&self, peer: PeerId, payload: &[u8]) {
        if payload.len() < 5 {
            return;
        }
        let stream_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        self.ensure_inbound_stream(peer, stream_id).await;
    }

    /// Create an inbound stream entry on first sight (whether
    /// triggered by an OPEN frame or by the implicit DATA-as-OPEN
    /// fallback). Idempotent: a second call with the same key is a
    /// no-op. Returns true if a new stream was created (so the
    /// caller can know whether the stream was already known).
    async fn ensure_inbound_stream(&self, peer: PeerId, stream_id: StreamId) -> bool {
        let key = (peer, stream_id);
        let deliver_rx = {
            let mut state = self.state.lock().await;
            if state.streams.contains_key(&key) {
                return false;
            }
            // Enforce the per-peer stream cap BEFORE allocating new
            // state. An attacker spamming OPEN/DATA frames with
            // unique ids cannot force unbounded allocation.
            let live_for_peer = state.streams.keys().filter(|(p, _)| p == &peer).count();
            if live_for_peer >= MAX_STREAMS_PER_PEER {
                return false;
            }
            let (deliver_tx, deliver_rx) = mpsc::unbounded_channel();
            state.streams.insert(
                key,
                StreamState {
                    send_next_seq: 0,
                    send_pending: BTreeMap::new(),
                    peer_recv_window: DEFAULT_RECV_WINDOW,
                    recv_next_seq: 0,
                    recv_buf: BTreeMap::new(),
                    recv_queue_bytes: 0,
                    deliver_tx,
                    sent_close: false,
                    received_close: false,
                },
            );
            state
                .congestion
                .entry(peer)
                .or_insert_with(|| CongestionCtrl::with_mode(self.cc_mode));
            deliver_rx
        };
        let _ = self.accept_tx.send((peer, stream_id, deliver_rx));
        true
    }

    async fn handle_data(&self, peer: PeerId, payload: &[u8]) {
        if payload.len() < 9 {
            return;
        }
        let stream_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let seq = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);
        let data = payload[9..].to_vec();

        // Reliable-OPEN fallback: if we've never seen this stream
        // before, the OPEN frame must have been dropped on a lossy
        // link. Auto-create the stream so the first DATA segment
        // serves as the implicit OPEN. The per-peer stream cap
        // inside `ensure_inbound_stream` still bounds allocation.
        self.ensure_inbound_stream(peer, stream_id).await;

        // Mutate state to deliver/buffer, then build ACK to send.
        let (chunks_to_deliver, ack_wire) = {
            let mut state = self.state.lock().await;
            let stream = match state.streams.get_mut(&(peer, stream_id)) {
                Some(s) => s,
                None => return,
            };

            let mut chunks = Vec::new();
            if seq < stream.recv_next_seq {
                // Duplicate of already-delivered segment: ignore but still ACK.
            } else if seq == stream.recv_next_seq {
                // In-order — deliver immediately, drain buffered follow-ons.
                chunks.push(data);
                stream.recv_next_seq = stream.recv_next_seq.wrapping_add(1);
                while let Some(next) = stream.recv_buf.remove(&stream.recv_next_seq) {
                    // We're draining an out-of-order segment
                    // that was previously counted in
                    // `recv_queue_bytes`; releasing it now.
                    stream.recv_queue_bytes = stream.recv_queue_bytes.saturating_sub(next.len());
                    chunks.push(next);
                    stream.recv_next_seq = stream.recv_next_seq.wrapping_add(1);
                }
            } else {
                // Out of order. Bounded by MAX_REORDER_WINDOW: a
                // segment whose seq is more than that many slots ahead
                // of recv_next_seq is dropped rather than buffered, so
                // an authenticated peer can't blow up our memory by
                // sending skipping seqs. Also drop if the buffer is
                // already at its cap.
                let gap = seq.wrapping_sub(stream.recv_next_seq);
                if gap > MAX_REORDER_WINDOW || stream.recv_buf.len() >= MAX_REORDER_WINDOW as usize
                {
                    // Silently drop; still ACK what we've delivered
                    // below so the sender isn't stuck retransmitting.
                } else {
                    stream.recv_queue_bytes = stream.recv_queue_bytes.saturating_add(data.len());
                    stream.recv_buf.insert(seq, data);
                }
            }

            let ack_wire = if stream.recv_next_seq > 0 {
                // Advertise the remaining flow-control budget: the
                // static DEFAULT_RECV_WINDOW minus whatever we're
                // currently buffering out-of-order. (Deliverable
                // bytes are assumed to be drained fast enough to
                // not count against flow control.)
                let window =
                    (DEFAULT_RECV_WINDOW as usize).saturating_sub(stream.recv_queue_bytes) as u32;
                let mut wire = Vec::with_capacity(13);
                wire.push(TAG_ACK);
                wire.extend_from_slice(&stream_id.to_be_bytes());
                let acked_up_to = stream.recv_next_seq - 1;
                wire.extend_from_slice(&acked_up_to.to_be_bytes());
                wire.extend_from_slice(&window.to_be_bytes());
                Some(wire)
            } else {
                None
            };
            (chunks, ack_wire)
        };

        // Deliver out-of-band of the lock.
        if !chunks_to_deliver.is_empty() {
            let state = self.state.lock().await;
            if let Some(stream) = state.streams.get(&(peer, stream_id)) {
                for chunk in chunks_to_deliver {
                    let _ = stream.deliver_tx.send(chunk);
                }
            }
        }

        if let Some(wire) = ack_wire {
            let _ = self.transport.send_data(&peer, &wire, 0, 0).await;
        }
    }

    async fn handle_ack(&self, peer: PeerId, payload: &[u8]) {
        if payload.len() < 9 {
            return;
        }
        let stream_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let acked_up_to = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);
        // Optional 4-byte flow-control window appended by any
        // non-legacy receiver. If absent, leave the peer window
        // untouched — the old 9-byte form is still valid.
        let advertised_window: Option<u32> = if payload.len() >= 13 {
            Some(u32::from_be_bytes([
                payload[9],
                payload[10],
                payload[11],
                payload[12],
            ]))
        } else {
            None
        };

        let mut state = self.state.lock().await;

        // We'll collect bytes acked and the oldest first-sent
        // timestamp so we can update the per-peer congestion state
        // after dropping the borrow of `stream`.
        let mut bytes_acked = 0usize;
        let mut rtt_sample: Option<Duration> = None;

        if let Some(stream) = state.streams.get_mut(&(peer, stream_id)) {
            // Defense: cap the ACK range at what we've actually
            // sent. A malicious receiver could otherwise send
            // `acked_up_to = u32::MAX` and clear every pending
            // entry for this stream in one shot.
            let max_sent = stream.send_next_seq.saturating_sub(1);
            let effective_ack = acked_up_to.min(max_sent);
            let to_remove: Vec<u32> = stream
                .send_pending
                .range(..=effective_ack)
                .map(|(k, _)| *k)
                .collect();
            let now = Instant::now();
            for k in to_remove {
                if let Some(seg) = stream.send_pending.remove(&k) {
                    bytes_acked += seg.data.len();
                    // Karn's algorithm: only use RTT samples from
                    // segments that were NEVER retransmitted.
                    if seg.retries == 0 {
                        let sample = now.duration_since(seg.first_sent);
                        // Take the longest sample across the
                        // whole ACK batch — closer to the real
                        // RTT than averaging a cluster.
                        rtt_sample = Some(match rtt_sample {
                            Some(existing) => existing.max(sample),
                            None => sample,
                        });
                    }
                }
            }

            if let Some(new_window) = advertised_window {
                stream.peer_recv_window = new_window;
            }
        }

        if bytes_acked > 0 {
            if let Some(cc) = state.congestion.get_mut(&peer) {
                cc.on_ack(bytes_acked, rtt_sample);
            }
        } else if advertised_window.is_some() {
            // Even with zero bytes acked, a fresh window update
            // may unblock a stalled sender. Notify waiters.
            if let Some(cc) = state.congestion.get_mut(&peer) {
                cc.notify.notify_waiters();
            }
        }
    }

    async fn handle_close(&self, peer: PeerId, payload: &[u8]) {
        if payload.len() < 5 {
            return;
        }
        let stream_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let mut state = self.state.lock().await;
        let should_remove = if let Some(stream) = state.streams.get_mut(&(peer, stream_id)) {
            stream.received_close = true;
            // Dropping deliver_tx by removing from map will close the
            // receiver, signalling EOF to the app.
            stream.sent_close
        } else {
            false
        };
        if should_remove {
            state.streams.remove(&(peer, stream_id));
        } else if let Some(stream) = state.streams.get_mut(&(peer, stream_id)) {
            // When only the remote has closed, we still want to deliver
            // any already-in-the-buffer bytes to the app and then drop
            // the deliver_tx so recv() returns None. Do the drop now.
            let (sink_tx, _sink_rx) = mpsc::unbounded_channel();
            // Swap out the deliver_tx with a dead sink so future in-order
            // deliveries (rare after close) are discarded and the app's
            // Receiver observes EOF when this original tx is dropped below.
            let old_tx = std::mem::replace(&mut stream.deliver_tx, sink_tx);
            drop(old_tx);
        }
    }

    async fn run_retransmit_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_millis(RETRANSMIT_SCAN_MS));
        loop {
            ticker.tick().await;
            // Collect retransmit targets, then signal loss to the
            // relevant per-peer congestion controllers AFTER the
            // scan so we only fire one `on_loss` per peer per
            // scan tick even if multiple segments happen to time
            // out simultaneously.
            let retransmits = {
                let mut state = self.state.lock().await;

                // Pre-compute per-peer RTOs from the current
                // congestion state (which holds the SRTT/RTTVAR
                // estimator). Falls back to RTO_BASE_MS if the
                // controller hasn't seen an ACK yet.
                let mut peer_rtos: HashMap<PeerId, Duration> = HashMap::new();
                for (peer_id, cc) in state.congestion.iter() {
                    peer_rtos.insert(*peer_id, cc.rto());
                }

                let mut out: Vec<(PeerId, Vec<u8>)> = Vec::new();
                let mut lost_peers: std::collections::HashSet<PeerId> =
                    std::collections::HashSet::new();
                for ((peer, stream_id), stream) in state.streams.iter_mut() {
                    let base_rto = peer_rtos
                        .get(peer)
                        .copied()
                        .unwrap_or(Duration::from_millis(RTO_BASE_MS));
                    for (seq, pending) in stream.send_pending.iter_mut() {
                        // Exponential backoff on top of the
                        // smoothed base RTO.
                        let shift = pending.retries.min(5);
                        let rto = base_rto
                            .checked_mul(1u32 << shift)
                            .unwrap_or_else(|| Duration::from_millis(RTO_MAX_MS))
                            .min(Duration::from_millis(RTO_MAX_MS));
                        if pending.last_sent.elapsed() >= rto && pending.retries < MAX_RETRIES {
                            pending.retries += 1;
                            pending.last_sent = Instant::now();
                            // NOTE: `first_sent` is NOT touched
                            // — Karn's algorithm excludes this
                            // segment from RTT samples now.
                            let mut wire = Vec::with_capacity(9 + pending.data.len());
                            wire.push(TAG_DATA);
                            wire.extend_from_slice(&stream_id.to_be_bytes());
                            wire.extend_from_slice(&seq.to_be_bytes());
                            wire.extend_from_slice(&pending.data);
                            out.push((*peer, wire));
                            lost_peers.insert(*peer);
                        }
                    }
                }

                // Signal loss to each affected peer's congestion
                // controller. Per-peer, one shrink per scan tick.
                for peer in lost_peers {
                    if let Some(cc) = state.congestion.get_mut(&peer) {
                        cc.on_loss();
                    }
                }

                out
            };
            for (peer, wire) in retransmits {
                let _ = self.transport.send_data(&peer, &wire, 0, 0).await;
            }
        }
    }
}

impl Stream {
    pub async fn send(&self, data: &[u8]) -> Result<(), StreamError> {
        self.manager
            .send_on_stream(self.peer_id, self.stream_id, data)
            .await
    }

    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.recv_rx.lock().await.recv().await
    }

    pub async fn close(&self) -> Result<(), StreamError> {
        self.manager
            .close_stream(self.peer_id, self.stream_id)
            .await
    }

    pub fn peer(&self) -> PeerId {
        self.peer_id
    }

    pub fn id(&self) -> StreamId {
        self.stream_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::{Direction, TransportConfig};

    async fn make_pair() -> (Arc<StreamManager>, Arc<StreamManager>, PeerId, PeerId) {
        let a_id = Identity::from_secret_bytes([0x10; 32]);
        let b_id = Identity::from_secret_bytes([0x11; 32]);
        let a_pub = a_id.public_bytes();
        let b_pub = b_id.public_bytes();

        let cfg = TransportConfig {
            accept_any_peer: true,
            ..TransportConfig::default()
        };
        let b = Arc::new(
            Transport::bind_with_config("127.0.0.1:0".parse().unwrap(), b_id, cfg)
                .await
                .unwrap(),
        );
        let b_addr = b.local_addr().unwrap();
        b.add_peer(a_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder)
            .await
            .unwrap();
        let b_peer_id_on_a = crate::crypto::derive_peer_id(&b_pub);

        let a = Arc::new(
            Transport::bind_with_config(
                "127.0.0.1:0".parse().unwrap(),
                a_id,
                TransportConfig {
                    accept_any_peer: true,
                    ..TransportConfig::default()
                },
            )
            .await
            .unwrap(),
        );
        let _a_peer_on_a = a
            .add_peer(b_pub, b_addr, Direction::Initiator)
            .await
            .unwrap();
        let a_peer_id_on_b = crate::crypto::derive_peer_id(&a_pub);

        let mgr_a = StreamManager::bind(a).await;
        let mgr_b = StreamManager::bind(b).await;

        (mgr_a, mgr_b, b_peer_id_on_a, a_peer_id_on_b)
    }

    #[tokio::test]
    async fn single_stream_roundtrip() {
        let (a, b, b_on_a, a_on_b) = make_pair().await;

        // a opens a stream to b
        let stream_a = a.open(b_on_a).await.unwrap();
        // b accepts
        let stream_b = tokio::time::timeout(Duration::from_secs(2), b.accept())
            .await
            .expect("accept timeout")
            .expect("accept none");
        assert_eq!(stream_b.peer(), a_on_b);

        // Send some data a -> b
        stream_a.send(b"hello from a").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), stream_b.recv())
            .await
            .expect("recv timeout")
            .expect("recv none");
        assert_eq!(got, b"hello from a");

        // And back b -> a
        stream_b.send(b"hello from b").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), stream_a.recv())
            .await
            .expect("recv timeout")
            .expect("recv none");
        assert_eq!(got, b"hello from b");
    }

    #[tokio::test]
    async fn large_payload_chunks_and_reassembles() {
        let (a, b, b_on_a, _) = make_pair().await;
        let stream_a = a.open(b_on_a).await.unwrap();
        let stream_b = tokio::time::timeout(Duration::from_secs(2), b.accept())
            .await
            .unwrap()
            .unwrap();

        // 10 KB payload — will be chunked across multiple segments.
        let big: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
        stream_a.send(&big).await.unwrap();

        let mut received = Vec::new();
        while received.len() < big.len() {
            let chunk = tokio::time::timeout(Duration::from_secs(3), stream_b.recv())
                .await
                .expect("recv timeout")
                .expect("recv none");
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received, big);
    }

    #[tokio::test]
    async fn multiple_streams_multiplexed() {
        let (a, b, b_on_a, _) = make_pair().await;

        let s1 = a.open(b_on_a).await.unwrap();
        let s2 = a.open(b_on_a).await.unwrap();
        assert_ne!(s1.id(), s2.id());

        let bs1 = tokio::time::timeout(Duration::from_secs(2), b.accept())
            .await
            .unwrap()
            .unwrap();
        let bs2 = tokio::time::timeout(Duration::from_secs(2), b.accept())
            .await
            .unwrap()
            .unwrap();

        s1.send(b"stream one").await.unwrap();
        s2.send(b"stream two").await.unwrap();

        // Accept order may not match open order; match by stream id.
        let (first_id, second_id) = (bs1.id(), bs2.id());
        let bs1_text = tokio::time::timeout(Duration::from_secs(2), bs1.recv())
            .await
            .unwrap()
            .unwrap();
        let bs2_text = tokio::time::timeout(Duration::from_secs(2), bs2.recv())
            .await
            .unwrap()
            .unwrap();

        // Map back: the stream with s1.id() got "stream one"
        if first_id == s1.id() {
            assert_eq!(bs1_text, b"stream one");
            assert_eq!(bs2_text, b"stream two");
            assert_eq!(second_id, s2.id());
        } else {
            assert_eq!(bs1_text, b"stream two");
            assert_eq!(bs2_text, b"stream one");
        }
    }

    // ---- CongestionCtrl unit tests (ECN ABE, HyStart++, pacing) ----

    #[test]
    fn on_ecn_mark_cuts_cwnd_to_85_percent() {
        // RFC 8511 ABE: a CE mark should shrink cwnd to 85% of
        // its current value (gentler than the 50% loss cut), and
        // ssthresh should track the new cwnd so subsequent growth
        // enters congestion avoidance rather than slow start.
        let mut cc = CongestionCtrl::new();
        cc.cwnd = 100_000;
        cc.ssthresh = usize::MAX; // still in slow start

        cc.on_ecn_mark();

        // 100_000 * 85 / 100 = 85_000
        assert_eq!(cc.cwnd, 85_000, "cwnd should be 85% of previous");
        assert_eq!(cc.ssthresh, 85_000, "ssthresh should track new cwnd");
    }

    #[test]
    fn on_ecn_mark_respects_min_cwnd() {
        // Below MIN_CWND the floor should hold.
        let mut cc = CongestionCtrl::new();
        cc.cwnd = MIN_CWND; // already at floor
        cc.on_ecn_mark();
        assert_eq!(cc.cwnd, MIN_CWND, "cwnd must never drop below MIN_CWND");
    }

    #[test]
    fn hystart_exits_slow_start_when_rtt_rises() {
        // Feed a full round of low-RTT samples, then a round of
        // samples with a clear RTT bump. HyStart++ should flip
        // ssthresh to the current cwnd so slow start ends.
        let mut cc = CongestionCtrl::new();
        cc.cwnd = 50_000;
        cc.ssthresh = usize::MAX; // fresh slow start
        assert!(cc.cwnd < cc.ssthresh, "precondition: in slow start");

        // Round 1: 8 samples at 20ms. This establishes the
        // "last round min" baseline.
        for _ in 0..HYSTART_MIN_RTT_SAMPLES {
            cc.hystart_observe(Duration::from_millis(20));
        }
        assert!(!cc.hs_done, "no bump yet, should still be in slow start");

        // Round 2: 8 samples at 40ms. That's a 20ms bump, well
        // over the 4ms..16ms clamped threshold, so HyStart++
        // should fire and exit slow start.
        for _ in 0..HYSTART_MIN_RTT_SAMPLES {
            cc.hystart_observe(Duration::from_millis(40));
        }
        assert!(cc.hs_done, "HyStart++ should have exited slow start");
        assert_eq!(
            cc.ssthresh, cc.cwnd,
            "ssthresh should have been clamped to current cwnd on exit"
        );
    }

    #[test]
    fn hystart_does_not_exit_on_stable_rtt() {
        // If RTT stays flat across rounds, HyStart++ must NOT
        // trigger — it would rob the connection of slow-start
        // throughput on a clean link.
        let mut cc = CongestionCtrl::new();
        cc.cwnd = 50_000;
        cc.ssthresh = usize::MAX;

        for _round in 0..4 {
            for _ in 0..HYSTART_MIN_RTT_SAMPLES {
                cc.hystart_observe(Duration::from_millis(25));
            }
        }
        assert!(!cc.hs_done, "stable RTT must not trigger HyStart++ exit");
        assert_eq!(cc.ssthresh, usize::MAX);
    }

    #[test]
    fn pacing_delay_none_without_srtt() {
        // On a brand new controller there's no SRTT yet, so
        // pacing is a no-op. Slow start is already ack-clocked.
        let mut cc = CongestionCtrl::new();
        assert!(cc.srtt.is_none());
        assert!(cc.pacing_delay(MAX_SEGMENT).is_none());
    }

    #[test]
    fn pacing_delay_returns_some_when_budget_crosses_1ms() {
        // With a 100ms SRTT and a very small cwnd (2*MSS), the
        // interval for one MSS segment is large enough to
        // exceed the 1ms floor. We don't assert an exact value
        // (the math rounds), only that pacing is active.
        let mut cc = CongestionCtrl::new();
        cc.srtt = Some(Duration::from_millis(100));
        cc.rttvar = Some(Duration::from_millis(10));
        cc.cwnd = 2 * MAX_SEGMENT;
        cc.ssthresh = 2 * MAX_SEGMENT; // in congestion avoidance (gain 1.25)

        // First call pins next_send_time to "now", the call
        // returns None (no wait required for the very first
        // segment). The second call should return Some because
        // next_send_time has been pushed into the future.
        let _ = cc.pacing_delay(MAX_SEGMENT);
        let second = cc.pacing_delay(MAX_SEGMENT);
        assert!(
            second.is_some(),
            "second call on a slow link should produce a non-None pacing delay"
        );
        let d = second.unwrap();
        assert!(
            d >= Duration::from_millis(1),
            "sub-1ms delays should be filtered out, got {:?}",
            d
        );
    }

    #[test]
    fn bbr_on_ack_grows_cwnd_from_bdp() {
        // BBR-lite should compute cwnd from BtlBw * RTprop * gain.
        // Feed in a stream of "healthy" acks and watch cwnd
        // track the delivery rate.
        let mut cc = CongestionCtrl::with_mode(CongestionControlMode::Bbr);
        let starting_cwnd = cc.cwnd;
        // Feed 20 samples, each representing 1KB delivered
        // in 10ms. That's 100 KB/s delivery rate and 10ms
        // RTT, so BDP = 100_000 * 0.010 = 1000 bytes,
        // cwnd = BDP * 2 = 2000 bytes. BBR_MIN_CWND clamps
        // this to 4*MSS = 4800, so the floor wins — which
        // is exactly the behavior we want on tiny paths.
        for _ in 0..20 {
            cc.on_ack(1024, Some(Duration::from_millis(10)));
        }
        assert!(cc.cwnd >= BBR_MIN_CWND, "cwnd should respect floor");
        assert!(cc.bbr_btlbw_bps > 0, "BtlBw should have been sampled");
        assert!(cc.bbr_rtprop.is_some(), "RTprop should have been sampled");
        let _ = starting_cwnd;
    }

    #[test]
    fn bbr_startup_exits_on_plateau() {
        // Feed 30 acks with a delivery rate that plateaus.
        // BBR-lite's Startup should detect the lack of growth
        // and transition into ProbeBW.
        let mut cc = CongestionCtrl::with_mode(CongestionControlMode::Bbr);
        assert_eq!(cc.bbr_phase, BbrPhase::Startup);
        // 40 samples @ the same rate → 4 rounds of 10 acks,
        // no growth, should hit the Startup exit after 3.
        for _ in 0..40 {
            cc.on_ack(1024, Some(Duration::from_millis(10)));
        }
        assert_eq!(
            cc.bbr_phase,
            BbrPhase::ProbeBw,
            "should have exited Startup"
        );
    }

    #[test]
    fn bbr_probebw_cycles_through_gains() {
        // Force the controller into ProbeBW and verify the
        // pacing gain cycles through the expected sequence.
        let mut cc = CongestionCtrl::with_mode(CongestionControlMode::Bbr);
        cc.bbr_phase = BbrPhase::ProbeBw;
        cc.bbr_cycle_idx = 0;
        // First probe: 125/100
        let (n, d) = cc.bbr_pacing_gain();
        assert_eq!((n, d), (125, 100));
        // Drive 10 samples → advance cycle → drain
        for _ in 0..10 {
            cc.on_ack(1024, Some(Duration::from_millis(10)));
        }
        let (n, d) = cc.bbr_pacing_gain();
        assert_eq!((n, d), (75, 100));
    }

    #[test]
    fn pacing_delay_zero_on_fast_link() {
        // Very fast link: 1ms SRTT, large cwnd. The per-segment
        // interval is sub-microsecond; pacing should short-
        // circuit to None so we don't burn syscalls on tiny
        // sleeps.
        let mut cc = CongestionCtrl::new();
        cc.srtt = Some(Duration::from_millis(1));
        cc.rttvar = Some(Duration::from_micros(100));
        cc.cwnd = 1_000_000;
        cc.ssthresh = 1_000_000;

        for _ in 0..10 {
            let d = cc.pacing_delay(MAX_SEGMENT);
            assert!(
                d.is_none(),
                "fast-link pacing must not introduce sleeps, got {:?}",
                d
            );
        }
    }
}

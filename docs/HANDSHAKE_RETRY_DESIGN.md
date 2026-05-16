# Handshake retry timing — fixing the dial-up retry storm

## The bug

`TransportConfig::handshake_retry_base_ms` is 50ms. The retry
loop uses exponential backoff: attempts fire at 50, 100, 200,
400, 800… ms after the previous send.

When the HELLO payload is small (classical ~116 B), the first
HELLO finishes transmitting in microseconds on any modern link,
and 50ms is a perfectly reasonable RTO. The first retry exists
to recover from a dropped packet, not to compensate for slow
transmission.

When the HELLO is large (hybrid PQ ~1294 B), the assumption
breaks. On a 10 Kbps link (1.25 KB/s), one HELLO takes
**~1040 ms** to push through the pipe. The 50ms retry timer
fires after 50ms — long before the first HELLO has even cleared
the local sender — and queues *another* 1294-byte HELLO. The
next retry at +100ms queues a third. By the time the first
HELLO would have actually finished transmitting at 1s, the
sender has queued 6+ duplicates onto a 10 Kbps link.

Result: the link saturates with redundant HELLOs, nothing
arrives intact within the handshake_max_attempts window
(default 10 × backoff), and the handshake times out cleanly.

This is the classic [bufferbloat][bbr] failure mode applied to
handshake setup: aggressive retransmission *causes* the
unreachability it tries to recover from.

The PQ-T.8 test sweep caught it:

> `scenario_10kbps_bandwidth_cap` — 1.4s with classical HELLO,
> times out at 15s with hybrid HELLO.

## The fix: align the default RTO with the rest of the
## reliability-protocol world

Every other major transport protocol uses a **1-second initial
RTO** before any RTT measurement is available. This is
literally a 14-year-old IETF standard.

> **RFC 6298 §2.1** (2011): "Until a round-trip time (RTT)
> measurement has been made for a segment sent between the
> sender and receiver, the sender SHOULD set RTO ← 1 second,
> though the 'backing off' on repeated retransmission discussed
> in (5.5) still applies."

A Google engineering retrospective on TCP tuning summarized why
this value was chosen:

> "RFC 6298 specifies using one full second as an initial
> timeout as sufficient for nearly all real-world network paths
> — and this value has long been hardcoded into the Linux
> kernel."

The choice of 1 second is calibrated to cover the slowest
realistic real-world link delivery time *for typical payload
sizes*. A 1300-byte payload on a 10 Kbps link bursts that
budget (~1040 ms just for the local sender to push the packet
out), but only marginally — one extra retransmit in the worst
case, instead of six.

QUIC uses the same calculation for its Probe Timeout (PTO):

> **RFC 9002 §6.2.1**: "QUIC uses a probe timeout (PTO), with a
> timer based on TCP's retransmission timeout (RTO) computation;
> see [RFC6298]."

WireGuard, the most relevant cousin (UDP-based crypto
tunnel handshake), is even more conservative:

> [`wireguard-go/device/constants.go`][wg-constants]:
> ```go
> const (
>     RekeyTimeout            = time.Second * 5
>     MaxTimerHandshakes      = 90 / 5
>     RekeyTimeoutJitterMaxMs = 334
> )
> ```
>
> Per [the WireGuard protocol description][wg-protocol]: "A
> handshake initiation is retried after `REKEY_TIMEOUT + jitter`
> ms, if a response has not been received, where jitter is some
> random value between 0 and 333 ms."

WireGuard accepts a ~5-second handshake completion time
(realistic for the first packet over an unknown path) as the
price of *not* retransmission-storming. They try up to 18 times
(90 seconds total) before giving up.

## Proposed change

Two-part change. The first is non-controversial (matches RFC
6298). The second adds nothing-to-lose tuning.

### 1. Bump `handshake_retry_base_ms` default from 50 to 1000

```rust
impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            // RFC 6298 §2.1: pre-RTT-sample initial RTO is 1s.
            // Matches TCP (Linux kernel default since 2.6), QUIC
            // PTO, and is conservatively bounded against the
            // RFC's value. Reduces retransmission storm on slow
            // links — see docs/HANDSHAKE_RETRY_DESIGN.md.
            handshake_retry_base_ms: 1000,
            // ...
        }
    }
}
```

LAN-only deployments that genuinely benefit from sub-second
recovery can override:

```rust
TransportConfig {
    handshake_retry_base_ms: 50, // I know my path RTT is ~1ms
    ..Default::default()
}
```

### 2. After first RTT sample, switch to RTT-driven retry

DRIFT already takes a passive RTT sample at HELLO_ACK arrival
(see `peer.update_neighbor_rtt(…)` in `handle_hello_ack`). For
**subsequent** handshakes against the same peer (rekey, post-
restart), use `max(200ms, 4 * SRTT)` instead of the static
default.

Per RFC 6298 §2.4: "Whenever RTO is computed, if it is less than
1 second, then the RTO SHOULD be rounded up to 1 second." For
DRIFT we relax this floor to 200ms because all our targets are
either local-network or general internet — never the
transcontinental dial-up cases RFC 6298 was hedging against.

Code sketch:

```rust
let retry_ms = match peer.rtt_estimate() {
    None => self.config.handshake_retry_base_ms,           // first contact
    Some(srtt) => (4 * srtt.as_millis() as u64).max(200),  // known peer
};
```

### 3. (Optional) Add `handshake_jitter_max_ms`

Currently DRIFT's retries fire at exact deterministic
intervals. WireGuard adds 0-334ms jitter to break up
synchronization between many peers handshaking
simultaneously (mesh bootstrap, post-restart reconnect storms).
The cost is one `rand::random()` per retry. The benefit shows
up only at scale (>50 simultaneous handshakes).

Default 0 (no jitter) for simplicity; bridges in heavy
federation deployments can opt in.

## Why this isn't PQ-specific

The 50ms default was wrong for classical HELLOs on slow links
*too* — it just didn't show up because classical HELLOs are
small enough that one retry fits comfortably in the link
budget. PQ makes the bug visible. The fix is correct for
classical and hybrid alike: align with RFC 6298, match what
TCP/QUIC/WireGuard already do.

Sanity check with the current adapter tests:

- LAN UDP, classical HELLO, RTT ~0.1ms: handshake completes in
  the first attempt. The 1s RTO never fires. **No regression**.
- LAN UDP, hybrid HELLO, RTT ~0.1ms: same. **No regression**.
- WAN UDP, classical HELLO, RTT 30ms, no loss: completes first
  try. RTO never fires. **No regression**.
- 10 Kbps link, hybrid HELLO: first attempt takes ~2s end-to-
  end. Second attempt fires at 1s before the first completes,
  doubling traffic on the slow link. Recoverable (handshake
  completes within ~3s) where today's 50ms blows up entirely.
  **Improvement**.

## Why payload-aware is a tempting trap

The "correct" answer to the 10 Kbps case is:

```
initial_rto = payload_bytes / estimated_min_bandwidth
            + estimated_max_rtt
            + safety_margin
```

We don't know `estimated_min_bandwidth` at handshake time. We
could assume some conservative value (e.g. 100 Kbps) but then:

- On a fast link with a *real* MTU/firewall problem, the
  retransmit timing is too slow to recover within the
  attempts budget.
- A bad actor could throttle their reads to make the legitimate
  client think the link is slow and back off; not really a
  threat but worth noticing.
- It complicates testability — the bench currently has a fixed
  RTO per-attempt.

The "right" thing is the same thing TCP does: assume the
worst-case real-world delivery time (~1s), and adapt downward
from there once you have actual RTT measurements. RFC 6298 has
the math right; we just need to use it.

## Implementation steps

1. Change `TransportConfig::default()` `handshake_retry_base_ms`
   from 50 to 1000.
2. Update `iot()` and `realtime()` presets to keep their
   current explicit values (IoT keeps 500ms; realtime can
   stay at 25ms — explicit opt-in to aggressive RTO).
3. Add `Peer::rtt_estimate() -> Option<Duration>` accessor.
4. Add RTT-aware path in `run_handshake_retry_loop` at
   `mod.rs:5562`: compute `retry_ms` per RFC 6298 §2.4.
5. Re-run T.8: `scenario_10kbps_bandwidth_cap` should now
   pass with hybrid_pq=true defaults flipped on.
6. Re-run full test suite to confirm no regression on the
   ~80 existing handshake tests (LAN-fast ones).
7. Add a new `tests/handshake_retry_timing.rs` test that
   asserts the RTO is in the expected range under various
   path conditions.

## Test plan for the fix

```rust
// drift/tests/handshake_retry_timing.rs

#[tokio::test]
async fn classical_handshake_on_lan_unaffected_by_rto_bump() {
    // RTO=1s default. LAN handshake completes in <100ms.
    // Asserts RTO never fires.
}

#[tokio::test]
async fn hybrid_handshake_completes_at_10kbps_with_rto_1s() {
    // Replicates scenario_10kbps_bandwidth_cap with hybrid_pq
    // on. Asserts handshake completes within
    // 4 * estimated_round_trip = ~10s budget.
}

#[tokio::test]
async fn second_handshake_uses_rtt_derived_rto() {
    // Establish a session (passive RTT sample taken). Force a
    // re-handshake. Asserts retransmit timer is
    // max(200ms, 4 * SRTT), not the 1s default.
}
```

## Citations

- [RFC 6298 — Computing TCP's Retransmission Timer (June 2011)][rfc6298]
- [RFC 9002 — QUIC Loss Detection and Congestion Control (May 2021)][rfc9002]
- [A Brief Look at Tuning TCP Retransmission Behaviour, Google
  Engineering (PDF)][google-tcp-tuning]
- [WireGuard Protocol & Cryptography description][wg-protocol]
- [`wireguard-go/device/constants.go`][wg-constants]
- [Cloudflare — "Post-quantum to origins" (Sep 2023)][cf-pq] —
  Specifically: *"With Kyber, the ClientHello doesn't fit
  anymore with typical packet sizes and needs to be split over
  two network packets."*
- [Adam Langley — Real-world measurements of structured-lattices
  and supersingular isogenies in TLS (Oct 2019)][langley-cecpq2]
  — End-to-end Chrome + Cloudflare PQ-handshake measurement.
- [BBR: Congestion-Based Congestion Control, Cardwell et al.
  ACM Queue 2016][bbr] — Background on why buffer-filling
  retransmission storms misdiagnose link state.

[rfc6298]: https://www.rfc-editor.org/rfc/rfc6298
[rfc9002]: https://www.rfc-editor.org/rfc/rfc9002.pdf
[google-tcp-tuning]: https://services.google.com/fh/files/misc/a_brief_look_at_tuning_tcp_retransmission_behaviour.pdf
[wg-protocol]: https://www.wireguard.com/protocol/
[wg-constants]: https://github.com/WireGuard/wireguard-go/blob/master/device/constants.go
[cf-pq]: https://blog.cloudflare.com/post-quantum-to-origins/
[langley-cecpq2]: https://www.imperialviolet.org/2019/10/30/pqsivssl.html
[bbr]: https://queue.acm.org/detail.cfm?id=3022184

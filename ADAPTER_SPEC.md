# DRIFT PacketIO Adapter Specification

Version 1.0 — April 2026

## Overview

This document specifies the contract for building a custom transport adapter for DRIFT. An adapter implements the `PacketIO` trait, which allows DRIFT to send and receive packets over any medium — UDP, TCP, WebSocket, serial, BLE, LoRa, or anything else that can move bytes between two endpoints.

DRIFT ships with two built-in adapters:
- **UdpPacketIO** — standard UDP datagram transport (default)
- **TcpPacketIO** — length-prefix framed TCP for firewall traversal

Third-party adapters plug in at runtime via `Transport::add_interface()`. Once attached, DRIFT handles everything else: identity, encryption, handshaking, congestion control, stream multiplexing, mesh routing, and cross-interface forwarding.

## The Trait

```rust
#[async_trait]
pub trait PacketIO: Send + Sync + 'static {
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
```

Three methods. That is the entire contract.

## Method Specifications

### `send_to(buf, dest) -> Result<usize>`

**Purpose:** Transmit `buf` as a single, discrete packet to `dest`.

**Requirements:**
- The entire contents of `buf` must be delivered as one atomic unit. The receiver's `recv_from` must return exactly these bytes in one call — no splitting, no merging with adjacent packets.
- If the underlying medium is a byte stream (TCP, serial), the adapter MUST implement framing to preserve packet boundaries. The recommended framing is length-prefix: `[length: u16 BE][payload]`.
- The `dest` parameter is a `SocketAddr`. For IP-based mediums, use it as the actual destination. For non-IP mediums (serial, BLE), ignore it — the physical link determines the destination.
- Returns the number of payload bytes accepted (not including any framing overhead).
- On transient errors (EAGAIN, buffer full), the adapter may either retry internally or return `Err`. DRIFT will retry at the protocol level.
- Must not block indefinitely. If the underlying medium is congested, return an error after a reasonable timeout rather than blocking forever.

**Maximum packet size:** DRIFT's `MAX_PACKET` is 1400 bytes. Adapters must support at least 1400-byte payloads. If the medium has a smaller MTU, the adapter must either fragment/reassemble transparently or return `Err(InvalidInput)` for oversized packets.

### `recv_from(buf) -> Result<(usize, SocketAddr)>`

**Purpose:** Receive the next complete packet into `buf`.

**Requirements:**
- Must block (async await) until a complete packet is available.
- Returns `(bytes_read, source_address)`.
- `bytes_read` is the exact payload size — no framing bytes, no padding.
- `source_address` identifies who sent the packet. For IP mediums, this is the sender's IP:port. For point-to-point mediums (serial, BLE), return a fixed placeholder address (e.g., `0.0.0.0:1`).
- The buffer `buf` is at least 1400 bytes. If a received packet exceeds `buf.len()`, the adapter should either truncate (with an error) or return `Err(InvalidData)`.
- Must return `Err` when the underlying connection/medium is closed or broken, so DRIFT can detect transport failure.

### `local_addr() -> Result<SocketAddr>`

**Purpose:** Return the local address this adapter is bound to.

**Requirements:**
- For IP mediums: return the actual bound address (e.g., `0.0.0.0:9000`).
- For non-IP mediums: return a placeholder (e.g., `0.0.0.0:0`).
- Must not block or perform I/O.

### Optional: `as_raw_fd() -> Option<RawFd>` (Unix only)

**Purpose:** Expose the underlying file descriptor for platform-specific operations (ECN socket options, sendmmsg batching).

**Default:** Returns `None`. Only implement if your adapter wraps a real file descriptor.

## Framing for Byte-Stream Mediums

If your medium delivers a continuous byte stream rather than discrete packets (TCP, serial, UART, SSH channel), you MUST add framing to recover DRIFT's packet boundaries.

### Recommended: Length-prefix framing

```
[length: u16 big-endian][payload: `length` bytes]
```

- Maximum frame size: 65535 bytes (u16 max). DRIFT packets are ≤1400 bytes, so this is always sufficient.
- The length field counts only the payload, not itself.
- Both sides must agree on the framing format. DRIFT's built-in `TcpPacketIO` uses this format.

### Alternative: SLIP (RFC 1055)

For serial/UART links where you need byte-stuffing:

```
[SLIP_END (0xC0)]
[payload with 0xC0 escaped as 0xDB 0xDC, 0xDB escaped as 0xDB 0xDD]
[SLIP_END (0xC0)]
```

- Slightly more overhead than length-prefix (escape sequences), but works on raw byte streams without knowing the frame length in advance.
- Well-suited for half-duplex radio links where length-prefix would require buffering.

### Alternative: COBS (Consistent Overhead Byte Stuffing)

For constrained links where predictable overhead matters:

- Fixed 1-byte overhead per 254 bytes of payload.
- Delimiter: 0x00.
- More complex to implement than SLIP but guarantees bounded overhead.

## Medium-Specific Guidance

### Datagram Mediums (UDP, SCTP, Unix SOCK_DGRAM)

No framing needed. `send_to` maps directly to the underlying send syscall; `recv_from` maps to recv. The OS preserves packet boundaries natively.

**Adapter complexity:** ~30 LOC.

### Message-Based Mediums (WebSocket, WebRTC DataChannel, MQTT)

No framing needed if the medium guarantees per-message delivery. Map each DRIFT packet to one message.

**Adapter complexity:** ~40-60 LOC.

### Byte-Stream Mediums (TCP, TLS, serial, SSH, named pipes)

Framing required. Use length-prefix for simplicity or SLIP for serial.

**Adapter complexity:** ~80-100 LOC.

### Half-Duplex / Broadcast Mediums (LoRa, amateur radio)

Special considerations:
- **Collision avoidance:** The adapter should implement CSMA/CA or a time-slotting scheme. DRIFT doesn't know about the physical medium's contention model.
- **MTU:** LoRa payloads are typically 51-222 bytes depending on spreading factor. DRIFT's short header (7 bytes) + auth tag (16 bytes) = 23 bytes overhead, leaving 28-199 bytes for payload. If `MAX_PACKET` (1400 bytes) exceeds the MTU, the adapter must fragment and reassemble.
- **`dest` parameter:** Ignored on broadcast mediums. All stations hear every transmission; DRIFT's `dst_id` in the header determines who processes it.

**Adapter complexity:** ~100-200 LOC (including framing + fragmentation).

## Lifecycle

### Initialization

1. Create your adapter (connect the TCP stream, open the serial port, etc.).
2. Wrap it in `Arc<dyn PacketIO>`.
3. Either:
   - Pass it to `Transport::bind_with_io(io, identity, config)` as the sole interface.
   - Call `transport.add_interface("name", io)` to attach it alongside existing interfaces.

### Runtime

- DRIFT spawns one async recv loop per interface. Each loop calls `recv_from` in a tight loop and feeds received packets into the shared processing pipeline.
- Outgoing packets are routed to the interface tagged on the destination peer. If a peer handshook via your adapter, all subsequent traffic to that peer flows through your adapter.
- Cross-interface forwarding happens automatically via DRIFT's mesh layer. A packet arriving on interface 0 (UDP) addressed to a peer on interface 1 (your adapter) gets forwarded without the adapter needing to know.

### Teardown

- When `recv_from` returns `Err`, the recv loop for that interface exits. Other interfaces continue running.
- The adapter's `Drop` impl should clean up underlying resources (close sockets, release ports).
- DRIFT does NOT call any explicit "close" method on the adapter. Implement `Drop` for cleanup.

## Error Handling

| Adapter returns | DRIFT behavior |
|---|---|
| `Ok(n)` from `send_to` | Packet accepted. Metrics bump. |
| `Err(WouldBlock)` from `send_to` | DRIFT retries at the protocol level (handshake retry, stream retransmit). |
| `Err(other)` from `send_to` | Logged as warning. Packet dropped. Protocol retransmit will recover if the stream layer is in use. |
| `Ok((n, src))` from `recv_from` | Packet processed normally. |
| `Err(any)` from `recv_from` | Recv loop for this interface exits. Other interfaces continue. Peers reachable only through this interface become unreachable until the adapter is re-added. |

## Congestion Control

DRIFT runs its own congestion control (NewReno or BBR-lite) in userspace. If your underlying medium also has CC (e.g., TCP), the two will compete — TCP backs off on loss, DRIFT sees slower delivery and backs off too, creating a "double penalty."

**Recommendation for CC-enabled mediums:** Set `TransportConfig` to use a high initial cwnd and consider disabling DRIFT's CC in a future config option. For now, the double-CC penalty is the price of TCP firewall traversal; it's still better than "can't connect at all because UDP is blocked."

**Recommendation for CC-free mediums (LoRa, serial):** DRIFT's CC provides backpressure that the medium doesn't have. Leave it enabled. It prevents a fast sender from overwhelming a slow link.

## Testing Your Adapter

### Required: Unit Test

Verify framing round-trip:

```rust
#[tokio::test]
async fn framing_roundtrip() {
    let (client_io, server_io) = create_connected_pair().await;

    // Send 100 variable-length packets.
    for i in 0..100u32 {
        let payload = vec![0xAA; (i as usize % 50) + 1];
        client_io.send_to(&payload, PLACEHOLDER).await.unwrap();
    }

    // Receive and verify each arrives with exact original length.
    for i in 0..100u32 {
        let mut buf = vec![0u8; 1400];
        let (n, _) = server_io.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, (i as usize % 50) + 1);
    }
}
```

### Required: Integration Test

Full DRIFT handshake + DATA over your adapter:

```rust
#[tokio::test]
async fn full_handshake_over_my_adapter() {
    let (client_io, server_io) = create_connected_pair().await;

    let bob = Transport::bind_with_io(
        Arc::new(server_io), bob_id, TransportConfig::default()
    ).await.unwrap();
    bob.add_peer(alice_pub, "0.0.0.0:0".parse().unwrap(), Direction::Responder).await.unwrap();

    let alice = Transport::bind_with_io(
        Arc::new(client_io), alice_id, TransportConfig::default()
    ).await.unwrap();
    let bob_peer = alice.add_peer(bob_pub, PLACEHOLDER, Direction::Initiator).await.unwrap();

    alice.send_data(&bob_peer, b"hello", 0, 0).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(5), bob.recv()).await.unwrap().unwrap();
    assert_eq!(pkt.payload, b"hello");
    assert_eq!(alice.metrics().handshakes_completed, 1);
}
```

### Recommended: Cross-Interface Test

Your adapter bridged with the built-in UDP adapter:

```rust
#[tokio::test]
async fn cross_interface_bridge() {
    let bridge = Transport::bind("127.0.0.1:0".parse().unwrap(), bridge_id).await.unwrap();
    let (adapter_io, peer_io) = create_connected_pair().await;
    bridge.add_interface("my-adapter", Arc::new(adapter_io));

    // UDP peer and adapter peer should both be reachable through the bridge.
}
```

### Recommended: Stress Test

Push 64 KB through a stream over your adapter. Verify byte-for-byte integrity. This exercises the retransmit loop, congestion control, and flow control under your adapter's latency/loss characteristics.

## Checklist for Adapter Authors

- [ ] `send_to` delivers the exact buffer as one atomic packet
- [ ] `recv_from` returns exactly one packet per call (no merging)
- [ ] Packet boundaries are preserved (framing if byte-stream medium)
- [ ] Maximum 1400-byte payload supported
- [ ] `recv_from` returns `Err` on connection close (not infinite hang)
- [ ] `local_addr` returns a valid or placeholder SocketAddr
- [ ] Unit test: framing round-trip with variable-length packets
- [ ] Integration test: full DRIFT handshake + DATA delivery
- [ ] `Drop` cleans up underlying resources
- [ ] Thread-safe: `Send + Sync + 'static` (required by trait)

## Example: Minimal Adapter Template

```rust
use async_trait::async_trait;
use drift::io::PacketIO;
use std::io;
use std::net::SocketAddr;

pub struct MyAdapter {
    // Your medium-specific state here.
}

#[async_trait]
impl PacketIO for MyAdapter {
    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        // Frame and transmit `buf` as one atomic packet.
        todo!()
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Receive one complete packet into `buf`.
        // Return (bytes_read, source_address).
        todo!()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("0.0.0.0:0".parse().unwrap())
    }
}
```

Then plug it in:

```rust
let my_io = Arc::new(MyAdapter::new(/* ... */));
let transport = Transport::bind_with_io(my_io, identity, config).await?;
// DRIFT now runs over your medium. Every feature works:
// handshakes, streams, datagrams, rekey, resumption, mesh routing.
```

Or add it to an existing multi-interface node:

```rust
let transport = Transport::bind("0.0.0.0:9000".parse()?, identity).await?;  // UDP
let my_io = Arc::new(MyAdapter::new(/* ... */));
transport.add_interface("my-medium", my_io);
// Now UDP peers AND your-medium peers can reach this node.
// Cross-interface forwarding is automatic.
```

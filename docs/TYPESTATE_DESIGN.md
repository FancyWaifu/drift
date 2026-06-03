# Type-state at API boundaries — design memo

## The opportunity

The structured-errors arc (slices 1–8) made illegal protocol-
layer errors unrepresentable at the type level — `Header::decode`
can no longer return a `CryptoError`, `xeddsa::verify` can no
longer return a `CodecError`. The next step on the same axis is
**illegal protocol-state combinations**.

A quick grep:

> 57 runtime checks of the form
> `matches!(peer.handshake, HandshakeState::Established { .. })`
> or `peer.handshake.is_ready_for_data()` across the workspace.

Each of these is a spot where the compiler does not know what
the call site has already verified. The check answers the
question "is this peer ready to do X?" and either silently
returns `None`/early-returns, or proceeds without re-validating
that the answer is still true.

Type-state would encode "this peer has session keys derived" or
"this peer is fully Established" at the type level, turning
those runtime `matches!` calls into compile-time guarantees.

## Why DRIFT's peer table makes the canonical type-state hard

The textbook type-state pattern wraps a value of type `T`,
consumes it through a state transition, and returns `T<NewState>`
or destroys it on rejection:

```rust
fn add_peer(t: PendingPeer) -> AwaitingAck;
fn handshake_complete(t: AwaitingAck) -> Established;
fn send_data(t: &Established, payload: &[u8]) -> Result<()>;
```

DRIFT's `Peer` lives in a sharded peer table, looked up by 8-byte
`PeerId`. Calls don't own the `Peer` — they take a shard lock,
look the peer up, mutate, drop the lock. There's no place to
consume a `PendingPeer` and produce an `Established` — the
struct's state transitions in-place. Trying to type-state the
`Peer` struct itself would require rewriting the peer table,
which is a much larger change than the value it delivers.

So: type-state on the *table-managed `Peer` struct* is the
wrong target.

## Where it works: API boundaries that hand out *handles*

The right targets are the points where the transport hands out a
**handle** to the app, and where the app calls back in. At those
boundaries, the handle is owned, transitions are explicit, and
the type can encode the contract.

Three candidates, ranked by value-to-effort:

### 1. `SessionKey<Initiator>` vs `SessionKey<Responder>` — easy win

`SessionKey` already carries a runtime `Direction` enum. Every
`seal` / `open` call branches on it to pick the nonce prefix.
Code that mixes a responder-direction `SessionKey` into an
initiator-side seal silently produces undecryptable bytes — the
test suite catches it, but the compiler doesn't.

Replace `Direction` with a type parameter:

```rust
pub struct SessionKey<D: Direction> { /* ... */ }
pub trait Direction { /* nonce prefix */ }
pub struct Initiator;
pub struct Responder;
```

`Peer.handshake` would carry `SessionKey<Initiator>` for the tx
side and `SessionKey<Responder>` for rx (or vice versa per role).
Mixing the two becomes a compile error.

**Effort:** ~one day. Touches `crypto.rs`, every call site that
constructs a `SessionKey`, and the `Peer` struct's field types.
**Risk:** very low. Mechanical refactor.

### 2. `PeerHandle` → `EstablishedPeerHandle` for app-facing APIs

`Transport::add_peer` returns `PeerId`. The app uses that ID for
`send_data`, `recv`, `update_peer_addr`, etc. Internally these
all call `peers.lock_for(&id)` and do a `matches!(handshake,
Established)` check — runtime, returning `PeerError::SessionNotReady`
if not.

Hand back a typed handle instead:

```rust
pub struct PeerHandle {            // returned by add_peer
    id: PeerId,
    transport: Weak<Inner>,
}

pub struct EstablishedPeerHandle { // returned by wait_until_established
    id: PeerId,
    transport: Weak<Inner>,
}

impl PeerHandle {
    pub async fn wait_until_established(self) -> EstablishedPeerHandle;
    pub async fn send_data(&self, payload: &[u8]) -> Result<()>;
        // ↑ still runtime-checks, for back-compat
}

impl EstablishedPeerHandle {
    pub async fn send_data(&self, payload: &[u8]) -> Result<()>;
        // ↑ skip the runtime check — type guarantees Established
    pub async fn open_stream(&self) -> StreamHandle;
    pub async fn rekey(&self) -> Result<()>;
}
```

Apps that want guaranteed-Established semantics opt in by
awaiting first. Existing apps using bare `PeerId` continue to
work; the handle type is additive.

**Effort:** ~one week. New type, new methods, careful
documentation. The interesting question is whether
`EstablishedPeerHandle` should become invalid if the peer is
later torn down (e.g. handshake exhausted) — most natural answer
is `send_data` returns a `PeerError::SessionTerminated`-style
variant, but that's a runtime fallback in disguise.

**Risk:** moderate. The handle's lifetime contract needs
thinking — what happens when the peer drops out of the table
mid-stream? Iroh handles this with `Closed` errors; DRIFT could
follow.

### 3. Resumption ticket: `UnvalidatedTicket` → `ValidatedTicket`

`import_resumption_ticket` currently does four runtime checks
(slice 7 split these into PeerError variants):

  * blob parses as ClientTicket
  * `ticket.server_id == peer`
  * `ticket.expiry > now`
  * `ticket.server_static_pub` matches our stored pub for this peer

A typed version:

```rust
pub struct UnvalidatedTicket(Vec<u8>);
pub struct ValidatedTicket { /* parsed fields */ }

impl UnvalidatedTicket {
    pub fn validate(self, expected: &PeerId, t: &Transport)
        -> Result<ValidatedTicket, PeerError>;
}

impl Transport {
    pub fn import_resumption_ticket(&self, t: ValidatedTicket);
        // ↑ infallible
}
```

**Effort:** ~half day. Low blast radius — only `import_resumption_ticket`
callers.
**Risk:** very low.

## What we should NOT do

* **Don't type-state the `Peer` struct itself.** Table-managed,
  state mutates in-place, no ownership transfer point.
* **Don't go all-in iroh-style with sealed traits and PhantomData
  everywhere.** That style works in iroh because they own the
  connection lifecycle end-to-end. DRIFT's mesh forwarding,
  federation, and resumption all add cross-cutting paths that
  fight against deep type-state. Pick the API boundaries that
  actually face the app.
* **Don't migrate `is_ready_for_data` / `Established` checks in
  internal recv paths.** Those run after a table lookup;
  there's no caller to hand an Established-typed reference to.
  Leave them as PeerError runtime returns.

## Phased rollout

  * **Phase 1 (1 PR, ~1 day):** `SessionKey<Initiator>` /
    `SessionKey<Responder>` with phantom data. Pure refactor,
    no behavior change. Validates the approach.
  * **Phase 2 (1 PR, ~half day):** `UnvalidatedTicket` /
    `ValidatedTicket` for resumption import. Tiny, well-bounded.
  * **Phase 3 (2–3 PRs, ~1 week):** `PeerHandle` /
    `EstablishedPeerHandle`. First PR adds the types alongside
    the existing `PeerId` API (additive, no breakage). Second PR
    migrates internal call sites. Third PR — optional —
    deprecates the bare-`PeerId` send path.

Stop after phase 2 if phase 3 starts feeling like ceremony for
its own sake. The win from phase 1 alone (no more mixed-
direction `SessionKey` bugs possible) probably justifies the
effort.

## Open questions

  * Should `EstablishedPeerHandle` hold a `Weak<Inner>` or own
    something stronger? Weak is right for "peer can be torn down
    out from under us" semantics, but adds upgrade-or-error
    boilerplate to every method.
  * Does the type-state add up for streams? Each `Stream` already
    has a state machine; type-stating it (Open / HalfClosed /
    Closed) follows the same pattern as PeerHandle but at
    higher frequency. Defer until phase 3 settles.

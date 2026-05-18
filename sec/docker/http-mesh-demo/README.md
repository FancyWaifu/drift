# Live demo: drift http on the client side, mesh-reachable

A drift node on the "client machine" hosts an `http://` listener (fronted by caddy) AND federates outbound to a remote bridge. It's reachable two ways at the same time:

- **Direct (web side):** any HTTP client → caddy → drift node
- **Mesh side:** any peer who can reach the remote bridge → bridge → federation link → drift node

This is the "I have a node behind nginx but I also want to be discoverable through a public bridge" pattern.

## Run

```
bash sec/docker/http-mesh-demo/run.sh
```

Generates ephemeral keys, brings up the four-container topology, runs the sender, and asserts the listener exits 0 on receipt.

Sample successful output:

```
==> bridge pub: c0a4c0f203dbd608...
==> client pub: 25853f6ffde5c7d2...
==> Bringing up remote-bridge + client-node + caddy
==> Running remote-sender + watching client-node for exit
[sender] connected to bridge at 10.97.0.20:51820
[sender] attempt 0: send_data ok
SENDER PASS: dispatched 6 packet(s) to target via bridge
==> RESULT: PASS — client machine reachable via mesh AND via http+caddy
```

## Topology

```
  ┌──────────────────────── meshnet (10.97.0.0/24) ────────────────────────┐
  │                                                                         │
  │   remote-sender (10.97.0.40)                                            │
  │       │  drift over UDP                                                 │
  │       ▼                                                                 │
  │   remote-bridge (10.97.0.20)                                            │
  │       ◀──── federation (UDP) ───── client-node (10.97.0.10)             │
  │                                          ▲                              │
  │                                          │ http://                      │
  │                                       caddy (10.97.0.30)                │
  │                                          ▲                              │
  │                                          │ http://  (any web client)    │
  │                                          └──────────────────────────────┤
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

- **`client-node`** runs `mesh-listener`: binds `http://0.0.0.0:51820`, federates outbound to `remote-bridge`, drains its own recv channel. Exits 0 when it sees the magic payload.
- **`caddy`** vanilla `caddy:2-alpine`, fronts the client node's HTTP listener. Doesn't know or care it's drift.
- **`remote-bridge`** standard `drift bridge --listen udp://...`. The "public bridge" in the user's home network analogy.
- **`remote-sender`** runs `mesh-sender`: connects to `remote-bridge` via UDP, addresses a packet to `client-node`'s pubkey, the bridge's mesh routing forwards over the federation link.

## What this proves

- A drift node can simultaneously be an HTTP server (web-reachable) AND a mesh participant (reachable through any bridge it federates with)
- Standard reverse proxy (vanilla caddy, no plugins) works in front of the HTTP side without disturbing the mesh side
- Federation routes converge fast enough (~few seconds) that a peer at the other end of the mesh can address the client node by pubkey alone

## What you'd do in production

Replace each container with its real counterpart:

| Demo container | Production equivalent |
|---|---|
| `client-node` | drift binary running on your laptop / homelab / VM, identity stored in `~/.config/drift/identity.key` |
| `caddy` | caddy / nginx / cloudflared / whatever you already operate, on the same host or in front of it |
| `remote-bridge` | a public drift bridge you operate or a community one |
| `remote-sender` | any other peer in the mesh — phone, friend's laptop, another homelab |

The compose file is annotated; copy the relevant pieces into your own deployment.

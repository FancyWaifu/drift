#!/usr/bin/env python3
"""Generate a large DRIFT ring compose file whose container IPs span
multiple /24 blocks, proving the topology works on a network larger
than a single /24 subnet.

Layout:
  - Docker bridge network: 10.100.0.0/16 (a /16, 65534 usable hosts).
  - N ring nodes, assigned IPs of the form 10.100.(i // PER_BLOCK).(i % PER_BLOCK + BASE).
  - With N=100 and PER_BLOCK=20, nodes occupy 5 different /24 blocks
    (10.100.0.x, 10.100.1.x, ... 10.100.4.x), so a /24 could not hold them.

Ring edge i -> (i+1) % N is wired via --next-addr.
"""

import sys

N = 100
PER_BLOCK = 20
BASE = 10
TOKENS = 20
INTERVAL_MS = 100
SUBNET = "10.100.0.0/16"


def ip(i: int) -> str:
    block = i // PER_BLOCK
    host = (i % PER_BLOCK) + BASE
    return f"10.100.{block}.{host}"


def main() -> None:
    out = []
    out.append(
        "# 100-node DRIFT ring on a /16 docker network.\n"
        "#\n"
        f"# Nodes are placed across {N // PER_BLOCK} different /24 blocks:\n"
        "#   10.100.0.10-29, 10.100.1.10-29, ... 10.100.4.10-29\n"
        "# so the topology provably cannot fit inside a single /24.\n"
        "# Each token makes a full 100-hop round trip to prove the ring\n"
        "# still converges across the larger address space.\n\n"
        "services:\n"
    )
    for i in range(N):
        nxt = ip((i + 1) % N)
        out.append(
            f"  node{i}:\n"
            f"    image: drift:latest\n"
            f"    container_name: drift-r100-{i}\n"
            f"    command:\n"
            f"      - drift-ring\n"
            f"      - --index\n"
            f'      - "{i}"\n'
            f"      - --total\n"
            f'      - "{N}"\n'
            f"      - --listen\n"
            f"      - 0.0.0.0:9000\n"
            f"      - --next-addr\n"
            f"      - {nxt}:9000\n"
            f"      - --tokens\n"
            f'      - "{TOKENS}"\n'
            f"      - --interval-ms\n"
            f'      - "{INTERVAL_MS}"\n'
            f"    networks:\n"
            f"      bignet:\n"
            f"        ipv4_address: {ip(i)}\n"
        )
    out.append(
        "\nnetworks:\n"
        "  bignet:\n"
        "    driver: bridge\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: {SUBNET}\n"
    )
    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()

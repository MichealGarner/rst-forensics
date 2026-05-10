"""Regenerate the three Phase 3 fixture pcaps.

Run from a checkout root with scapy installed:

    python tests/fixtures/build_fixtures.py

The pcaps are committed to the repo so the test suite doesn't need scapy
just to *read* them — but it does need scapy to *build* them. Each scenario
is constructed deterministically: fixed timestamps, fixed seq/ack numbers,
fixed IP-IDs. Re-running the script produces byte-identical pcaps.

Three scenarios:

* ``server_netem_rst.pcap`` — well-behaved server stack closes with a RST
  after netem-induced loss. Every fingerprint matches the SYN-ACK
  baseline. Expected verdict: SERVER, confidence 1.0.

* ``fortigate_inline_rst.pcap`` — inline firewall forges a RST on behalf
  of the server. The forged packet carries the firewall's TTL, a sentinel
  window, no TCP options, a sequence number nowhere near the receive
  window, and arrives faster than ½ RTT. Expected verdict: MIDPATH,
  confidence 1.0.

* ``client_rst.pcap`` — client gives up on a quiet connection and sends
  an outgoing RST after a long pause. The classifier's existing scorers
  read every RST against the server baseline regardless of direction, so
  this one verdicts as SERVER-leaning; the test asserts on the things
  that ARE diagnostic for an outgoing RST (direction + CLIENT timing
  vote + absence of any MIDPATH signal).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap

FIXTURES_DIR = Path(__file__).resolve().parent

CLIENT_IP = "10.0.0.42"
SERVER_IP = "203.0.113.10"
FIREWALL_IP = SERVER_IP   # forged source — that's the whole point
SPORT = 51514
DPORT = 443

# Common TCP option sets, in scapy form. The _scapy.to_meta shim maps:
#   Timestamp -> "timestamp", SAckOK -> "sack_perm", MSS -> "mss",
#   WScale -> "wscale", NOP -> "nop"
_HANDSHAKE_OPTS = [
    ("MSS", 1460),
    ("SAckOK", b""),
    ("Timestamp", (10_000, 0)),
    ("NOP", None),
    ("WScale", 7),
]
_SERVER_HANDSHAKE_OPTS = [
    ("MSS", 1460),
    ("SAckOK", b""),
    ("Timestamp", (50_000, 10_000)),
    ("NOP", None),
    ("WScale", 7),
]
_DATA_OPTS_CLIENT = [("NOP", None), ("NOP", None), ("Timestamp", (10_010, 50_000))]
_DATA_OPTS_SERVER = [("NOP", None), ("NOP", None), ("Timestamp", (50_010, 10_010))]
_RST_OPTS_SERVER = [("NOP", None), ("NOP", None), ("Timestamp", (50_020, 10_010))]


def _stamp(pkts, t0=0.0, deltas=None):
    """Pin per-packet timestamps so wrpcap writes deterministic times."""
    if deltas is None:
        deltas = [0.0] * len(pkts)
    assert len(deltas) == len(pkts)
    t = t0
    for pkt, d in zip(pkts, deltas):
        t += d
        pkt.time = t
    return pkts


def _handshake():
    """Common SYN / SYN-ACK / ACK opening. Returns (packets, deltas)."""
    syn = IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=20_000) / TCP(
        sport=SPORT, dport=DPORT, flags="S", seq=1000, window=64240,
        options=_HANDSHAKE_OPTS,
    )
    synack = IP(src=SERVER_IP, dst=CLIENT_IP, ttl=64, id=10_000) / TCP(
        sport=DPORT, dport=SPORT, flags="SA", seq=2000, ack=1001, window=29200,
        options=_SERVER_HANDSHAKE_OPTS,
    )
    ack = IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=20_001) / TCP(
        sport=SPORT, dport=DPORT, flags="A", seq=1001, ack=2001, window=64240,
        options=_DATA_OPTS_CLIENT,
    )
    # 20 ms RTT; ACK arrives 2 ms after SYN-ACK.
    return [syn, synack, ack], [0.0, 0.020, 0.002]


def _client_get():
    """Client GET request, 80 bytes."""
    payload = b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: fixture\r\n\r\n"
    # Pad to exactly 80 bytes for predictable expected_seq math.
    if len(payload) < 80:
        payload = payload + b"X" * (80 - len(payload))
    payload = payload[:80]
    return IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=20_002) / TCP(
        sport=SPORT, dport=DPORT, flags="PA", seq=1001, ack=2001, window=64240,
        options=_DATA_OPTS_CLIENT,
    ) / Raw(payload)


def _server_data():
    """Server response, 200 bytes. Bumps expected_seq_to_client to 2201."""
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    payload = payload + b"Y" * (200 - len(payload))
    payload = payload[:200]
    return IP(src=SERVER_IP, dst=CLIENT_IP, ttl=64, id=10_001) / TCP(
        sport=DPORT, dport=SPORT, flags="PA", seq=2001, ack=1081, window=29200,
        options=_DATA_OPTS_SERVER,
    ) / Raw(payload)


# --------------------------------------------------------------------------- #
# Scenario 1: clean server-originated RST                                     #
# --------------------------------------------------------------------------- #

def build_server_netem_rst() -> list:
    pkts, deltas = _handshake()
    pkts.extend([_client_get(), _server_data()])
    deltas.extend([0.008, 0.020])

    # Server RST after netem timeout. Every fingerprint stays inside the
    # server's baseline: TTL/window/options match, IP-ID continues, seq lands
    # exactly on the next expected byte (2001 + 200 = 2201).
    rst = IP(src=SERVER_IP, dst=CLIENT_IP, ttl=64, id=10_002) / TCP(
        sport=DPORT, dport=SPORT, flags="RA", seq=2201, ack=1081, window=29200,
        options=_RST_OPTS_SERVER,
    )
    pkts.append(rst)
    deltas.append(0.025)   # ~RTT after the data; > ½ RTT so timing -> SERVER 0.5
    return _stamp(pkts, t0=1_700_000_000.0, deltas=deltas)


# --------------------------------------------------------------------------- #
# Scenario 2: inline firewall forges a RST                                    #
# --------------------------------------------------------------------------- #

def build_fortigate_inline_rst() -> list:
    pkts, deltas = _handshake()
    pkts.extend([_client_get(), _server_data()])
    deltas.extend([0.008, 0.020])

    # Forged: src spoofs the server, but TTL says it was minted much closer,
    # window is a sentinel, options are stripped, seq is gibberish, and it
    # arrives 5 ms after the server data — under ½ RTT (10 ms). Six-for-six
    # MIDPATH.
    rst = IP(src=FIREWALL_IP, dst=CLIENT_IP, ttl=240, id=44_000) / TCP(
        sport=DPORT, dport=SPORT, flags="R", seq=999_999, ack=0, window=0,
        options=[],
    )
    pkts.append(rst)
    deltas.append(0.005)
    return _stamp(pkts, t0=1_700_000_000.0, deltas=deltas)


# --------------------------------------------------------------------------- #
# Scenario 3: client gives up on a quiet connection                           #
# --------------------------------------------------------------------------- #

def build_client_rst() -> list:
    pkts, deltas = _handshake()
    pkts.extend([_client_get(), _server_data()])
    deltas.extend([0.008, 0.020])

    # Three seconds of silence, then a clean Linux-style outgoing RST: TTL
    # matches the SYN's, IP-ID 0 (per-flow counter), no options, ack number
    # acknowledges what the server sent, seq lands at 1081 (next byte after
    # the 80-byte GET). The big arrival delta makes the timing scorer vote
    # CLIENT — the diagnostic signal for outgoing RSTs.
    rst = IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0) / TCP(
        sport=SPORT, dport=DPORT, flags="RA", seq=1081, ack=2201, window=64240,
        options=[],
    )
    pkts.append(rst)
    deltas.append(3.000)
    return _stamp(pkts, t0=1_700_000_000.0, deltas=deltas)


SCENARIOS: dict[str, callable] = {
    "server_netem_rst.pcap": build_server_netem_rst,
    "fortigate_inline_rst.pcap": build_fortigate_inline_rst,
    "client_rst.pcap": build_client_rst,
}


def main() -> int:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in SCENARIOS.items():
        out = FIXTURES_DIR / name
        pkts = builder()
        wrpcap(str(out), pkts)
        print(f"wrote {out.relative_to(FIXTURES_DIR.parent.parent)} ({len(pkts)} packets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

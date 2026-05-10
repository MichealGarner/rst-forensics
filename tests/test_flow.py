"""Flow tracker tests — fabricate ``PacketMeta`` records to drive scenarios.

No scapy required: the tracker is library-agnostic by design.
"""

from __future__ import annotations

from rst_forensics.flow import (
    FlowTracker,
    PacketMeta,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
)
from rst_forensics.observation import Direction
from rst_forensics.scoring import Origin
from rst_forensics.verdict import classify

CLIENT, SERVER = "10.0.0.1", "203.0.113.5"
SPORT, DPORT = 50000, 443


def _meta(ts: float, from_server: bool, **overrides) -> PacketMeta:
    if from_server:
        src, dst, sport, dport = SERVER, CLIENT, DPORT, SPORT
    else:
        src, dst, sport, dport = CLIENT, SERVER, SPORT, DPORT
    fields = dict(
        ts=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        ttl=64, ip_id=0, seq=0, ack=0, flags=0, window=29200,
        options=frozenset(), payload_len=0,
    )
    fields.update(overrides)
    return PacketMeta(**fields)


def _handshake(t: FlowTracker) -> None:
    """Drive a vanilla SYN / SYN-ACK / ACK through the tracker."""
    t.update(_meta(0.00, False, flags=TCP_SYN, seq=1000, window=64240))
    t.update(_meta(0.05, True, flags=TCP_SYN | TCP_ACK,
                   seq=2000, ack=1001, ip_id=1230,
                   options=frozenset({"timestamp", "sack_perm"})))
    t.update(_meta(0.06, False, flags=TCP_ACK, seq=1001, ack=2001))


def test_handshake_locks_server_baseline_and_rtt() -> None:
    t = FlowTracker()
    _handshake(t)
    obs = t.update(_meta(0.10, True, flags=TCP_RST | TCP_ACK,
                         seq=2001, ack=1001, ip_id=1240,
                         options=frozenset({"timestamp", "sack_perm"})))
    assert obs is not None
    assert obs.direction is Direction.TO_CLIENT
    b = obs.baseline
    assert b.server_ttl == 64
    assert b.last_ip_id == 1230
    assert b.server_window == 29200
    assert b.server_options == frozenset({"timestamp", "sack_perm"})
    assert b.expected_seq == 2001
    assert b.rtt_seconds == 0.05
    # End-to-end: this RST should classify SERVER.
    assert classify(obs).origin is Origin.SERVER


def test_midpath_rst_after_data_classifies_midpath() -> None:
    t = FlowTracker()
    _handshake(t)
    # 100 bytes of server data — bumps expected_seq_to_client.
    t.update(_meta(0.10, True, flags=TCP_PSH | TCP_ACK,
                   seq=2001, ack=1001, ip_id=1231,
                   options=frozenset({"timestamp", "sack_perm"}),
                   payload_len=100))
    # Inline firewall injects: higher TTL, sentinel window, options stripped,
    # seq miles outside the receive window, arrived faster than ½ RTT.
    obs = t.update(_meta(0.105, True, flags=TCP_RST,
                         ttl=240, seq=99_999, ip_id=44_000, window=0,
                         options=frozenset()))
    assert obs is not None
    assert obs.ttl == 240
    assert obs.baseline.server_ttl == 64
    assert obs.baseline.last_ip_id == 1231  # post-data update, pre-RST
    v = classify(obs)
    assert v.origin is Origin.MIDPATH
    assert v.confidence > 0.7


def test_outgoing_rst_marks_to_server_direction() -> None:
    t = FlowTracker()
    _handshake(t)
    # Long quiet period, then the client gives up.
    obs = t.update(_meta(2.10, False, flags=TCP_RST,
                         seq=1001, ack=2001, window=29200))
    assert obs is not None
    assert obs.direction is Direction.TO_SERVER
    assert classify(obs).scores[Origin.CLIENT] > 0


def test_no_handshake_falls_through_to_unknown_baseline() -> None:
    """Mid-stream capture: tracker can't pin server side; scorers abstain."""
    t = FlowTracker()
    obs = t.update(_meta(0.0, True, flags=TCP_RST, seq=1234))
    assert obs is not None
    assert obs.baseline.server_ttl is None
    assert obs.baseline.rtt_seconds is None
    assert classify(obs).origin is Origin.UNKNOWN


def test_arrival_delta_measured_against_prior_packet() -> None:
    t = FlowTracker()
    _handshake(t)
    obs = t.update(_meta(0.20, True, flags=TCP_RST | TCP_ACK,
                         seq=2001, ack=1001, ip_id=1240,
                         options=frozenset({"timestamp", "sack_perm"})))
    assert obs is not None
    assert abs(obs.arrival_delta - 0.14) < 1e-9  # 0.20 - 0.06 (last ACK)


def test_fin_consumes_one_seq_for_expected_seq_tracking() -> None:
    t = FlowTracker()
    _handshake(t)
    # Server sends FIN — consumes one byte of sequence space.
    t.update(_meta(0.10, True, flags=TCP_FIN | TCP_ACK,
                   seq=2001, ack=1001, ip_id=1231,
                   options=frozenset({"timestamp", "sack_perm"})))
    obs = t.update(_meta(0.11, True, flags=TCP_RST,
                         seq=2002, ack=1001, ip_id=1232,
                         options=frozenset({"timestamp", "sack_perm"})))
    assert obs is not None
    assert obs.baseline.expected_seq == 2002

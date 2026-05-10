"""Per-flow baseline tracker.

Translates packet observations into ``FlowBaseline`` updates and emits an
``RstObservation`` whenever a TCP RST is seen. Stays library-agnostic: each
adapter converts its native packet (scapy, dpkt, raw) into ``PacketMeta``
first, so the tracker is testable without any pcap I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .observation import Direction, FlowBaseline, RstObservation

# TCP flag bits — duplicated here so adapters don't have to import scapy
# constants just to call into the tracker.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

_SEQ_MASK = 0xFFFFFFFF


@dataclass(frozen=True)
class PacketMeta:
    """Minimal, library-agnostic view of an IPv4 + TCP packet."""

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ttl: int
    ip_id: int
    seq: int
    ack: int
    flags: int
    window: int
    options: frozenset[str]
    payload_len: int


FlowKey = tuple[str, int, str, int]


def _flow_key(m: PacketMeta) -> FlowKey:
    """Order-independent 5-tuple key (skipping protocol — TCP-only here)."""
    a = (m.src_ip, m.src_port)
    b = (m.dst_ip, m.dst_port)
    return (a[0], a[1], b[0], b[1]) if a <= b else (b[0], b[1], a[0], a[1])


@dataclass
class FlowState:
    """Mutable per-flow baseline accumulator."""

    server_ip: str | None = None
    server_port: int | None = None
    server_ttl: int | None = None
    last_server_ip_id: int | None = None
    server_window: int | None = None
    server_options: frozenset[str] = field(default_factory=frozenset)
    syn_ts: float | None = None
    rtt_seconds: float | None = None
    last_ts: float | None = None
    expected_seq_to_client: int | None = None
    expected_seq_to_server: int | None = None
    client_rcv_win_lo: int | None = None
    client_rcv_win_hi: int | None = None
    server_rcv_win_lo: int | None = None
    server_rcv_win_hi: int | None = None


class FlowTracker:
    """Streaming baseline builder.

    Feed every TCP packet via :meth:`update`; the call returns an
    ``RstObservation`` when the packet was a RST, and ``None`` otherwise.
    """

    def __init__(self) -> None:
        self._flows: dict[FlowKey, FlowState] = {}

    def update(self, m: PacketMeta) -> RstObservation | None:
        st = self._flows.setdefault(_flow_key(m), FlowState())

        is_syn = bool(m.flags & TCP_SYN)
        is_ack = bool(m.flags & TCP_ACK)
        is_rst = bool(m.flags & TCP_RST)
        is_synack = is_syn and is_ack

        # Pin the server side off the SYN-ACK — first definitive marker.
        if is_synack and st.server_ip is None:
            st.server_ip = m.src_ip
            st.server_port = m.src_port
            st.server_ttl = m.ttl
            st.last_server_ip_id = m.ip_id
            st.server_window = m.window
            st.server_options = m.options
            if st.syn_ts is not None:
                st.rtt_seconds = m.ts - st.syn_ts
            st.expected_seq_to_client = (m.seq + 1) & _SEQ_MASK
        elif is_syn and not is_ack and st.syn_ts is None:
            st.syn_ts = m.ts

        if st.server_ip is not None:
            from_server = (
                m.src_ip == st.server_ip and m.src_port == st.server_port
            )
        else:
            from_server = None  # mid-stream capture — let scorers abstain

        # Maintain baselines off non-RST packets so the RST itself is
        # compared against what came *before* it.
        if from_server is True and not is_rst:
            st.last_server_ip_id = m.ip_id
            consumed = (
                m.payload_len
                + (1 if m.flags & TCP_FIN else 0)
                + (1 if is_syn else 0)   # SYN-ACK burns a seq too
            )
            st.expected_seq_to_client = (m.seq + consumed) & _SEQ_MASK
            # server's view of client = server's rcv window
            st.server_rcv_win_lo = m.ack
            st.server_rcv_win_hi = (m.ack + m.window) & _SEQ_MASK
        elif from_server is False and not is_rst:
            consumed = (
                m.payload_len
                + (1 if m.flags & TCP_FIN else 0)
                + (1 if is_syn else 0)
            )
            st.expected_seq_to_server = (m.seq + consumed) & _SEQ_MASK
            # client's view of server = client's rcv window
            st.client_rcv_win_lo = m.ack
            st.client_rcv_win_hi = (m.ack + m.window) & _SEQ_MASK

        delta = (m.ts - st.last_ts) if st.last_ts is not None else 0.0
        st.last_ts = m.ts

        if not is_rst:
            return None

        if from_server is True:
            direction = Direction.TO_CLIENT
            expected = st.expected_seq_to_client
            lo, hi = st.client_rcv_win_lo, st.client_rcv_win_hi
        elif from_server is False:
            direction = Direction.TO_SERVER
            expected = st.expected_seq_to_server
            lo, hi = st.server_rcv_win_lo, st.server_rcv_win_hi
        else:
            direction = Direction.TO_CLIENT
            expected, lo, hi = None, None, None

        baseline = FlowBaseline(
            server_ttl=st.server_ttl,
            last_ip_id=st.last_server_ip_id,
            server_window=st.server_window,
            server_options=st.server_options,
            expected_seq=expected,
            rcv_window_lo=lo,
            rcv_window_hi=hi,
            rtt_seconds=st.rtt_seconds,
        )
        return RstObservation(
            ttl=m.ttl,
            ip_id=m.ip_id,
            window=m.window,
            options_present=m.options,
            seq=m.seq,
            arrival_delta=delta,
            direction=direction,
            baseline=baseline,
        )

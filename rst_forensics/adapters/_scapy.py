"""scapy → ``PacketMeta`` shim.

Kept in one place so adapter modules don't each duplicate the layer-extraction
boilerplate, and so the rest of the package never touches scapy types.
"""

from __future__ import annotations

from typing import Any

from ..flow import PacketMeta

# Map scapy option names to the lowercase names ``score_options`` expects.
_OPT_NAMES: dict[str, str] = {
    "Timestamp": "timestamp",
    "SAckOK": "sack_perm",
    "SAck": "sack",
    "MSS": "mss",
    "WScale": "wscale",
    "NOP": "nop",
    "EOL": "eol",
}


def to_meta(pkt: Any) -> PacketMeta | None:
    """Convert a scapy packet to ``PacketMeta``; return ``None`` if not IPv4+TCP."""
    if not pkt.haslayer("IP") or not pkt.haslayer("TCP"):
        return None
    ip = pkt["IP"]
    tcp = pkt["TCP"]

    opts: list[str] = []
    for opt in (tcp.options or []):
        name = opt[0] if isinstance(opt, tuple) else opt
        opts.append(_OPT_NAMES.get(name, str(name).lower()))

    payload = bytes(tcp.payload) if tcp.payload else b""
    return PacketMeta(
        ts=float(getattr(pkt, "time", 0.0)),
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=int(tcp.sport),
        dst_port=int(tcp.dport),
        ttl=int(ip.ttl),
        ip_id=int(ip.id),
        seq=int(tcp.seq),
        ack=int(tcp.ack),
        flags=int(tcp.flags),
        window=int(tcp.window),
        options=frozenset(opts),
        payload_len=len(payload),
    )

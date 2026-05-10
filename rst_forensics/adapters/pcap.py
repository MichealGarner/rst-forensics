"""Pcap / pcapng reader — streams packets through the flow tracker."""

from __future__ import annotations

from ..flow import FlowTracker
from ..observation import RstObservation
from . import _scapy


def read(path: str) -> list[RstObservation]:
    """Walk ``path`` once, returning every RST in capture order."""
    from scapy.all import PcapReader  # noqa: import-time scapy guard

    tracker = FlowTracker()
    out: list[RstObservation] = []
    with PcapReader(path) as reader:
        for pkt in reader:
            meta = _scapy.to_meta(pkt)
            if meta is None:
                continue
            obs = tracker.update(meta)
            if obs is not None:
                out.append(obs)
    return out

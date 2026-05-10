"""Passive sniffer — wraps :class:`scapy.AsyncSniffer`.

Returns the list of RSTs observed during the capture window. Pass either
``count`` (stop after N matching packets) or ``timeout`` (wall-clock). The
``on_rst`` callback fires as each RST is classified, useful for live UIs.
"""

from __future__ import annotations

from typing import Callable

from ..flow import FlowTracker
from ..observation import RstObservation
from . import _scapy


def sniff(
    iface: str | None = None,
    bpf_filter: str = "tcp",
    count: int = 0,
    timeout: float | None = None,
    on_rst: Callable[[RstObservation], None] | None = None,
) -> list[RstObservation]:
    """Block until ``count`` packets seen / ``timeout`` elapsed; return RSTs."""
    from scapy.all import AsyncSniffer  # noqa: import-time scapy guard

    tracker = FlowTracker()
    out: list[RstObservation] = []

    def _handle(pkt) -> None:
        meta = _scapy.to_meta(pkt)
        if meta is None:
            return
        obs = tracker.update(meta)
        if obs is None:
            return
        out.append(obs)
        if on_rst is not None:
            on_rst(obs)

    sniffer = AsyncSniffer(
        iface=iface,
        filter=bpf_filter,
        prn=_handle,
        count=count or 0,
        store=False,
    )
    sniffer.start()
    try:
        sniffer.join(timeout=timeout)
    finally:
        if sniffer.running:
            sniffer.stop()
    return out

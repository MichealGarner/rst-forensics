"""Input dataclasses for the classifier.

Kept deliberately narrow so any pcap parser (scapy, dpkt, raw struct) can
populate them without coupling the classifier to a packet library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Direction(str, Enum):
    """Where the RST is heading from the capture point's perspective."""

    TO_CLIENT = "to_client"
    TO_SERVER = "to_server"


@dataclass(frozen=True)
class FlowBaseline:
    """What we learned about the flow from packets observed before the RST.

    Every field is optional. Scorers abstain (return ``Origin.UNKNOWN``) when
    the relevant baseline is missing rather than guessing — phase 3 will
    populate as much as it can per flow, and we want partial-info verdicts to
    degrade gracefully.
    """

    server_ttl: int | None = None
    last_ip_id: int | None = None
    server_window: int | None = None
    server_options: frozenset[str] = field(default_factory=frozenset)
    expected_seq: int | None = None
    rcv_window_lo: int | None = None
    rcv_window_hi: int | None = None
    rtt_seconds: float | None = None


@dataclass(frozen=True)
class RstObservation:
    """A single RST packet plus the flow context needed to classify it."""

    ttl: int
    ip_id: int
    window: int
    options_present: frozenset[str]   # e.g. {"timestamp", "sack_perm"}
    seq: int
    arrival_delta: float              # seconds since prior packet in this flow
    direction: Direction
    baseline: FlowBaseline = field(default_factory=FlowBaseline)

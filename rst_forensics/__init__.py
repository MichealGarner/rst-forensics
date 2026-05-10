"""rst-forensics — classify TCP RST origin from packet observations."""

from .flow import FlowState, FlowTracker, PacketMeta
from .observation import Direction, FlowBaseline, RstObservation
from .scoring import ALL_SCORERS, Origin, Score
from .verdict import Verdict, classify

__all__ = [
    "ALL_SCORERS",
    "Direction",
    "FlowBaseline",
    "FlowState",
    "FlowTracker",
    "Origin",
    "PacketMeta",
    "RstObservation",
    "Score",
    "Verdict",
    "classify",
]

__version__ = "0.3.0"

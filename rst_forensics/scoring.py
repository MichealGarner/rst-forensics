"""Six independent scoring functions plus the ``Score`` value type.

Each scorer takes an ``RstObservation`` and returns one ``Score``. The
verdict aggregator in ``verdict.py`` collects them and picks a winner. This
file holds *all* the heuristics — phase 1's whole purpose is to lock them in
behind a stable interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .observation import Direction, RstObservation


class Origin(str, Enum):
    SERVER = "server"
    MIDPATH = "midpath"
    CLIENT = "client"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Score:
    """One scorer's vote toward an origin.

    ``weight`` is roughly a confidence in [0, 1]; the aggregator sums weights
    per origin, so weights are also the relative voice each scorer gets.
    """

    origin: Origin
    weight: float
    reason: str


# --------------------------------------------------------------------------- #
# 1. TTL delta                                                                #
# --------------------------------------------------------------------------- #

def score_ttl(obs: RstObservation) -> Score:
    """A RST whose TTL diverges from the established server TTL by more than
    a couple of hops likely came from somewhere else on the path. Higher TTL
    than the server's baseline = injected from *fewer* hops away (closer to
    us), which is the classic mid-path-firewall fingerprint.
    """
    base = obs.baseline.server_ttl
    if base is None:
        return Score(Origin.UNKNOWN, 0.0, "no server TTL baseline")

    delta = abs(obs.ttl - base)
    if delta == 0:
        return Score(Origin.SERVER, 0.9, f"TTL {obs.ttl} matches server baseline")
    if delta <= 2:
        # Multipath / route flap can shift TTL by a hop or two — ambiguous.
        return Score(Origin.SERVER, 0.4, f"TTL within {delta} of baseline")
    if obs.ttl > base:
        return Score(
            Origin.MIDPATH, 0.85,
            f"TTL {obs.ttl} exceeds server baseline {base} by {delta} (closer hop)",
        )
    return Score(
        Origin.MIDPATH, 0.7,
        f"TTL {obs.ttl} differs from server baseline {base} by {delta}",
    )


# --------------------------------------------------------------------------- #
# 2. IP-ID continuity                                                         #
# --------------------------------------------------------------------------- #

# IP-ID is 16 bits and wraps. A modest forward jump from the last server
# IP-ID is consistent with either a per-host or per-flow counter. Big jumps
# point to a different stack entirely.
_IP_ID_TOLERANCE = 2048


def score_ip_id(obs: RstObservation) -> Score:
    """Continuation of the server's IP-ID counter is a server fingerprint.
    Big leaps suggest the RST was minted by a different stack.
    """
    last = obs.baseline.last_ip_id
    if last is None:
        return Score(Origin.UNKNOWN, 0.0, "no IP-ID baseline")

    forward = (obs.ip_id - last) % 65536
    if 0 < forward <= _IP_ID_TOLERANCE:
        return Score(
            Origin.SERVER, 0.7,
            f"IP-ID {obs.ip_id} continues sequence (Δ={forward})",
        )
    if obs.ip_id == 0:
        # Linux often emits IP-ID 0 on connection-oriented sockets after
        # negotiating per-flow counters; weak server signal.
        return Score(Origin.SERVER, 0.2, "IP-ID zero (per-flow counter)")
    return Score(
        Origin.MIDPATH, 0.65,
        f"IP-ID {obs.ip_id} jumps {forward} from baseline {last}",
    )


# --------------------------------------------------------------------------- #
# 3. Window / MSS fingerprint                                                 #
# --------------------------------------------------------------------------- #

# Sentinel windows seen on inline reset injectors (Cisco ASA, FortiGate,
# Palo Alto, several IPS appliances). Not exhaustive — the point is "values
# no real socket would land on by accident".
_FIREWALL_WINDOWS: frozenset[int] = frozenset({0, 4128, 8192, 16384})


def score_window(obs: RstObservation) -> Score:
    """Sentinel windows beat baseline-match: a server happens to use a
    sentinel-shaped value (rare), but a midpath box almost always does.
    """
    base = obs.baseline.server_window
    if obs.window in _FIREWALL_WINDOWS and base != obs.window:
        return Score(
            Origin.MIDPATH, 0.75,
            f"window {obs.window} matches firewall sentinel set",
        )
    if base is None:
        return Score(Origin.UNKNOWN, 0.0, "no server window baseline")
    if obs.window == base:
        return Score(Origin.SERVER, 0.6, f"window {obs.window} matches baseline")
    if abs(obs.window - base) <= max(1, base // 4):
        return Score(
            Origin.SERVER, 0.3,
            f"window {obs.window} within ±25% of baseline {base}",
        )
    return Score(
        Origin.MIDPATH, 0.5,
        f"window {obs.window} diverges from baseline {base}",
    )


# --------------------------------------------------------------------------- #
# 4. TCP options                                                              #
# --------------------------------------------------------------------------- #

def score_options(obs: RstObservation) -> Score:
    """Stacks that negotiated SACK / timestamps usually carry timestamps even
    on RSTs (RFC 7323). Inline injectors strip everything to keep the packet
    minimal — the absence is the tell.
    """
    base = obs.baseline.server_options
    if not base:
        return Score(Origin.UNKNOWN, 0.0, "no server option baseline")

    if "timestamp" in base and "timestamp" not in obs.options_present:
        return Score(
            Origin.MIDPATH, 0.7,
            "server uses TCP timestamps; RST has none",
        )
    if obs.options_present == base:
        return Score(
            Origin.SERVER, 0.55,
            f"options {sorted(obs.options_present)} exactly match baseline",
        )
    if obs.options_present & base:
        return Score(
            Origin.SERVER, 0.35,
            f"options {sorted(obs.options_present)} partially match baseline",
        )
    return Score(Origin.MIDPATH, 0.5, "no overlap with server option set")


# --------------------------------------------------------------------------- #
# 5. Sequence-number plausibility                                             #
# --------------------------------------------------------------------------- #

def score_sequence(obs: RstObservation) -> Score:
    """A legitimate endpoint RST's sequence number sits at the expected next
    byte or, failing that, somewhere inside the receiver's advertised window.
    Way-out values are blind injections.
    """
    expected = obs.baseline.expected_seq
    lo = obs.baseline.rcv_window_lo
    hi = obs.baseline.rcv_window_hi

    if expected is not None and obs.seq == expected:
        return Score(Origin.SERVER, 0.85, f"seq {obs.seq} matches expected")
    if lo is not None and hi is not None:
        if lo <= obs.seq <= hi:
            return Score(
                Origin.SERVER, 0.5,
                f"seq {obs.seq} within receive window [{lo},{hi}]",
            )
        return Score(
            Origin.MIDPATH, 0.8,
            f"seq {obs.seq} outside receive window [{lo},{hi}]",
        )
    return Score(Origin.UNKNOWN, 0.0, "no sequence-window baseline")


# --------------------------------------------------------------------------- #
# 6. Arrival timing                                                           #
# --------------------------------------------------------------------------- #

def score_timing(obs: RstObservation) -> Score:
    """A RST that comes back faster than ½ RTT after our last outbound byte
    can't have been generated at the far end. Conversely, an *outgoing* RST
    long after a quiet period usually means the local stack gave up.
    """
    rtt = obs.baseline.rtt_seconds
    if rtt is None or obs.arrival_delta < 0:
        return Score(Origin.UNKNOWN, 0.0, "no RTT baseline")

    half_rtt = rtt / 2.0
    if obs.direction is Direction.TO_CLIENT:
        if obs.arrival_delta < half_rtt:
            return Score(
                Origin.MIDPATH, 0.9,
                f"Δ={obs.arrival_delta:.4f}s < ½ RTT ({half_rtt:.4f}s); "
                "too fast for the server to have replied",
            )
        if obs.arrival_delta <= rtt * 1.5:
            return Score(
                Origin.SERVER, 0.5,
                f"Δ={obs.arrival_delta:.4f}s within ~RTT ({rtt:.4f}s)",
            )
        return Score(
            Origin.UNKNOWN, 0.0,
            f"Δ={obs.arrival_delta:.4f}s ambiguous against RTT {rtt:.4f}s",
        )

    # TO_SERVER — outgoing RST
    if obs.arrival_delta >= rtt * 1.5:
        return Score(
            Origin.CLIENT, 0.6,
            f"outgoing RST after Δ={obs.arrival_delta:.4f}s — local close",
        )
    return Score(
        Origin.UNKNOWN, 0.0,
        f"outgoing Δ={obs.arrival_delta:.4f}s ambiguous against RTT {rtt:.4f}s",
    )


ALL_SCORERS: tuple = (
    score_ttl,
    score_ip_id,
    score_window,
    score_options,
    score_sequence,
    score_timing,
)

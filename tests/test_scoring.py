"""Per-scorer unit tests. Each test exercises one branch with a hand-built
``RstObservation`` so the heuristics stay legible and easy to tune.
"""

from __future__ import annotations

from rst_forensics import Direction, FlowBaseline, Origin, RstObservation
from rst_forensics.scoring import (
    score_ip_id,
    score_options,
    score_sequence,
    score_timing,
    score_ttl,
    score_window,
)


def _baseline(**overrides) -> FlowBaseline:
    fields = dict(
        server_ttl=64,
        last_ip_id=1230,
        server_window=29200,
        server_options=frozenset({"timestamp", "sack_perm"}),
        expected_seq=1000,
        rcv_window_lo=900,
        rcv_window_hi=1500,
        rtt_seconds=0.05,
    )
    fields.update(overrides)
    return FlowBaseline(**fields)


def _obs(**overrides) -> RstObservation:
    fields = dict(
        ttl=64,
        ip_id=1235,
        window=29200,
        options_present=frozenset({"timestamp", "sack_perm"}),
        seq=1000,
        arrival_delta=0.05,
        direction=Direction.TO_CLIENT,
        baseline=_baseline(),
    )
    fields.update(overrides)
    return RstObservation(**fields)


# --------------------------------------------------------------------- TTL ---

def test_ttl_match_votes_server() -> None:
    s = score_ttl(_obs(ttl=64))
    assert s.origin is Origin.SERVER
    assert s.weight >= 0.8


def test_ttl_within_two_hops_is_weak_server() -> None:
    s = score_ttl(_obs(ttl=66))
    assert s.origin is Origin.SERVER
    assert s.weight < 0.5


def test_ttl_higher_than_baseline_votes_midpath() -> None:
    s = score_ttl(_obs(ttl=120))
    assert s.origin is Origin.MIDPATH
    assert "closer hop" in s.reason


def test_ttl_lower_diverges_votes_midpath() -> None:
    s = score_ttl(_obs(ttl=40))
    assert s.origin is Origin.MIDPATH


def test_ttl_no_baseline_abstains() -> None:
    s = score_ttl(_obs(baseline=FlowBaseline()))
    assert s.origin is Origin.UNKNOWN
    assert s.weight == 0.0


# -------------------------------------------------------------------- IP-ID --

def test_ip_id_continuation_votes_server() -> None:
    s = score_ip_id(_obs(ip_id=1235))
    assert s.origin is Origin.SERVER
    assert "continues" in s.reason


def test_ip_id_jump_votes_midpath() -> None:
    s = score_ip_id(_obs(ip_id=40000))
    assert s.origin is Origin.MIDPATH


def test_ip_id_zero_is_weak_server() -> None:
    s = score_ip_id(_obs(ip_id=0))
    assert s.origin is Origin.SERVER
    assert s.weight < 0.3


def test_ip_id_no_baseline_abstains() -> None:
    s = score_ip_id(_obs(baseline=FlowBaseline()))
    assert s.origin is Origin.UNKNOWN


# ------------------------------------------------------------------- window --

def test_window_match_votes_server() -> None:
    s = score_window(_obs(window=29200))
    assert s.origin is Origin.SERVER


def test_window_firewall_sentinel_votes_midpath() -> None:
    s = score_window(_obs(window=0))
    assert s.origin is Origin.MIDPATH


def test_window_within_tolerance_is_weak_server() -> None:
    s = score_window(_obs(window=29000))
    assert s.origin is Origin.SERVER


def test_window_diverges_votes_midpath() -> None:
    s = score_window(_obs(window=1234))
    assert s.origin is Origin.MIDPATH


# ------------------------------------------------------------------ options --

def test_options_stripped_votes_midpath() -> None:
    s = score_options(_obs(options_present=frozenset()))
    assert s.origin is Origin.MIDPATH


def test_options_exact_match_votes_server() -> None:
    s = score_options(_obs())
    assert s.origin is Origin.SERVER
    assert "exactly match" in s.reason


def test_options_partial_match_votes_server() -> None:
    s = score_options(_obs(options_present=frozenset({"timestamp"})))
    # timestamp present so the strip-detector won't fire; partial-match path
    assert s.origin is Origin.SERVER


def test_options_no_baseline_abstains() -> None:
    s = score_options(_obs(baseline=FlowBaseline()))
    assert s.origin is Origin.UNKNOWN


# ------------------------------------------------------------------ sequence -

def test_seq_matches_expected_votes_server() -> None:
    s = score_sequence(_obs(seq=1000))
    assert s.origin is Origin.SERVER
    assert s.weight >= 0.8


def test_seq_within_window_votes_server() -> None:
    s = score_sequence(_obs(seq=1100))
    assert s.origin is Origin.SERVER


def test_seq_outside_window_votes_midpath() -> None:
    s = score_sequence(_obs(seq=99_999))
    assert s.origin is Origin.MIDPATH


def test_seq_no_baseline_abstains() -> None:
    s = score_sequence(_obs(baseline=FlowBaseline()))
    assert s.origin is Origin.UNKNOWN


# -------------------------------------------------------------------- timing -

def test_timing_too_fast_votes_midpath() -> None:
    s = score_timing(_obs(arrival_delta=0.001))
    assert s.origin is Origin.MIDPATH
    assert s.weight >= 0.8


def test_timing_within_rtt_votes_server() -> None:
    s = score_timing(_obs(arrival_delta=0.05))
    assert s.origin is Origin.SERVER


def test_timing_outgoing_late_votes_client() -> None:
    s = score_timing(_obs(direction=Direction.TO_SERVER, arrival_delta=2.0))
    assert s.origin is Origin.CLIENT


def test_timing_outgoing_fast_abstains() -> None:
    s = score_timing(_obs(direction=Direction.TO_SERVER, arrival_delta=0.001))
    assert s.origin is Origin.UNKNOWN


def test_timing_no_rtt_baseline_abstains() -> None:
    s = score_timing(_obs(baseline=FlowBaseline()))
    assert s.origin is Origin.UNKNOWN

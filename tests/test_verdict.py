"""End-to-end aggregator tests with three representative fixtures."""

from __future__ import annotations

from rst_forensics import (
    Direction,
    FlowBaseline,
    Origin,
    RstObservation,
    classify,
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


def test_clean_server_rst_classifies_server() -> None:
    obs = RstObservation(
        ttl=64,
        ip_id=1235,
        window=29200,
        options_present=frozenset({"timestamp", "sack_perm"}),
        seq=1000,
        arrival_delta=0.05,
        direction=Direction.TO_CLIENT,
        baseline=_baseline(),
    )
    v = classify(obs)
    assert v.origin is Origin.SERVER
    assert v.confidence > 0.6
    assert v.scores[Origin.SERVER] > v.scores[Origin.MIDPATH]


def test_obvious_midpath_rst_classifies_midpath() -> None:
    # Higher TTL, sentinel window, options stripped, seq out of window,
    # arrived faster than ½ RTT — every scorer should vote MIDPATH.
    obs = RstObservation(
        ttl=128,
        ip_id=44_000,
        window=0,
        options_present=frozenset(),
        seq=99_999,
        arrival_delta=0.001,
        direction=Direction.TO_CLIENT,
        baseline=_baseline(),
    )
    v = classify(obs)
    assert v.origin is Origin.MIDPATH
    assert v.confidence > 0.8


def test_outgoing_late_rst_registers_client_vote() -> None:
    # Outgoing RST after a long quiet period — classic local close. Other
    # scorers still match the server fingerprint (because we hand-set the
    # baseline to align), so we just assert the CLIENT vote was registered.
    obs = RstObservation(
        ttl=64,
        ip_id=1235,
        window=29200,
        options_present=frozenset({"timestamp", "sack_perm"}),
        seq=1000,
        arrival_delta=2.0,
        direction=Direction.TO_SERVER,
        baseline=_baseline(),
    )
    v = classify(obs)
    assert v.scores[Origin.CLIENT] > 0


def test_no_baseline_returns_unknown() -> None:
    obs = RstObservation(
        ttl=64,
        ip_id=1234,
        window=29200,
        options_present=frozenset(),
        seq=1000,
        arrival_delta=0.05,
        direction=Direction.TO_CLIENT,
        baseline=FlowBaseline(),
    )
    v = classify(obs)
    assert v.origin is Origin.UNKNOWN
    assert v.confidence == 0.0


def test_explain_contains_verdict_and_evidence() -> None:
    obs = RstObservation(
        ttl=64,
        ip_id=1235,
        window=29200,
        options_present=frozenset({"timestamp", "sack_perm"}),
        seq=1000,
        arrival_delta=0.05,
        direction=Direction.TO_CLIENT,
        baseline=_baseline(),
    )
    text = classify(obs).explain()
    assert "Verdict:" in text
    assert "Evidence:" in text
    # All six scorers must surface a line.
    assert text.count("[") >= 6

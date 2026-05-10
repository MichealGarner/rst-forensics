"""CLI tests — adapter is monkeypatched so scapy isn't required to run."""

from __future__ import annotations

import json

from rst_forensics import (
    Direction,
    FlowBaseline,
    RstObservation,
)
from rst_forensics import cli
from rst_forensics.adapters import pcap as pcap_adapter


_BASE_BASELINE = FlowBaseline(
    server_ttl=64,
    last_ip_id=1230,
    server_window=29200,
    server_options=frozenset({"timestamp", "sack_perm"}),
    expected_seq=1000,
    rcv_window_lo=900,
    rcv_window_hi=1500,
    rtt_seconds=0.05,
)


def _server_rst() -> RstObservation:
    return RstObservation(
        ttl=64, ip_id=1235, window=29200,
        options_present=frozenset({"timestamp", "sack_perm"}),
        seq=1000, arrival_delta=0.05,
        direction=Direction.TO_CLIENT, baseline=_BASE_BASELINE,
    )


def _midpath_rst() -> RstObservation:
    return RstObservation(
        ttl=240, ip_id=44_000, window=0,
        options_present=frozenset(),
        seq=99_999, arrival_delta=0.001,
        direction=Direction.TO_CLIENT, baseline=_BASE_BASELINE,
    )


def test_cli_pcap_json_midpath_exits_two(monkeypatch, capsys):
    monkeypatch.setattr(pcap_adapter, "read", lambda _path: [_midpath_rst()])
    rc = cli.main(["--json", "pcap", "fake.pcap"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 2
    assert len(payload) == 1
    assert payload[0]["verdict"] == "midpath"
    assert payload[0]["rst"]["ttl"] == 240
    assert payload[0]["rst"]["direction"] == "to_client"
    # Confidence is in [0, 1].
    assert 0.0 <= payload[0]["confidence"] <= 1.0
    assert len(payload[0]["evidence"]) == 6  # one per scorer


def test_cli_pcap_server_only_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(pcap_adapter, "read", lambda _path: [_server_rst()])
    rc = cli.main(["--json", "pcap", "fake.pcap"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload[0]["verdict"] == "server"


def test_cli_pcap_no_rsts_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(pcap_adapter, "read", lambda _path: [])
    rc = cli.main(["pcap", "fake.pcap"])
    assert rc == 0


def test_cli_quiet_suppresses_output_but_keeps_exit(monkeypatch, capsys):
    monkeypatch.setattr(pcap_adapter, "read", lambda _path: [_midpath_rst()])
    rc = cli.main(["--quiet", "pcap", "fake.pcap"])
    out = capsys.readouterr().out
    assert rc == 2
    assert out == ""


def test_cli_handles_missing_pcap(monkeypatch, capsys):
    def _raise(_path):
        raise FileNotFoundError("nope.pcap")
    monkeypatch.setattr(pcap_adapter, "read", _raise)
    rc = cli.main(["pcap", "nope.pcap"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "nope.pcap" in err


def test_cli_handles_missing_scapy(monkeypatch, capsys):
    def _raise(_path):
        raise ImportError("No module named 'scapy'")
    monkeypatch.setattr(pcap_adapter, "read", _raise)
    rc = cli.main(["pcap", "fake.pcap"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "scapy" in err

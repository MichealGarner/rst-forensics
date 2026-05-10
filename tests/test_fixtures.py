"""End-to-end tests against the committed Phase 3 fixture pcaps.

Each pcap is a hand-built scenario — see ``tests/fixtures/build_fixtures.py``
for the construction. These tests drive each pcap through the real
pcap adapter (which means scapy is required) and assert what each scenario
is supposed to demonstrate.

The fixtures themselves are committed to the repo so this test runs
without needing scapy's packet *building* path — only the *reading* path,
which the pcap adapter already wraps.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Pcap reading needs scapy. Skip the whole module when it isn't installed.
pytest.importorskip("scapy")

from rst_forensics.adapters import pcap as pcap_adapter
from rst_forensics.observation import Direction
from rst_forensics.scoring import Origin
from rst_forensics.verdict import classify

FIXTURES = Path(__file__).parent / "fixtures"

SERVER_PCAP = FIXTURES / "server_netem_rst.pcap"
FIREWALL_PCAP = FIXTURES / "fortigate_inline_rst.pcap"
CLIENT_PCAP = FIXTURES / "client_rst.pcap"


def _read_one(path: Path):
    """Read a fixture and assert it produced exactly one RST."""
    assert path.is_file(), f"fixture missing: {path} — run tests/fixtures/build_fixtures.py"
    rsts = pcap_adapter.read(str(path))
    assert len(rsts) == 1, f"{path.name}: expected 1 RST, got {len(rsts)}"
    return rsts[0]


# --------------------------------------------------------------------------- #
# Scenario 1 — clean server-originated RST                                    #
# --------------------------------------------------------------------------- #

def test_server_netem_rst_classifies_server() -> None:
    obs = _read_one(SERVER_PCAP)
    assert obs.direction is Direction.TO_CLIENT
    # Sanity: the RST inherited the server fingerprints we set.
    assert obs.ttl == 64
    assert obs.window == 29200
    assert obs.baseline.server_ttl == 64
    assert obs.baseline.last_ip_id == 10_001  # post-data, pre-RST

    v = classify(obs)
    assert v.origin is Origin.SERVER, v.explain()
    assert v.scores[Origin.MIDPATH] == 0.0
    assert v.scores[Origin.CLIENT] == 0.0
    # Every scorer should have voted SERVER (none abstained), confidence 1.0.
    assert v.confidence == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# Scenario 2 — inline firewall forges a RST                                   #
# --------------------------------------------------------------------------- #

def test_fortigate_inline_rst_classifies_midpath() -> None:
    obs = _read_one(FIREWALL_PCAP)
    assert obs.direction is Direction.TO_CLIENT
    assert obs.ttl == 240            # firewall is closer than the server
    assert obs.window == 0            # sentinel
    assert obs.options_present == frozenset()

    v = classify(obs)
    assert v.origin is Origin.MIDPATH, v.explain()
    assert v.scores[Origin.SERVER] == 0.0
    assert v.scores[Origin.CLIENT] == 0.0
    assert v.confidence == pytest.approx(1.0)
    # CI-gate exit code path: any MIDPATH should trip the gate.
    assert any(s.origin is Origin.MIDPATH and s.weight >= 0.7 for s in v.evidence)


# --------------------------------------------------------------------------- #
# Scenario 3 — client gives up                                                #
# --------------------------------------------------------------------------- #

def test_client_rst_is_outgoing_with_client_timing_signal() -> None:
    """The current scorers read every RST against the server's baseline, so
    a well-formed outgoing client RST will score SERVER-dominant on the raw
    fingerprint scorers (TTL/IP-ID/window/seq match because the client is
    closing politely). The diagnostic signals for an outgoing RST are:

    * direction is TO_SERVER (the FlowTracker correctly identifies it),
    * the timing scorer fires for CLIENT (long pause before the close),
    * the verdict is NOT MIDPATH — nothing about this RST should look
      like an injection.

    Sharpening client/server discrimination on outgoing RSTs is a known
    follow-up — phase 4 territory.
    """
    obs = _read_one(CLIENT_PCAP)
    assert obs.direction is Direction.TO_SERVER
    assert obs.arrival_delta >= 1.5 * obs.baseline.rtt_seconds  # timing precondition

    v = classify(obs)
    assert v.origin is not Origin.MIDPATH, v.explain()
    assert v.scores[Origin.CLIENT] > 0.0, "timing scorer should vote CLIENT"
    # And the seq/window scorers shouldn't think this is a blind injection.
    assert v.scores[Origin.MIDPATH] < v.scores[Origin.SERVER] + v.scores[Origin.CLIENT]

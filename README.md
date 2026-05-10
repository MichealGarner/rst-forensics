# rst-forensics

[![tests](https://github.com/MichealGarner/rst-forensics/actions/workflows/test.yml/badge.svg)](https://github.com/MichealGarner/rst-forensics/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/MichealGarner/rst-forensics/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Classify the origin of a TCP RST — **server**, **mid-path firewall**, or **client** —
from a small struct of packet observations. Pure Python, no scapy in the
classifier itself: capture/parse libraries feed `RstObservation` instances in
later phases.

> **Why this exists.** A TCP connection dies with a RST and you need to know
> *who* killed it: the application server (legitimate close), an inline
> firewall forging packets to enforce policy, or your own client stack
> giving up. Wireshark shows you the RST; rst-forensics gives you a verdict
> with weighted evidence (TTL, IP-ID, window, options, sequence, timing) so
> the answer is reproducible and CI-gateable instead of tribal.

## Status

**Phase 3 — fixtures, CI, and PyPI.** Three deterministic lab pcaps
(`tests/fixtures/build_fixtures.py`) drive the pcap adapter + classifier
end-to-end on every push. GitHub Actions runs the suite across Python
3.10–3.13. Tagged `v*.*.*` releases publish to PyPI through Trusted
Publishing.

Earlier phases (still the working surface):

* **Phase 1** — pure-Python classifier. Six scorers (TTL, IP-ID, window,
  options, sequence, timing), weighted aggregation, `Verdict.explain()`.
  No scapy dependency.
* **Phase 2** — capture + CLI. Library-agnostic `FlowTracker` builds
  per-flow baselines from streaming packets and emits `RstObservation`s
  on every RST. Three thin scapy-backed adapters feed it: passive
  `AsyncSniffer`, active probe (initiates a TCP connection and watches
  for the reply), and a pcap/pcapng reader. The `rst-forensics` CLI
  wraps all three with a Rich table or `--json` output and
  pmtud-sweeper-style exit codes (0 clean, 1 setup error, 2 at least
  one MIDPATH RST detected).

## Heuristics

Each scorer returns a `Score(origin, weight, reason)`. The aggregator sums
weights per origin (ignoring `UNKNOWN`) and picks the largest; confidence is
`winning_weight / total_weight`.

| # | Scorer            | Vote logic |
|---|-------------------|-----------|
| 1 | `score_ttl`       | TTL == server baseline → SERVER. Higher than baseline → MIDPATH (closer hop). Diverges by >2 → MIDPATH. |
| 2 | `score_ip_id`     | Small forward delta (mod 16-bit) from last server IP-ID → SERVER. Large jump → MIDPATH. IP-ID 0 → weak SERVER (per-flow counters). |
| 3 | `score_window`    | Matches sentinel firewall window set `{0, 4128, 8192, 16384}` → MIDPATH. Within ±25% of baseline → SERVER. |
| 4 | `score_options`   | Server uses TCP timestamps but RST has none → MIDPATH. Exact option-set match → SERVER. |
| 5 | `score_sequence`  | seq == expected → SERVER. Inside advertised receive window → SERVER. Outside → MIDPATH. |
| 6 | `score_timing`    | TO_CLIENT and Δ < ½ RTT → MIDPATH (faster than the server could reply). Within ~RTT → SERVER. TO_SERVER and Δ ≥ 1.5 × RTT → CLIENT (local close). |

Unknown / missing baseline = the scorer abstains (`Origin.UNKNOWN`, weight 0).

## Quick use

```python
from rst_forensics import (
    classify, RstObservation, FlowBaseline, Direction,
)

obs = RstObservation(
    ttl=128, ip_id=44000, window=0,
    options_present=frozenset(),
    seq=99999, arrival_delta=0.001,
    direction=Direction.TO_CLIENT,
    baseline=FlowBaseline(
        server_ttl=64, last_ip_id=1230, server_window=29200,
        server_options=frozenset({"timestamp", "sack_perm"}),
        expected_seq=1000, rcv_window_lo=900, rcv_window_hi=1500,
        rtt_seconds=0.05,
    ),
)
print(classify(obs).explain())
```

## CLI

```bash
# Walk a pcap, render a Rich table, exit 2 if any RST classified midpath:
rst-forensics pcap captures/firewall-rst.pcap

# JSON for piping to jq / a CI step:
rst-forensics --json pcap captures/firewall-rst.pcap

# Live capture for 30s on eth0:
sudo rst-forensics passive --iface eth0 --timeout 30

# Active probe — initiate a connection and classify any RST that comes back:
sudo rst-forensics active --host example.com --port 443
```

Exit codes: `0` clean, `1` setup error, `2` ≥ 1 RST classified MIDPATH.

Sample output against the committed FortiGate fixture:

```
$ rst-forensics pcap tests/fixtures/fortigate_inline_rst.pcap
┏━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   #  ┃ Verdict ┃ Confidence ┃ Top evidence                                   ┃
┡━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   1  │ MIDPATH │      1.00  │ TTL 240 ≠ baseline 64 (closer hop)             │
│      │         │            │ window=0 in firewall sentinel set              │
│      │         │            │ seq outside advertised rcv window              │
│      │         │            │ Δt < ½ RTT — too fast for the server           │
└──────┴─────────┴────────────┴────────────────────────────────────────────────┘
exit 2
```

> Drop a real screenshot of the live Rich output here once you've run it on
> a terminal that renders unicode borders the way you want them in docs.

## Develop

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test,all]"   # 'all' pulls scapy + rich for the adapters/CLI
pytest
```

The flow tracker tests don't import scapy; CLI tests monkeypatch the
adapters, so the suite runs without root or libpcap.

## Roadmap

- **Phase 3 — done.** Lab fixtures (Linux netem server, FortiGate inline
  RST, client-side give-up) regenerated deterministically from
  `tests/fixtures/build_fixtures.py` and asserted in `tests/test_fixtures.py`.
  CI matrix on Python 3.10–3.13. Tagged releases ship to PyPI via Trusted
  Publishing.
- **Phase 4 — sharper outgoing-RST discrimination.** The current scorers
  read every RST against the server baseline, so a polite client-originated
  RST scores SERVER-leaning on the fingerprint scorers and only the timing
  scorer dissents. Add direction-aware scoring (or a dedicated CLIENT
  scorer set) so client closes verdict cleanly as `CLIENT` instead of
  relying on absence-of-MIDPATH.

## License

MIT — see [`LICENSE`](LICENSE) (or the `license` field in `pyproject.toml`).

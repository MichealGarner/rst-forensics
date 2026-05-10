# CLAUDE.md — rst-forensics working memory

> Working memory for Claude Code sessions on this repo. Kept in-tree because
> the project was built with Claude assistance and the conventions here are
> useful both to future sessions and to readers curious about how the codebase
> is organised. See the [README](./README.md) for the user-facing intro.

## What this is

`rst-forensics` is a small Python library + CLI that classifies the *origin* of
a TCP RST: **server**, **mid-path firewall**, or **client**. It exists because
when a TCP connection dies with a RST, Wireshark shows you the packet but not
who sent it — the question of whether your server closed politely, a corporate
firewall forged the close, or your client gave up is usually answered by tribal
knowledge. This tool gives a reproducible, weighted-evidence verdict instead.

The companion blog post lives at
[michealgarner.co.uk/blog/who-sent-that-rst-forensic-classification-of-tcp-resets-with-rst-forensics](https://michealgarner.co.uk/blog/who-sent-that-rst-forensic-classification-of-tcp-resets-with-rst-forensics).
It walks a SaaS-vs-customer-firewall scenario through to the four-fingerprint
MIDPATH evidence list. The repo is the artefact the post links to.

## Repo layout

```
rst_forensics/
  __init__.py        # public API surface, re-exports + __version__
  observation.py     # RstObservation, FlowBaseline, Direction (the inputs)
  scoring.py         # Origin enum, Score, six scorers, ALL_SCORERS list
  verdict.py         # Verdict, classify(), Verdict.explain()
  flow.py            # FlowTracker — library-agnostic, builds baselines
  adapters/
    _scapy.py        # shared scapy helpers
    pcap.py          # read pcap/pcapng → list[RstObservation]
    passive.py       # AsyncSniffer-backed live capture
    active.py        # initiates a TCP connection, classifies the reply
  cli.py             # rst-forensics console_script — Rich + JSON output

tests/
  test_scoring.py    # per-scorer unit tests
  test_verdict.py    # aggregation tests
  test_flow.py       # FlowTracker tests, no scapy import
  test_cli.py        # CLI tests, monkeypatches adapters
  test_fixtures.py   # end-to-end against built pcaps
                     # (uses pytest.importorskip("scapy"))
  fixtures/
    build_fixtures.py  # deterministic regenerator — committed; pcaps are not
    *.pcap             # built on demand by CI / locally; not in git history

.github/workflows/
  test.yml           # matrix pytest on Python 3.10/3.11/3.12/3.13/3.14
  publish.yml        # dormant; fires on v*.*.* tags, would push to PyPI via
                     # Trusted Publishing if set up. NOT currently configured.
```

## Heuristics, in one breath

Six scorers vote with weights: TTL match, IP-ID delta, window value (incl.
firewall sentinel set `{0, 4128, 8192, 16384}`), TCP options match, sequence
number vs. expected/window, and arrival timing vs. RTT. Aggregator sums weights
per origin (ignoring `UNKNOWN`), picks the largest, reports
`confidence = winning / total`. See `README.md` heuristics table for vote logic.

## Decisions worth not re-litigating

* **Not publishing to PyPI.** `pip install
  git+https://github.com/MichealGarner/rst-forensics` is enough for readers
  who want to try it. `publish.yml` left dormant in case that changes.
* **Fixture pcaps are built in CI / locally, not committed.** Builder is
  deterministic, pcaps are byte-identical across runs. Keeps repo lean.
* **Scapy is optional.** The classifier core has no scapy dependency. Only
  the adapters and the fixture *builder* need it. `test_fixtures.py` skips
  cleanly when scapy isn't installed.
* **CI matrix is 3.10–3.14**, matching `requires-python = ">=3.10"` in
  pyproject.

## Local dev loop

```bash
python -m venv .venv
source .venv/bin/activate          # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e ".[test,all]"
python tests/fixtures/build_fixtures.py
pytest -q
```

46 tests. The `[all]` extra pulls scapy + rich for the adapters and CLI; the
`test_fixtures.py` module skips cleanly without scapy. On Windows, scapy emits
a benign `No libpcap provider available` warning at import — harmless for
pcap reading and packet building (which is what the tests use). Live capture
(`rst-forensics passive` / `active`) needs Npcap from npcap.com.

## Things to avoid

* **Don't re-add PyPI version / pyversions badges to the README** — they'll
  render as "not found" because the package isn't published.
* **Don't tag `v*.*.*`** without first either configuring Trusted Publishing
  on PyPI or disabling `publish.yml`. Otherwise a red publish job appears in
  Actions for no benefit.
* **Don't commit the fixture `.pcap` files.** They're gitignored via
  `tests/fixtures/*.pcap` (and `.pcapng`). The deterministic builder is the
  source of truth, not a checked-in binary.

## Possible future work

Direction-aware scoring would let outgoing client RSTs verdict cleanly as
`CLIENT` instead of leaning `SERVER` on the fingerprint scorers with only the
timing scorer dissenting. Currently every scorer compares against the server
baseline; a parallel client-baseline path (or per-direction scorer set) is the
shape of the fix. Not on the roadmap unless someone asks for it.

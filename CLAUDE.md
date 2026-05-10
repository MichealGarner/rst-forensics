# CLAUDE.md — rst-forensics working memory

Living context for any Claude session opening this repo. Update as decisions are made.

## What this is

`rst-forensics` is a small Python library + CLI that classifies the *origin* of
a TCP RST: **server**, **mid-path firewall**, or **client**. It exists because
when a TCP connection dies with a RST, Wireshark shows you the packet but not
who sent it — the question of whether your server closed politely, a corporate
firewall forged the close, or your client gave up is usually answered by tribal
knowledge. This tool gives a reproducible, weighted-evidence verdict instead.

The author is **Micheal Garner** (`michealgarner@hotmail.co.uk`,
GitHub `MichealGarner`). The repo is public at
<https://github.com/MichealGarner/rst-forensics>.

## Why it exists (the actual goal)

This is a **companion repo for a blog post**. The code is the artefact the post
will reference and link to. It is **not** a maintained library, **not** on PyPI,
and there is no plan to publish it. The README, CI, and badges exist to make the
repo presentable to readers arriving from the post — not to support a release
cadence.

## Repo layout

```
rst_forensics/
  __init__.py        # public API surface, re-exports + __version__
  observation.py     # RstObservation, FlowBaseline, Direction (the inputs)
  scoring.py         # Origin enum, Score, six scorers, ALL_SCORERS list
  verdict.py         # Verdict, classify(), Verdict.explain()
  flow.py            # FlowTracker — library-agnostic, builds baselines
  adapters/
    __init__.py
    _scapy.py        # shared scapy helpers
    pcap.py          # read pcap/pcapng → list[RstObservation]
    passive.py       # AsyncSniffer-backed live capture
    active.py        # initiates a TCP connection, classifies the reply
  cli.py             # rst-forensics console_script — Rich + JSON output

tests/
  test_scoring.py    # Phase 1 unit tests (each scorer)
  test_verdict.py    # Phase 1 aggregation tests
  test_flow.py       # Phase 2 FlowTracker tests, no scapy import
  test_cli.py        # Phase 2 CLI tests, monkeypatches adapters
  test_fixtures.py   # Phase 3 end-to-end tests against committed pcaps
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

## Phases shipped

* **Phase 1** — pure-Python classifier. No scapy dependency. `Verdict.explain()`
  prints per-scorer reasons.
* **Phase 2** — `FlowTracker` baseline builder + three scapy-backed adapters
  (passive sniffer, active probe, pcap reader) + Rich/JSON CLI with
  pmtud-sweeper-style exit codes (0 clean, 1 setup error, 2 ≥1 MIDPATH).
* **Phase 3a** — deterministic fixture pcaps via `tests/fixtures/build_fixtures.py`.
  Three scenarios: clean server-originated RST, FortiGate inline forgery,
  client give-up. End-to-end tests in `test_fixtures.py`.
* **Phase 3b** — public GitHub repo, three commits (CI / publish / docs).
* **Phase 3c** — `test.yml` matrix, regenerates fixtures in CI, runs pytest.
  **Confirmed green on GitHub-hosted runners across 3.10–3.14.**
* **Phase 3d** — `publish.yml` written but **dormant**. Trusted Publishing
  on PyPI is **not** configured; do not tag `v*.*.*` until/unless that's set
  up, or the publish job will go red.
* **Phase 3e** — README badges (CI + static Python-versions + MIT) and "why
  this exists" callout. PyPI badges removed because the repo isn't published.
* **Phase 3f** — Python 3.14 added to CI matrix after local verification that
  scapy 2.7.0 works on 3.14.

## Decisions worth not re-litigating

* **Not publishing to PyPI.** Goal is the blog post; `pip install
  git+https://github.com/MichealGarner/rst-forensics` is enough for readers
  who want to try it. `publish.yml` left dormant in case future-Micheal
  changes his mind.
* **Fixture pcaps are built in CI / locally, not committed.** Builder is
  deterministic, pcaps are byte-identical across runs. Keeps repo lean.
* **Scapy is optional.** The classifier core has no scapy dependency. Only
  the adapters and the fixture *builder* need it. `test_fixtures.py` skips
  cleanly when scapy isn't installed.
* **CI matrix is 3.10–3.14**, matching `requires-python = ">=3.10"` in
  pyproject.

## Operational notes for future Claude sessions

* **Author env**: Windows, PowerShell, Python 3.14 installed system-wide.
  Working directory is `D:\Workarea\Claude\Projects\rst-forensics`. PowerShell
  execution policy was set to `RemoteSigned -Scope CurrentUser`, so `.ps1`
  activate scripts work.
* **Local dev loop**:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  pip install -e ".[test,all]"
  python tests/fixtures/build_fixtures.py
  pytest -q
  ```
  46 tests, ~all green on 3.14.
* **scapy on Windows** emits `WARNING: No libpcap provider available ! pcap
  won't be used` at import. Harmless for pcap *reading* and packet *building*
  (which is what tests use). Only matters for live capture (`rst-forensics
  passive` / `active`) — install Npcap from npcap.com if you need that.
* **Sandbox/shell flake**: in at least one Cowork session, the workspace
  Linux sandbox failed to boot ("Workspace unavailable. The isolated Linux
  environment failed to start"). File tools still worked. If shell is dead,
  hand the user PowerShell commands to run locally rather than burning time
  retrying the sandbox.

## Open / next

* **Blog post.** The next session is for drafting it. Audience, length,
  publication venue, tone, and which scenario to lead with are all TBD —
  the user will brief the new session directly. Material to draw from:
  the README's "why this exists" callout, the heuristics table, the three
  fixture scenarios in `test_fixtures.py`, and the `Verdict.explain()`
  output style.
* **Phase 4 (deferred, possibly never)** — direction-aware scoring so an
  outgoing client RST verdicts as `CLIENT` instead of `SERVER`-leaning with
  a CLIENT timing dissent. Not blocking the blog post; flag for the future.

## Things to avoid

* Don't re-add PyPI version / pyversions badges to the README — they'll
  render as "not found".
* Don't tag `v*.*.*` without first either configuring Trusted Publishing on
  PyPI or temporarily disabling `publish.yml`. Otherwise a red publish job
  appears in Actions for no benefit.
* Don't commit the fixture `.pcap` files — they're built on demand and
  are gitignored via `tests/fixtures/*.pcap` (and `.pcapng`). If you find
  yourself wanting to commit one, the deterministic builder is the right
  source of truth, not a checked-in binary.

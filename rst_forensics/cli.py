"""rst-forensics command-line interface.

Three modes mirror the three adapters:

    rst-forensics pcap path.pcap
    rst-forensics passive --iface eth0 [--filter "tcp"] [--count N | --timeout S]
    rst-forensics active --host example.com --port 443 [--timeout S]

Output is a Rich table by default, JSON with ``--json``. Exit codes follow
the ``pmtud-sweeper`` convention so this slots into a CI gate:

    0  no RSTs, or only SERVER / CLIENT verdicts
    1  setup error (bad args, missing pcap, scapy unavailable, no privilege)
    2  at least one RST classified as MIDPATH
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable

from .observation import RstObservation
from .scoring import Origin
from .verdict import Verdict, classify


def _verdicts(rsts: Iterable[RstObservation]) -> list[tuple[RstObservation, Verdict]]:
    return [(o, classify(o)) for o in rsts]


def _exit_code(verdicts: list[tuple[RstObservation, Verdict]]) -> int:
    return 2 if any(v.origin is Origin.MIDPATH for _, v in verdicts) else 0


def _emit_json(verdicts: list[tuple[RstObservation, Verdict]]) -> None:
    payload = []
    for obs, v in verdicts:
        payload.append({
            "verdict": v.origin.value,
            "confidence": round(v.confidence, 3),
            "scores": {o.value: round(w, 3) for o, w in v.scores.items()},
            "rst": {
                "direction": obs.direction.value,
                "ttl": obs.ttl,
                "ip_id": obs.ip_id,
                "window": obs.window,
                "seq": obs.seq,
                "options": sorted(obs.options_present),
                "delta_seconds": obs.arrival_delta,
            },
            "evidence": [
                {"origin": s.origin.value, "weight": s.weight, "reason": s.reason}
                for s in v.evidence
            ],
        })
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _emit_table(verdicts: list[tuple[RstObservation, Verdict]]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        # Plain-text fallback so the CLI still works without rich installed.
        if not verdicts:
            print("(no RSTs observed)")
            return
        for i, (obs, v) in enumerate(verdicts, 1):
            print(
                f"{i:>3}  {obs.direction.value:<10} ttl={obs.ttl:<3} "
                f"ip_id={obs.ip_id:<6} win={obs.window:<6} "
                f"=> {v.origin.value:<7} ({v.confidence:.0%})"
            )
        return

    console = Console()
    if not verdicts:
        console.print("[dim](no RSTs observed)[/dim]")
        return

    colours = {
        "server": "green",
        "midpath": "red",
        "client": "yellow",
        "unknown": "dim",
    }
    table = Table(title="RST observations")
    table.add_column("#", justify="right")
    table.add_column("dir")
    table.add_column("ttl", justify="right")
    table.add_column("ip-id", justify="right")
    table.add_column("win", justify="right")
    table.add_column("opts")
    table.add_column("verdict")
    table.add_column("conf", justify="right")
    for i, (obs, v) in enumerate(verdicts, 1):
        colour = colours.get(v.origin.value, "white")
        table.add_row(
            str(i),
            obs.direction.value,
            str(obs.ttl),
            str(obs.ip_id),
            str(obs.window),
            ",".join(sorted(obs.options_present)) or "-",
            f"[{colour}]{v.origin.value}[/{colour}]",
            f"{v.confidence:.0%}",
        )
    console.print(table)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rst-forensics",
        description="Classify TCP RST origin (server / midpath / client).",
    )
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of a table")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-RST output (exit code still set)")

    sub = parser.add_subparsers(dest="mode", required=True)

    p_pcap = sub.add_parser("pcap", help="Read RSTs from a pcap/pcapng file")
    p_pcap.add_argument("path")

    p_passive = sub.add_parser("passive", help="Sniff live traffic")
    p_passive.add_argument("--iface")
    p_passive.add_argument("--filter", default="tcp", dest="bpf",
                           help="BPF filter (default: tcp)")
    p_passive.add_argument("--count", type=int, default=0,
                           help="Stop after N packets (0 = unlimited)")
    p_passive.add_argument("--timeout", type=float,
                           help="Stop after this many seconds")

    p_active = sub.add_parser("active", help="Probe host:port and classify any RST")
    p_active.add_argument("--host", required=True)
    p_active.add_argument("--port", type=int, required=True)
    p_active.add_argument("--timeout", type=float, default=5.0)
    p_active.add_argument("--iface")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.mode == "pcap":
            from .adapters import pcap as pcap_adapter
            rsts = pcap_adapter.read(args.path)
        elif args.mode == "passive":
            from .adapters import passive as passive_adapter
            rsts = passive_adapter.sniff(
                iface=args.iface,
                bpf_filter=args.bpf,
                count=args.count,
                timeout=args.timeout,
            )
        elif args.mode == "active":
            from .adapters import active as active_adapter
            rsts = active_adapter.probe(
                args.host, args.port,
                timeout=args.timeout, iface=args.iface,
            )
        else:  # pragma: no cover — argparse rejects this first
            print(f"error: unknown mode {args.mode!r}", file=sys.stderr)
            return 1
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except ImportError as e:
        print(f"error: scapy is required for this mode ({e})", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(
            f"error: insufficient privilege ({e}); "
            "try sudo or grant CAP_NET_RAW",
            file=sys.stderr,
        )
        return 1

    verdicts = _verdicts(rsts)
    if not args.quiet:
        if args.json:
            _emit_json(verdicts)
        else:
            _emit_table(verdicts)
    return _exit_code(verdicts)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

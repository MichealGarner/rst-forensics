"""Verdict aggregator.

Sums each scorer's weight into the origin it voted for (ignoring UNKNOWN
abstentions), picks the largest, and reports confidence as the winner's
share of the total cast weight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .observation import RstObservation
from .scoring import ALL_SCORERS, Origin, Score


@dataclass(frozen=True)
class Verdict:
    origin: Origin
    confidence: float                # winning_weight / total_cast_weight
    scores: dict[Origin, float]      # totals per origin (incl. UNKNOWN at 0)
    evidence: list[Score] = field(default_factory=list)

    def explain(self) -> str:
        lines = [f"Verdict: {self.origin.value}  confidence={self.confidence:.2f}"]
        for o, total in sorted(self.scores.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {o.value:<8} {total:5.2f}")
        lines.append("Evidence:")
        for s in self.evidence:
            lines.append(f"  [{s.origin.value:<7} w={s.weight:.2f}] {s.reason}")
        return "\n".join(lines)


def classify(
    obs: RstObservation,
    scorers: Iterable = ALL_SCORERS,
) -> Verdict:
    """Run every scorer against ``obs`` and aggregate into a Verdict."""
    totals: dict[Origin, float] = {o: 0.0 for o in Origin}
    evidence: list[Score] = []
    for fn in scorers:
        s = fn(obs)
        evidence.append(s)
        if s.origin is not Origin.UNKNOWN:
            totals[s.origin] += s.weight

    contestants = {o: w for o, w in totals.items() if o is not Origin.UNKNOWN}
    cast = sum(contestants.values())
    if cast == 0.0:
        return Verdict(Origin.UNKNOWN, 0.0, totals, evidence)

    winner, win_weight = max(contestants.items(), key=lambda kv: kv[1])
    return Verdict(winner, win_weight / cast, totals, evidence)

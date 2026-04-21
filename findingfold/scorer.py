"""Priority scoring for folded groups.

Weights are tunable defaults. Override via --severity-weights or config file
if your org prioritizes differently.
"""

import math

from .fold import FoldedGroup, SEVERITY_RANK

# Default weights — adjust to your org's priorities
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "INFORMATIONAL": 0}


def score_group(g: FoldedGroup) -> float:
    score = SEVERITY_WEIGHT.get(g.severity, 5)
    score += min(math.log2(max(g.finding_count, 1)) * 5, 20)
    score += min(math.log2(max(g.resource_count, 1)) * 5, 15)
    if len(g.accounts) > 1:
        score += 10
    if g.first_seen:
        from datetime import datetime, timezone
        try:
            first = datetime.fromisoformat(g.first_seen.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - first).days
            if age_days > 90:
                score += 10
            elif age_days > 30:
                score += 5
        except (ValueError, TypeError):
            pass
    return round(min(score, 100), 1)

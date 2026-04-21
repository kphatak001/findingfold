"""Load and filter findings from various sources."""


def filter_findings(findings: list[dict], min_severity: str = "LOW",
                    include_suppressed: bool = False) -> list[dict]:
    """Filter findings by RecordState, Workflow.Status, and severity.

    By default:
    - Only ACTIVE findings (RecordState=ACTIVE)
    - Excludes SUPPRESSED (Workflow.Status != SUPPRESSED)
    - Respects min_severity threshold
    """
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
    min_rank = severity_rank.get(min_severity.upper(), 0)
    filtered = []
    for f in findings:
        if f.get("RecordState", "ACTIVE") != "ACTIVE":
            continue
        if not include_suppressed and f.get("Workflow", {}).get("Status") == "SUPPRESSED":
            continue
        sev = f.get("Severity", {}).get("Label", "LOW")
        if severity_rank.get(sev, 0) < min_rank:
            continue
        filtered.append(f)
    return filtered

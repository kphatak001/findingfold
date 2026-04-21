"""Core data model and fold engine."""

from dataclasses import dataclass, field
from typing import Optional
import hashlib


@dataclass
class FoldedGroup:
    group_id: str
    root_cause: str
    root_cause_type: str
    fix_target: str
    findings: list[dict] = field(default_factory=list)
    finding_count: int = 0
    resource_count: int = 0
    severity: str = "LOW"
    score: float = 0.0
    first_seen: str = ""
    accounts: set = field(default_factory=set)
    regions: set = field(default_factory=set)
    recommendation: str = ""
    explanations: list[str] = field(default_factory=list)


@dataclass
class FoldReport:
    total_findings: int = 0
    total_groups: int = 0
    compression_ratio: float = 0.0
    groups: list[FoldedGroup] = field(default_factory=list)
    ungrouped: list[dict] = field(default_factory=list)


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def _highest_severity(findings: list[dict]) -> str:
    best = "LOW"
    for f in findings:
        sev = f.get("Severity", {}).get("Label", "LOW")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(best, 0):
            best = sev
    return best


def _first_seen(findings: list[dict]) -> str:
    dates = [f.get("FirstObservedAt", f.get("CreatedAt", "")) for f in findings]
    return min((d for d in dates if d), default="")


def _unique_resources(findings: list[dict]) -> int:
    ids = set()
    for f in findings:
        for r in f.get("Resources", []):
            ids.add(r.get("Id", ""))
    return len(ids)


def _accounts(findings: list[dict]) -> set:
    return {f.get("AwsAccountId", "") for f in findings if f.get("AwsAccountId")}


def _regions(findings: list[dict]) -> set:
    regions = set()
    for f in findings:
        # Extract region from finding ARN or Resources
        for r in f.get("Resources", []):
            rid = r.get("Id", "")
            if rid.startswith("arn:aws:"):
                parts = rid.split(":")
                if len(parts) > 3 and parts[3]:
                    regions.add(parts[3])
        # Also check ProductArn
        parn = f.get("ProductArn", "")
        if parn.startswith("arn:aws:"):
            parts = parn.split(":")
            if len(parts) > 3 and parts[3]:
                regions.add(parts[3])
    return regions


def fold(findings: list[dict], rules: list = None, explain: bool = False) -> FoldReport:
    """Run findings through fold rules in priority order. First match wins."""
    from .rules import ami, cloudformation, iac_tag, security_group, iam_policy, title_fingerprint
    from .scorer import score_group

    all_rules = [
        ami.AmiRule(),
        cloudformation.CloudFormationRule(),
        iac_tag.IacTagRule(),
        security_group.SecurityGroupRule(),
        iam_policy.IamPolicyRule(),
        title_fingerprint.TitleFingerprintRule(),
    ]

    if rules and rules != ["all"]:
        rule_names = set(rules)
        all_rules = [r for r in all_rules if r.name in rule_names]

    # group_key → (rule, list[finding], list[explanation])
    groups: dict[str, tuple] = {}
    ungrouped = []

    for f in findings:
        matched = False
        for rule in all_rules:
            result = rule.match(f)
            if result:
                key = result["key"]
                if key not in groups:
                    groups[key] = (rule, result, [], [])
                groups[key][2].append(f)
                if explain:
                    fid = f.get("Id", "unknown")[:60]
                    groups[key][3].append(f"{fid} → {rule.name}: {result.get('reason', key)}")
                matched = True
                break
        if not matched:
            ungrouped.append(f)

    # Build FoldedGroup objects
    folded = []
    for key, (rule, result, group_findings, explanations) in groups.items():
        g = FoldedGroup(
            group_id=hashlib.sha256(key.encode()).hexdigest()[:12],
            root_cause=result["root_cause"],
            root_cause_type=rule.name,
            fix_target=result["fix_target"],
            findings=group_findings,
            finding_count=len(group_findings),
            resource_count=_unique_resources(group_findings),
            severity=_highest_severity(group_findings),
            first_seen=_first_seen(group_findings),
            accounts=_accounts(group_findings),
            regions=_regions(group_findings),
            recommendation=result.get("recommendation", ""),
            explanations=explanations,
        )
        g.score = score_group(g)
        folded.append(g)

    folded.sort(key=lambda g: g.score, reverse=True)

    total = len(findings)
    n_groups = len(folded)
    return FoldReport(
        total_findings=total,
        total_groups=n_groups,
        compression_ratio=round(total / n_groups, 1) if n_groups else 0,
        groups=folded,
        ungrouped=ungrouped,
    )

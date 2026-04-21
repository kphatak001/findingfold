"""Output: terminal, JSON, markdown, CSV."""

import json
import sys
import csv
import io

from .fold import FoldReport, FoldedGroup


def report_terminal(report: FoldReport, verbose: bool = False, explain: bool = False, file=None):
    out = file or sys.stdout

    print(f"\nfindingfold report", file=out)
    print("═" * 60, file=out)
    print(f"\n  📊 {report.total_findings} findings → {report.total_groups} root causes "
          f"({report.compression_ratio}x compression)\n", file=out)

    for i, g in enumerate(report.groups, 1):
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(g.severity, "⚪")
        print(f"  #{i} [{g.severity}] {sev_icon} Score: {g.score} {'─' * 30}", file=out)
        print(f"  {g.root_cause}", file=out)
        print(f"  │ {g.finding_count} findings across {g.resource_count} resources", file=out)
        if g.accounts:
            accts = ", ".join(sorted(g.accounts))
            print(f"  │ Accounts: {accts}", file=out)
        if g.regions:
            print(f"  │ Regions: {', '.join(sorted(g.regions))}", file=out)
        if g.first_seen:
            print(f"  │ First seen: {g.first_seen[:10]}", file=out)
        if g.recommendation:
            print(f"  │ Fix: {g.recommendation}", file=out)

        if explain and g.explanations:
            print(f"  │ Grouping rationale:", file=out)
            shown = g.explanations[:5] if not verbose else g.explanations
            for exp in shown:
                print(f"  │   • {exp}", file=out)
            if len(g.explanations) > 5 and not verbose:
                print(f"  │   ... and {len(g.explanations) - 5} more (use -v to see all)", file=out)

        if verbose:
            print(f"  │ Finding IDs:", file=out)
            for f in g.findings[:10]:
                print(f"  │   {f.get('Id', 'unknown')[:80]}", file=out)
            if len(g.findings) > 10:
                print(f"  │   ... and {len(g.findings) - 10} more", file=out)
        print(file=out)

    if report.ungrouped:
        print(f"  ─────────────────────────────────────────────────────────", file=out)
        print(f"  Ungrouped: {len(report.ungrouped)} findings", file=out)

    print("═" * 60 + "\n", file=out)


def report_json(report: FoldReport, explain: bool = False, file=None):
    out = file or sys.stdout
    data = {
        "total_findings": report.total_findings,
        "total_groups": report.total_groups,
        "compression_ratio": report.compression_ratio,
        "groups": [],
        "ungrouped_count": len(report.ungrouped),
    }
    for g in report.groups:
        entry = {
            "group_id": g.group_id,
            "root_cause": g.root_cause,
            "root_cause_type": g.root_cause_type,
            "fix_target": g.fix_target,
            "finding_count": g.finding_count,
            "resource_count": g.resource_count,
            "severity": g.severity,
            "score": g.score,
            "first_seen": g.first_seen,
            "accounts": sorted(g.accounts),
            "regions": sorted(g.regions),
            "recommendation": g.recommendation,
            "finding_ids": [f.get("Id", "") for f in g.findings],
        }
        if explain:
            entry["explanations"] = g.explanations
        data["groups"].append(entry)
    print(json.dumps(data, indent=2, default=str), file=out)


def report_markdown(report: FoldReport, file=None):
    out = file or sys.stdout
    print(f"# findingfold Report\n", file=out)
    print(f"**{report.total_findings}** findings → **{report.total_groups}** root causes "
          f"(**{report.compression_ratio}x** compression)\n", file=out)
    print("| # | Severity | Score | Root Cause | Findings | Resources | Fix |", file=out)
    print("|---|----------|-------|------------|----------|-----------|-----|", file=out)
    for i, g in enumerate(report.groups, 1):
        cause = g.root_cause[:60] + "..." if len(g.root_cause) > 60 else g.root_cause
        rec = g.recommendation[:40] + "..." if len(g.recommendation) > 40 else g.recommendation
        print(f"| {i} | {g.severity} | {g.score} | {cause} | {g.finding_count} | {g.resource_count} | {rec} |", file=out)
    print(file=out)
    if report.ungrouped:
        print(f"**Ungrouped:** {len(report.ungrouped)} findings\n", file=out)


def report_csv(report: FoldReport, file=None):
    out = file or sys.stdout
    writer = csv.writer(out)
    writer.writerow(["rank", "severity", "score", "root_cause", "root_cause_type",
                      "fix_target", "finding_count", "resource_count", "accounts", "regions",
                      "recommendation"])
    for i, g in enumerate(report.groups, 1):
        writer.writerow([i, g.severity, g.score, g.root_cause, g.root_cause_type,
                          g.fix_target, g.finding_count, g.resource_count,
                          ";".join(sorted(g.accounts)), ";".join(sorted(g.regions)),
                          g.recommendation])

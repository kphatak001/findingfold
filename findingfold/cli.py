"""CLI entry point for findingfold."""

import argparse
import sys

from . import __version__
from .ingest import filter_findings
from .fold import fold
from .reporter import report_terminal, report_json, report_markdown, report_csv


def main():
    parser = argparse.ArgumentParser(
        prog="findingfold",
        description="Collapse security findings by root cause. "
                    "200 findings → 12 fixes.",
    )
    parser.add_argument("source", nargs="?", help="Path to findings JSON or SARIF file")
    parser.add_argument("--from-hub", action="store_true", help="Load from Security Hub API (requires boto3)")
    parser.add_argument("--accounts", help="Comma-separated AWS account IDs (with --from-hub)")
    parser.add_argument("--region", help="AWS region (with --from-hub)")
    parser.add_argument("--sarif", action="store_true", help="Treat input file as SARIF format")
    parser.add_argument("--min-severity", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                        help="Minimum severity (default: LOW)")
    parser.add_argument("--min-group-size", type=int, default=2,
                        help="Only show groups with N+ findings (default: 2)")
    parser.add_argument("--format", dest="fmt", default="terminal",
                        choices=["terminal", "json", "markdown", "csv"],
                        help="Output format (default: terminal)")
    parser.add_argument("-o", "--output", help="Write report to file")
    parser.add_argument("--show-ungrouped", action="store_true", help="Include ungrouped findings")
    parser.add_argument("--rules", default="all",
                        help="Fold rules: all (default), ami, cloudformation, iac, security_group, iam, title")
    parser.add_argument("--max-findings", type=int, default=10000, help="Max findings to ingest (default: 10000)")
    parser.add_argument("--include-suppressed", action="store_true", help="Include SUPPRESSED findings")
    parser.add_argument("--enrich", action="store_true",
                        help="Enrich findings with AWS API data (backfill AMI IDs, etc.)")
    parser.add_argument("--filter-fp", action="store_true",
                        help="Use LLM to filter likely false positives before folding (requires anthropic or openai)")
    parser.add_argument("--fp-backend", choices=["anthropic", "openai"],
                        help="LLM backend for --filter-fp (auto-detects from env if omitted)")
    parser.add_argument("--explain", action="store_true",
                        help="Show why each finding was grouped where it was")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show individual findings within groups")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Load findings
    if args.from_hub:
        from .sources.security_hub import load
        accounts = args.accounts.split(",") if args.accounts else None
        findings = load(region=args.region, accounts=accounts,
                        min_severity=args.min_severity, max_findings=args.max_findings)
    elif args.source:
        if args.sarif or args.source.endswith(".sarif") or args.source.endswith(".sarif.json"):
            from .sources.sarif import load
        else:
            from .sources.json_file import load
        findings = load(args.source, max_findings=args.max_findings)
    else:
        parser.error("Provide a findings file or use --from-hub")

    # Filter
    findings = filter_findings(findings, min_severity=args.min_severity,
                               include_suppressed=args.include_suppressed)

    if not findings:
        print("No findings match the filter criteria.", file=sys.stderr)
        sys.exit(0)

    # Enrich (before fold)
    if args.enrich:
        from .enrich import enrich_ami_ids
        findings = enrich_ami_ids(findings, region=args.region)

    # Filter false positives (before fold)
    fp_removed = []
    if args.filter_fp:
        from .fp_filter import filter_false_positives
        findings, fp_removed = filter_false_positives(
            findings, backend=args.fp_backend, verbose=args.verbose)
        print(f"FP filter: {len(fp_removed)} likely false positives removed, "
              f"{len(findings)} findings remaining.", file=sys.stderr)

    # Fold
    rules = None if args.rules == "all" else args.rules.split(",")
    report = fold(findings, rules=rules, explain=args.explain)

    # Filter by min group size
    if args.min_group_size > 1:
        report.ungrouped.extend(
            f for g in report.groups if g.finding_count < args.min_group_size for f in g.findings
        )
        report.groups = [g for g in report.groups if g.finding_count >= args.min_group_size]
        report.total_groups = len(report.groups)
        if report.total_groups:
            report.compression_ratio = round(report.total_findings / report.total_groups, 1)

    # Report
    out = open(args.output, "w") if args.output else sys.stdout
    try:
        if args.fmt == "json":
            report_json(report, explain=args.explain, file=out)
        elif args.fmt == "markdown":
            report_markdown(report, file=out)
        elif args.fmt == "csv":
            report_csv(report, file=out)
        else:
            report_terminal(report, verbose=args.verbose, explain=args.explain, file=out)
    finally:
        if args.output:
            out.close()


if __name__ == "__main__":
    main()

"""MCP server exposing findingfold as agent-installable tools."""

import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .fold import fold
from .ingest import filter_findings
from .reporter import report_json

mcp = FastMCP("findingfold", instructions=(
    "Collapse security findings by root cause. "
    "Takes Security Hub JSON, SARIF files, or live API data and groups "
    "duplicate findings into actionable fix targets."
))


def _fold_and_report(findings: list[dict], min_severity: str, rules: list | None,
                     min_group_size: int) -> str:
    findings = filter_findings(findings, min_severity=min_severity)
    if not findings:
        return json.dumps({"error": "No findings match the filter criteria."})
    report = fold(findings, rules=rules, explain=True)
    if min_group_size > 1:
        report.groups = [g for g in report.groups if g.finding_count >= min_group_size]
        report.total_groups = len(report.groups)
        if report.total_groups:
            report.compression_ratio = round(report.total_findings / report.total_groups, 1)
    import io
    buf = io.StringIO()
    report_json(report, explain=True, file=buf)
    return buf.getvalue()


@mcp.tool()
def fold_findings(file_path: str, min_severity: str = "LOW",
                  rules: str = "all", min_group_size: int = 2) -> str:
    """Fold a Security Hub JSON export by root cause.

    Args:
        file_path: Path to Security Hub findings JSON file.
        min_severity: Minimum severity: CRITICAL, HIGH, MEDIUM, LOW.
        rules: Comma-separated fold rules (ami,cloudformation,iac,security_group,iam,title) or 'all'.
        min_group_size: Only return groups with this many findings or more.
    """
    path = Path(file_path).expanduser()
    if not path.exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    data = json.loads(path.read_text())
    findings = data if isinstance(data, list) else data.get("Findings", data.get("findings", []))
    rule_list = None if rules == "all" else rules.split(",")
    return _fold_and_report(findings, min_severity, rule_list, min_group_size)


@mcp.tool()
def fold_sarif(file_path: str, min_severity: str = "LOW",
               rules: str = "all", min_group_size: int = 2) -> str:
    """Fold a SARIF file (Semgrep, Snyk, Trivy, GitHub Code Scanning) by root cause.

    Args:
        file_path: Path to SARIF (.sarif or .sarif.json) file.
        min_severity: Minimum severity: CRITICAL, HIGH, MEDIUM, LOW.
        rules: Comma-separated fold rules or 'all'.
        min_group_size: Only return groups with this many findings or more.
    """
    path = Path(file_path).expanduser()
    if not path.exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    from .sources.sarif import load
    findings = load(str(path))
    rule_list = None if rules == "all" else rules.split(",")
    return _fold_and_report(findings, min_severity, rule_list, min_group_size)


@mcp.tool()
def fold_from_security_hub(region: str = "us-east-1", accounts: str = "",
                           min_severity: str = "LOW", rules: str = "all",
                           min_group_size: int = 2, enrich: bool = False) -> str:
    """Pull findings from Security Hub API and fold by root cause. Requires boto3 and AWS credentials.

    Args:
        region: AWS region to query.
        accounts: Comma-separated AWS account IDs (empty = all accessible).
        min_severity: Minimum severity: CRITICAL, HIGH, MEDIUM, LOW.
        rules: Comma-separated fold rules or 'all'.
        min_group_size: Only return groups with this many findings or more.
        enrich: Backfill AMI IDs via EC2 API for better grouping.
    """
    try:
        from .sources.security_hub import load
    except ImportError:
        return json.dumps({"error": "boto3 required. Install with: pip install findingfold[aws]"})
    acct_list = accounts.split(",") if accounts else None
    findings = load(region=region, accounts=acct_list, min_severity=min_severity)
    if enrich:
        from .enrich import enrich_ami_ids
        findings = enrich_ami_ids(findings, region=region)
    rule_list = None if rules == "all" else rules.split(",")
    return _fold_and_report(findings, min_severity, rule_list, min_group_size)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

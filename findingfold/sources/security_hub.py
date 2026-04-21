"""Load findings from Security Hub API via boto3.

Requires: pip install findingfold[aws]
Uses default boto3 credential chain. For cross-account, configure
a delegated admin account or use --profile with assumed roles.
"""


def load(region: str = None, accounts: list[str] = None,
         min_severity: str = "LOW", max_findings: int = 10000) -> list[dict]:
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 required for --from-hub. Install with: pip install findingfold[aws]")

    client = boto3.client("securityhub", region_name=region) if region else boto3.client("securityhub")

    filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
    if accounts:
        filters["AwsAccountId"] = [{"Value": a, "Comparison": "EQUALS"} for a in accounts]

    severity_map = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 1}
    if min_severity.upper() in severity_map:
        filters["SeverityNormalized"] = [{"Gte": severity_map[min_severity.upper()]}]

    findings = []
    paginator = client.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters, MaxResults=100):
        findings.extend(page.get("Findings", []))
        if len(findings) >= max_findings:
            break

    return findings[:max_findings]

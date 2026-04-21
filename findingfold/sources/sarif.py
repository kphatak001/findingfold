"""Load findings from SARIF (Static Analysis Results Interchange Format).

SARIF is the open standard for security findings. Supported by:
GitHub Code Scanning, Snyk, Semgrep, Checkov, Trivy, and many others.

Converts SARIF results into Security Hub-compatible finding dicts
so the fold engine can process them uniformly.
"""

import json


def _sarif_severity_to_label(level: str) -> str:
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFORMATIONAL"}.get(level, "MEDIUM")


def load(path: str, max_findings: int = 10000) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    findings = []
    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules_map = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules_map[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules_map.get(rule_id, {})
            level = result.get("level", "warning")

            # Build location info
            locations = result.get("locations", [])
            resource_id = ""
            if locations:
                phys = locations[0].get("physicalLocation", {})
                resource_id = phys.get("artifactLocation", {}).get("uri", "")

            finding = {
                "Id": f"sarif:{tool_name}:{rule_id}:{resource_id}",
                "Title": result.get("message", {}).get("text", rule.get("shortDescription", {}).get("text", rule_id)),
                "Description": rule.get("fullDescription", {}).get("text", ""),
                "GeneratorId": f"{tool_name}/{rule_id}",
                "Severity": {"Label": _sarif_severity_to_label(level)},
                "RecordState": "ACTIVE",
                "Resources": [{"Type": "File", "Id": resource_id}],
                "ProductArn": f"sarif:{tool_name}",
                "AwsAccountId": "",
                "CreatedAt": "",
                # Preserve SARIF metadata for rules that need it
                "_sarif": {"tool": tool_name, "ruleId": rule_id, "level": level},
            }
            findings.append(finding)
            if len(findings) >= max_findings:
                return findings

    return findings

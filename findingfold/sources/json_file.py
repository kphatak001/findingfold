"""Load findings from exported JSON file.

Accepts:
  - Security Hub GetFindings response: {"Findings": [...]}
  - Raw array of findings: [...]
  - Multi-account merged: multiple files or array of arrays

For multi-account: each finding should have AwsAccountId populated.
If merging exports from different accounts manually, ensure each file's
findings include the account ID (Security Hub exports include this by default).
"""

import json


def load(path: str, max_findings: int = 10000) -> list[dict]:
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("Findings", data.get("findings", data.get("results", [])))
    else:
        raise ValueError(f"Unexpected JSON format in {path}")

    return findings[:max_findings]

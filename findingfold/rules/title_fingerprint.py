"""Catch-all: group findings by normalized title fingerprint.

Handles findings not caught by more specific rules. Strips resource-specific
identifiers (ARNs, instance IDs, bucket names, account IDs) to find findings
that are the same issue on different resources.

Normalization examples:
  Security Hub: "S3 bucket my-bucket-prod-123 does not have encryption"
              → "S3 bucket * does not have encryption"
  GuardDuty:   "UnauthorizedAccess:EC2/SSHBruteForce on i-0abc123"
              → "UnauthorizedAccess:EC2/SSHBruteForce on *"
  Config:      "s3-bucket-logging-enabled on my-bucket"
              → "s3-bucket-logging-enabled on *"
  Inspector:   "CVE-2026-1234 - package xyz on i-0abc123"
              → "CVE-2026-1234 - package xyz on *"
"""

import re
import hashlib

from . import BaseRule

# Patterns to strip from titles for normalization
_STRIP_PATTERNS = [
    r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{0,12}:[^\s,\]\"']*",  # ARNs (incl S3 with empty fields)
    r"\bi-[0-9a-f]{7,17}\b",                                     # EC2 instance IDs
    r"\bami-[0-9a-f]{8,17}\b",                                   # AMI IDs
    r"\bsg-[0-9a-f]{8,17}\b",                                    # Security group IDs
    r"\bvpc-[0-9a-f]{8,17}\b",                                   # VPC IDs
    r"\bsubnet-[0-9a-f]{8,17}\b",                                # Subnet IDs
    r"\bvol-[0-9a-f]{8,17}\b",                                   # EBS volume IDs
    r"\bsnap-[0-9a-f]{8,17}\b",                                  # Snapshot IDs
    r"\beni-[0-9a-f]{8,17}\b",                                   # ENI IDs
    r"\b\d{12}\b",                                                # AWS account IDs
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",  # UUIDs
    r"[a-z0-9][a-z0-9.\-]{2,62}\.s3[.\-]",                      # S3 bucket names in URLs
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _STRIP_PATTERNS]


def normalize_title(title: str) -> str:
    result = title
    for pat in _COMPILED:
        result = pat.sub("*", result)
    # Collapse multiple * and whitespace
    result = re.sub(r"\*[\s,]*\*", "*", result)
    result = re.sub(r"\s+", " ", result).strip()
    return result


class TitleFingerprintRule(BaseRule):
    name = "title"

    def match(self, finding: dict):
        title = finding.get("Title", "")
        if not title:
            return None
        severity = finding.get("Severity", {}).get("Label", "LOW")
        generator = finding.get("GeneratorId", "")
        normalized = normalize_title(title)
        key = f"title:{hashlib.sha256(f'{normalized}:{severity}:{generator}'.encode()).hexdigest()[:16]}"
        return {
            "key": key,
            "root_cause": normalized,
            "fix_target": generator.split("/")[-1] if "/" in generator else normalized[:80],
            "recommendation": f"Remediate: {normalized}",
            "reason": f"title fingerprint (normalized from: {title[:60]})",
        }

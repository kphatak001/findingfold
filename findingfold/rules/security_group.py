"""Group findings by shared security group rule patterns."""

import json
import hashlib

from . import BaseRule


def _sg_rule_fingerprint(finding: dict) -> str | None:
    """Hash the SG rule pattern (ports + CIDRs) for grouping."""
    for r in finding.get("Resources", []):
        sg = r.get("Details", {}).get("AwsEc2SecurityGroup", {})
        perms = sg.get("IpPermissions", []) + sg.get("IpPermissionsEgress", [])
        if perms:
            # Normalize and hash
            normalized = json.dumps(perms, sort_keys=True, default=str)
            return hashlib.sha256(normalized.encode()).hexdigest()[:16]
    return None


class SecurityGroupRule(BaseRule):
    name = "security_group"

    def match(self, finding: dict):
        fp = _sg_rule_fingerprint(finding)
        if not fp:
            return None
        title = finding.get("Title", "security group misconfiguration")
        key = f"sg:{fp}:{title}"
        return {
            "key": key,
            "root_cause": f"Security groups with identical rule pattern — {title}",
            "fix_target": f"SG rule pattern {fp[:8]}",
            "recommendation": "Update the common security group rule pattern across all affected groups",
            "reason": f"SG rule fingerprint={fp[:8]}",
        }

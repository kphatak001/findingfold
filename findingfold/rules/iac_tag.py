"""Group findings by IaC tags (Terraform, CDK, Pulumi)."""

from . import BaseRule

_IAC_TAG_MAP = {
    "tf_module": "terraform",
    "tf_workspace": "terraform",
    "terraform:module": "terraform",
    "aws:cdk:path": "cdk",
    "pulumi:project": "pulumi",
    "pulumi:stack": "pulumi",
}


def _get_iac_info(finding: dict) -> tuple[str, str, str] | None:
    """Return (tool, tag_key, tag_value) or None."""
    for r in finding.get("Resources", []):
        tags = r.get("Tags", {})
        items = tags.items() if isinstance(tags, dict) else [(t["Key"], t["Value"]) for t in tags] if isinstance(tags, list) else []
        for k, v in items:
            if k in _IAC_TAG_MAP:
                return _IAC_TAG_MAP[k], k, v
    return None


class IacTagRule(BaseRule):
    name = "iac"

    def match(self, finding: dict):
        info = _get_iac_info(finding)
        if not info:
            return None
        tool, tag_key, tag_value = info
        key = f"iac:{tool}:{tag_value}"
        return {
            "key": key,
            "root_cause": f"{tool.title()} module '{tag_value}' has findings",
            "fix_target": tag_value,
            "recommendation": f"Update {tool} module '{tag_value}' and redeploy",
            "reason": f"{tag_key}={tag_value}",
        }

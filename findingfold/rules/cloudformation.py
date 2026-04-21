"""Group findings by CloudFormation stack."""

from . import BaseRule

_CFN_TAG_KEYS = {"aws:cloudformation:stack-name", "aws:cloudformation:stack-id"}


def _get_stack_name(finding: dict) -> str | None:
    for r in finding.get("Resources", []):
        tags = r.get("Tags", {})
        if isinstance(tags, dict):
            for k in _CFN_TAG_KEYS:
                if k in tags:
                    return tags[k]
        elif isinstance(tags, list):
            for t in tags:
                if t.get("Key") in _CFN_TAG_KEYS:
                    return t.get("Value")
    return None


class CloudFormationRule(BaseRule):
    name = "cloudformation"

    def match(self, finding: dict):
        stack = _get_stack_name(finding)
        if not stack:
            return None
        # Use stack name (strip stack-id to just name)
        name = stack.split("/")[1] if "/" in stack else stack
        key = f"cfn:{name}"
        return {
            "key": key,
            "root_cause": f"CloudFormation stack '{name}' has misconfigurations",
            "fix_target": name,
            "recommendation": f"Update template for stack '{name}' and redeploy",
            "reason": f"aws:cloudformation:stack-name={name}",
        }

"""Group findings by shared IAM policy."""

from . import BaseRule


def _get_policy_arn(finding: dict) -> str | None:
    for r in finding.get("Resources", []):
        # Direct IAM policy resource
        if r.get("Type") == "AwsIamPolicy":
            return r.get("Id")
        # IAM role with attached policies
        role = r.get("Details", {}).get("AwsIamRole", {})
        policies = role.get("AttachedManagedPolicies", [])
        if policies:
            # Return the first policy — grouping by shared policy
            return policies[0].get("PolicyArn", policies[0].get("PolicyName"))
    return None


class IamPolicyRule(BaseRule):
    name = "iam"

    def match(self, finding: dict):
        policy = _get_policy_arn(finding)
        if not policy:
            return None
        title = finding.get("Title", "IAM misconfiguration")
        # Use policy as group key (all roles sharing this policy group together)
        name = policy.split("/")[-1] if "/" in policy else policy
        key = f"iam:{policy}:{title}"
        return {
            "key": key,
            "root_cause": f"IAM policy '{name}' — {title}",
            "fix_target": name,
            "recommendation": f"Update or replace policy '{name}' with scoped permissions",
            "reason": f"PolicyArn={policy}",
        }

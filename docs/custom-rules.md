# Writing Custom Fold Rules

Add your own grouping logic by creating a rule module.

## Rule Interface

Every rule implements `BaseRule` with a single `match()` method:

```python
# findingfold/rules/my_rule.py

from . import BaseRule

class MyRule(BaseRule):
    name = "my_rule"  # Used in --rules flag and reports

    def match(self, finding: dict) -> dict | None:
        """Return a match dict if this rule applies, None otherwise.

        The match dict must contain:
          key          — Unique group key (findings with same key are grouped)
          root_cause   — Human-readable root cause description
          fix_target   — What to actually fix (AMI ID, stack name, etc.)
          recommendation — How to fix it
          reason       — Why this finding matched (shown in --explain mode)
        """
        # Your logic here
        return None
```

## Example: Group by AWS Account

```python
from . import BaseRule

class AccountRule(BaseRule):
    name = "account"

    def match(self, finding: dict):
        account = finding.get("AwsAccountId")
        title = finding.get("Title", "")
        if not account:
            return None
        key = f"account:{account}:{title}"
        return {
            "key": key,
            "root_cause": f"Account {account} — {title}",
            "fix_target": account,
            "recommendation": f"Fix in account {account}",
            "reason": f"AwsAccountId={account}",
        }
```

## Example: Group by Custom Tag

```python
from . import BaseRule

class TeamTagRule(BaseRule):
    name = "team_tag"

    def match(self, finding: dict):
        for r in finding.get("Resources", []):
            tags = r.get("Tags", {})
            if isinstance(tags, dict):
                team = tags.get("team") or tags.get("Team")
            elif isinstance(tags, list):
                team = next((t["Value"] for t in tags if t["Key"] in ("team", "Team")), None)
            else:
                continue
            if team:
                return {
                    "key": f"team:{team}",
                    "root_cause": f"Team '{team}' owns resources with findings",
                    "fix_target": team,
                    "recommendation": f"Route to team '{team}' for remediation",
                    "reason": f"tag:team={team}",
                }
        return None
```

## Registering Your Rule

Add it to the rule list in `findingfold/fold.py`:

```python
from .rules import my_rule

all_rules = [
    ami.AmiRule(),
    cloudformation.CloudFormationRule(),
    iac_tag.IacTagRule(),
    security_group.SecurityGroupRule(),
    iam_policy.IamPolicyRule(),
    my_rule.MyRule(),              # Add before title_fingerprint
    title_fingerprint.TitleFingerprintRule(),  # Keep last (catch-all)
]
```

**Rule priority matters.** Place more specific rules earlier. The title fingerprint rule should always be last — it's the catch-all.

## Key Design Rules

1. **Return `None` if the rule doesn't apply.** Don't force a match.
2. **The `key` determines grouping.** Two findings with the same key go in the same group.
3. **Be specific in the key.** `f"ami:{image_id}:{title}"` groups by AMI + finding type. Just `f"ami:{image_id}"` would group ALL findings for an AMI together regardless of type.
4. **The `fix_target` should be actionable.** "ami-0abc123" is actionable. "CVE-2026-1234" is not.
5. **Test with `--explain`** to verify your rule matches what you expect.

## Testing

```bash
# Run with only your rule
findingfold findings.json --rules my_rule --explain

# Compare with all rules
findingfold findings.json --explain
```

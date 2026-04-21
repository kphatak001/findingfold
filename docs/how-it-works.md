# How It Works

findingfold takes a flat list of security findings and collapses them into root-cause groups.

## The Problem

Security Hub generates findings per-resource:

```
Finding 1: CVE-2026-1234 on i-0aaa111
Finding 2: CVE-2026-1234 on i-0bbb222
Finding 3: CVE-2026-1234 on i-0ccc333
...
Finding 47: CVE-2026-1234 on i-0zzz999
```

All 47 instances were launched from the same AMI. There's one fix: rebuild the AMI.

## The Solution

findingfold runs 6 fold rules in priority order against each finding. The first rule that matches assigns the finding to a group.

### Rule Priority

1. **AMI** — Groups by `Resources[].Details.AwsEc2Instance.ImageId`. Most specific: "these 47 instances all came from the same AMI."
2. **CloudFormation** — Groups by `aws:cloudformation:stack-name` tag. "These 12 resources are all in the same stack."
3. **IaC Tags** — Groups by Terraform (`tf_module`), CDK (`aws:cdk:path`), or Pulumi (`pulumi:project`) tags.
4. **Security Group** — Hashes the SG rule set (ports + CIDRs) and groups SGs with identical patterns.
5. **IAM Policy** — Groups roles/users sharing the same overly-permissive policy.
6. **Title Fingerprint** — Catch-all. Normalizes the finding title (strips instance IDs, ARNs, account numbers) and groups identical normalized titles.

### Why Priority Matters

A finding might match both the AMI rule and the title fingerprint rule. The AMI rule wins because it's more actionable — "rebuild AMI ami-abc123" is a better fix target than "remediate CVE-2026-1234 across your fleet."

### Scoring

Each group gets a 0-100 priority score based on:
- Severity (CRITICAL=40, HIGH=30, MEDIUM=15, LOW=5)
- Finding count (logarithmic, capped at 20)
- Resource count (logarithmic, capped at 15)
- Multi-account spread (+10 if findings span accounts)
- Age (+5 if >30 days, +10 if >90 days)

Groups are sorted by score. The top group is always the highest-leverage fix.

### Title Normalization

The title fingerprint rule strips resource-specific identifiers:

| Raw Title | Normalized |
|-----------|------------|
| `UnauthorizedAccess:EC2/SSHBruteForce on i-0abc123` | `UnauthorizedAccess:EC2/SSHBruteForce on *` |
| `S3 bucket my-bucket-prod does not have encryption` | `S3 bucket * does not have encryption` |
| `CVE-2026-1234 - package xyz on i-0abc123` | `CVE-2026-1234 - package xyz on *` |
| `Issue in account 111122223333` | `Issue in account *` |

Stripped patterns: ARNs, instance IDs, AMI IDs, SG IDs, VPC IDs, account IDs, UUIDs, S3 bucket names.

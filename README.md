# findingfold

> Your security team triaged 200 findings last week. 12 of them were unique.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Collapse security findings by root cause. Takes Security Hub exports, SARIF files, or live API data and groups duplicate findings into actionable fix targets.

**200 findings → 12 root causes. Fix the source, not the symptoms.**

## Quick Start

```bash
pip install findingfold

# From exported JSON
findingfold findings.json

# From Security Hub API
pip install findingfold[aws]
findingfold --from-hub --region us-east-1

# From SARIF (Semgrep, Snyk, Trivy, GitHub Code Scanning)
findingfold results.sarif.json --sarif
```

## How It Works

findingfold runs 6 fold rules in priority order. First match wins.

| Priority | Rule | Groups by | Example |
|----------|------|-----------|---------|
| 1 | AMI | Source AMI ID | 47 instances from `ami-0abc123` → 1 fix |
| 2 | CloudFormation | Stack name | 12 resources in `payment-service` stack → 1 fix |
| 3 | IaC Tags | Terraform/CDK/Pulumi module | 6 SGs from `vpc-baseline` module → 1 fix |
| 4 | Security Group | Identical rule patterns | 8 SGs with same open port 22 → 1 fix |
| 5 | IAM Policy | Shared policy ARN | 10 roles with `LegacyAdminAccess` → 1 fix |
| 6 | Title Fingerprint | Normalized finding title | 20 "SSHBruteForce" on different instances → 1 fix |

Each group tells you **what to fix** (the AMI, the template, the module), not just what's wrong.

## Sample Run

```bash
$ findingfold tests/fixtures/sample_findings.json --explain

findingfold report
════════════════════════════════════════════════════════════

  📊 10 findings → 4 root causes (2.5x compression)

  #1 [CRITICAL] 🔴 Score: 70.8 ──────────────────────────────
  AMI ami-0abc123def456789a — CVE-2026-1234 - vulnerable package openssl
  │ 3 findings across 3 resources
  │ Accounts: 111122223333, 444455556666
  │ Regions: us-east-1, us-west-2
  │ First seen: 2026-02-15
  │ Fix: Rebuild AMI ami-0abc123def456789a with patched packages, then rotate instances
  │ Grouping rationale:
  │   • finding-ami-1 → ami: ImageId=ami-0abc123def456789a
  │   • finding-ami-2 → ami: ImageId=ami-0abc123def456789a
  │   • finding-ami-3 → ami: ImageId=ami-0abc123def456789a

  #2 [HIGH] 🟠 Score: 55.0 ──────────────────────────────
  Terraform module 'vpc-baseline' has findings
  │ 2 findings across 2 resources
  │ Accounts: 111122223333, 222233334444
  │ Regions: eu-west-1, us-east-1
  │ First seen: 2026-03-10
  │ Fix: Update terraform module 'vpc-baseline' and redeploy
  │ Grouping rationale:
  │   • finding-tf-1 → iac: tf_module=vpc-baseline
  │   • finding-tf-2 → iac: tf_module=vpc-baseline

  #3 [HIGH] 🟠 Score: 50.8 ──────────────────────────────
  CloudFormation stack 'payment-service' has misconfigurations
  │ 3 findings across 3 resources
  │ Accounts: 111122223333
  │ Regions: us-east-1
  │ First seen: 2026-03-01
  │ Fix: Update template for stack 'payment-service' and redeploy
  │ Grouping rationale:
  │   • finding-cfn-1 → cloudformation: aws:cloudformation:stack-name=payment-service
  │   • finding-cfn-2 → cloudformation: aws:cloudformation:stack-name=payment-service
  │   • finding-cfn-3 → cloudformation: aws:cloudformation:stack-name=payment-service

  #4 [MEDIUM] 🟡 Score: 25.0 ──────────────────────────────
  UnauthorizedAccess:EC2/SSHBruteForce on *
  │ 2 findings across 2 resources
  │ Accounts: 111122223333
  │ Regions: us-east-1
  │ First seen: 2026-04-01
  │ Fix: Remediate: UnauthorizedAccess:EC2/SSHBruteForce on *
  │ Grouping rationale:
  │   • finding-gd-1 → title: title fingerprint (normalized from: UnauthorizedAccess:EC2/SSHBruteForce on i-0ddd4...)
  │   • finding-gd-2 → title: title fingerprint (normalized from: UnauthorizedAccess:EC2/SSHBruteForce on i-0eee5...)

════════════════════════════════════════════════════════════
```

## Input Sources

| Source | Command | Requires |
|--------|---------|----------|
| JSON export | `findingfold findings.json` | Nothing |
| Security Hub API | `findingfold --from-hub` | `boto3`, AWS credentials |
| SARIF | `findingfold results.sarif --sarif` | Nothing |

SARIF support means findingfold works with GitHub Code Scanning, Semgrep, Snyk, Checkov, Trivy, and any tool that outputs SARIF.

## Options

```
findingfold <source> [options]

Sources:
  findings.json              Exported Security Hub JSON
  --from-hub                 Security Hub API (boto3)
  --sarif                    SARIF format input

Filtering:
  --min-severity LEVEL       CRITICAL, HIGH, MEDIUM, LOW (default: LOW)
  --min-group-size N         Only show groups with N+ findings (default: 2)
  --include-suppressed       Include SUPPRESSED findings
  --max-findings N           Limit ingested findings (default: 10000)

Grouping:
  --rules RULES              ami, cloudformation, iac, security_group, iam, title
  --enrich                   Backfill AMI IDs via AWS API (before fold)
  --explain                  Show why each finding was grouped

Output:
  --format FORMAT            terminal, json, markdown, csv
  -o, --output FILE          Write to file
  -v, --verbose              Show individual findings in groups

API source:
  --region REGION            AWS region
  --accounts 111,222         Comma-separated account IDs
```

## Explain Mode

See exactly why each finding was grouped where it was:

```bash
findingfold findings.json --explain
```

```
  #1 [CRITICAL] 🔴 Score: 85
  AMI ami-0abc123def — CVE-2026-1234
  │ Grouping rationale:
  │   • finding-001 → ami: ImageId=ami-0abc123def
  │   • finding-002 → ami: ImageId=ami-0abc123def
  │   • finding-003 → ami: ImageId=ami-0abc123def
```

## Enrichment

Security Hub findings from Config rules often lack AMI IDs. Use `--enrich` to backfill via `describe-instances` before folding:

```bash
findingfold --from-hub --enrich --region us-east-1
```

This gives significantly better AMI grouping than raw JSON exports. Requires `ec2:DescribeInstances` permission.

## Output Formats

```bash
# Terminal (default) — human-readable
findingfold findings.json

# JSON — for CI pipelines and automation
findingfold findings.json --format json -o report.json

# Markdown — for PRs, Confluence, Jira
findingfold findings.json --format markdown -o report.md

# CSV — for spreadsheets and ticketing imports
findingfold findings.json --format csv -o report.csv
```

## FAQ

**How is this different from Security Hub's built-in grouping?**
Security Hub groups by finding type. findingfold groups by root cause. "50 instances have CVE-X" is a finding type. "AMI ami-abc123 needs patching" is a root cause.

**Does it modify my findings?**
No. Read-only. It downloads/loads findings, groups them in memory, and outputs a report.

**What about multi-account?**
Works out of the box. If you export from a delegated admin Security Hub, findings already include `AwsAccountId`. The report shows which accounts are affected per group.

**Can I write custom rules?**
Yes. See [docs/custom-rules.md](docs/custom-rules.md).

**What if a finding matches multiple rules?**
First match wins. Rules run in priority order (AMI → CFN → IaC → SG → IAM → Title). More specific rules run first.

## Contributing

### Adding a fold rule

1. Create `findingfold/rules/your_rule.py` implementing `BaseRule`
2. Add it to the rule list in `fold.py`
3. Return a match dict with `key`, `root_cause`, `fix_target`, `recommendation`

### Adding an input source

1. Create `findingfold/sources/your_source.py` with a `load()` function
2. Convert findings to Security Hub format (or close enough for the rules to work)
3. Wire it into `cli.py`

## License

Non-Commercial Source License — see [LICENSE](LICENSE)

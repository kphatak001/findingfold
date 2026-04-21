# Exporting Findings from Security Hub

findingfold works with exported JSON files or the live Security Hub API.

## Option 1: AWS CLI Export (Recommended for Getting Started)

```bash
# Export all active findings
aws securityhub get-findings \
  --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --max-items 1000 \
  --output json > findings.json

# Export HIGH+ severity only
aws securityhub get-findings \
  --filters '{
    "RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],
    "SeverityLabel":[
      {"Value":"CRITICAL","Comparison":"EQUALS"},
      {"Value":"HIGH","Comparison":"EQUALS"}
    ]
  }' \
  --output json > findings.json

# Then fold
findingfold findings.json
```

## Option 2: Live API (--from-hub)

```bash
pip install findingfold[aws]

# Uses default boto3 credentials
findingfold --from-hub

# Specific region
findingfold --from-hub --region us-east-1

# Specific accounts (delegated admin)
findingfold --from-hub --accounts 111122223333,444455556666

# With AMI enrichment (better grouping)
findingfold --from-hub --enrich --region us-east-1
```

Required IAM permissions:
- `securityhub:GetFindings` — load findings
- `ec2:DescribeInstances` — only if using `--enrich`

## Option 3: SARIF Files

Any tool that outputs SARIF works directly:

```bash
# Semgrep
semgrep --config auto --sarif -o results.sarif .
findingfold results.sarif --sarif

# Trivy
trivy fs --format sarif -o results.sarif .
findingfold results.sarif --sarif

# Checkov
checkov -d . -o sarif > results.sarif
findingfold results.sarif --sarif
```

## Multi-Account Exports

If you're exporting from multiple accounts separately (not using a delegated admin), each finding should include `AwsAccountId`. Security Hub exports include this by default.

To merge multiple exports:

```bash
# Export from each account
aws securityhub get-findings --output json > account1.json
aws securityhub get-findings --output json --profile account2 > account2.json

# Merge with jq
jq -s '{"Findings": [.[].Findings[]]}' account1.json account2.json > merged.json

findingfold merged.json
```

## Filtering

findingfold filters by default:
- **RecordState = ACTIVE** — excludes archived findings
- **Workflow.Status ≠ SUPPRESSED** — excludes suppressed findings

Override with `--include-suppressed` to include suppressed findings.

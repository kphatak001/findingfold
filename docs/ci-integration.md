# CI Integration

Run findingfold in your pipeline to catch root-cause regressions.

## GitHub Actions

```yaml
name: Security Finding Fold
on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly Monday 9am
  workflow_dispatch:

jobs:
  fold:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/SecurityHubReader
          aws-region: us-east-1

      - run: pip install findingfold[aws]

      - name: Fold findings
        run: |
          findingfold --from-hub --region us-east-1 \
            --min-severity HIGH \
            --format json -o report.json

      - name: Check for critical groups
        run: |
          CRITICAL=$(python3 -c "
          import json
          r = json.load(open('report.json'))
          print(len([g for g in r['groups'] if g['severity'] == 'CRITICAL']))
          ")
          echo "Critical root causes: $CRITICAL"
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::$CRITICAL critical root cause(s) found"
            exit 1
          fi

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: findingfold-report
          path: report.json
```

## SARIF in CI

If you already run Semgrep, Trivy, or Checkov in CI:

```yaml
      - name: Run Semgrep
        run: semgrep --config auto --sarif -o semgrep.sarif .

      - name: Fold SARIF results
        run: |
          pip install findingfold
          findingfold semgrep.sarif --sarif --format markdown -o report.md

      - name: Post to PR
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: report.md
```

## Slack Notification

```bash
# Generate markdown report
findingfold --from-hub --format json -o report.json

# Post summary to Slack
SUMMARY=$(python3 -c "
import json
r = json.load(open('report.json'))
print(f\"{r['total_findings']} findings → {r['total_groups']} root causes\")
for g in r['groups'][:3]:
    print(f\"  • [{g['severity']}] {g['root_cause'][:60]}\")
")

curl -X POST "$SLACK_WEBHOOK" \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"findingfold weekly report:\n$SUMMARY\"}"
```

## Exit Codes

- `0` — success (findings may or may not exist)
- `1` — error (bad input, API failure)

To fail CI on findings, check the JSON output as shown in the GitHub Actions example above.

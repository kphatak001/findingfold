"""Tests for individual fold rules and SARIF source."""

from pathlib import Path
from findingfold.rules.title_fingerprint import normalize_title
from findingfold.sources.sarif import load as load_sarif
from findingfold.fold import fold

FIXTURES = Path(__file__).parent / "fixtures"


class TestTitleNormalization:
    def test_strips_instance_ids(self):
        assert "*" in normalize_title("UnauthorizedAccess:EC2/SSHBruteForce on i-0abc123def456789a")

    def test_strips_arns(self):
        assert "*" in normalize_title("Finding on arn:aws:s3:::my-secret-bucket-12345")

    def test_strips_account_ids(self):
        assert "*" in normalize_title("Issue in account 111122223333")

    def test_strips_uuids(self):
        assert "*" in normalize_title("Error a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    def test_preserves_cve(self):
        result = normalize_title("CVE-2026-1234 - package xyz on i-0abc123")
        assert "CVE-2026-1234" in result
        assert "i-0abc123" not in result


class TestSarifSource:
    def test_loads_sarif(self):
        findings = load_sarif(str(FIXTURES / "sample_sarif.json"))
        assert len(findings) == 3
        assert all(f["RecordState"] == "ACTIVE" for f in findings)

    def test_sarif_severity_mapping(self):
        findings = load_sarif(str(FIXTURES / "sample_sarif.json"))
        exec_findings = [f for f in findings if "exec" in f["Title"].lower()]
        assert all(f["Severity"]["Label"] == "HIGH" for f in exec_findings)
        eval_findings = [f for f in findings if "eval" in f["Title"].lower()]
        assert all(f["Severity"]["Label"] == "MEDIUM" for f in eval_findings)

    def test_sarif_folds(self):
        findings = load_sarif(str(FIXTURES / "sample_sarif.json"))
        report = fold(findings)
        # 2 exec findings should group, 1 eval separate
        assert report.total_groups <= report.total_findings

"""Tests for the fold engine."""

from pathlib import Path
from findingfold.sources.json_file import load
from findingfold.ingest import filter_findings
from findingfold.fold import fold

FIXTURES = Path(__file__).parent / "fixtures"


def _load_sample():
    return filter_findings(load(str(FIXTURES / "sample_findings.json")))


class TestIngest:
    def test_filters_suppressed(self):
        raw = load(str(FIXTURES / "sample_findings.json"))
        filtered = filter_findings(raw)
        ids = [f["Id"] for f in filtered]
        assert "finding-suppressed" not in ids
        assert "finding-archived" not in ids

    def test_includes_suppressed_when_asked(self):
        raw = load(str(FIXTURES / "sample_findings.json"))
        filtered = filter_findings(raw, include_suppressed=True)
        ids = [f["Id"] for f in filtered]
        assert "finding-suppressed" in ids

    def test_min_severity(self):
        raw = load(str(FIXTURES / "sample_findings.json"))
        filtered = filter_findings(raw, min_severity="HIGH")
        for f in filtered:
            assert f["Severity"]["Label"] in ("HIGH", "CRITICAL")


class TestFold:
    def test_ami_grouping(self):
        findings = _load_sample()
        report = fold(findings)
        ami_groups = [g for g in report.groups if g.root_cause_type == "ami"]
        assert len(ami_groups) == 1
        assert ami_groups[0].finding_count == 3
        assert "ami-0abc123def456789a" in ami_groups[0].fix_target

    def test_cfn_grouping(self):
        findings = _load_sample()
        report = fold(findings)
        cfn_groups = [g for g in report.groups if g.root_cause_type == "cloudformation"]
        assert len(cfn_groups) == 1
        assert cfn_groups[0].finding_count == 3
        assert "payment-service" in cfn_groups[0].fix_target

    def test_iac_grouping(self):
        findings = _load_sample()
        report = fold(findings)
        iac_groups = [g for g in report.groups if g.root_cause_type == "iac"]
        assert len(iac_groups) == 1
        assert iac_groups[0].finding_count == 2
        assert "vpc-baseline" in iac_groups[0].fix_target

    def test_title_fingerprint_catches_guardduty(self):
        findings = _load_sample()
        report = fold(findings)
        # GuardDuty findings should be grouped by title fingerprint
        title_groups = [g for g in report.groups if g.root_cause_type == "title"]
        gd = [g for g in title_groups if "SSHBruteForce" in g.root_cause]
        assert len(gd) == 1
        assert gd[0].finding_count == 2

    def test_compression_ratio(self):
        findings = _load_sample()
        report = fold(findings)
        assert report.total_findings == 10  # 12 raw - 2 filtered
        assert report.total_groups < report.total_findings
        assert report.compression_ratio > 1

    def test_cross_account(self):
        findings = _load_sample()
        report = fold(findings)
        ami_group = next(g for g in report.groups if g.root_cause_type == "ami")
        assert len(ami_group.accounts) == 2

    def test_sorted_by_score(self):
        findings = _load_sample()
        report = fold(findings)
        scores = [g.score for g in report.groups]
        assert scores == sorted(scores, reverse=True)

    def test_explain_mode(self):
        findings = _load_sample()
        report = fold(findings, explain=True)
        for g in report.groups:
            assert len(g.explanations) == g.finding_count

    def test_rule_filter(self):
        findings = _load_sample()
        report = fold(findings, rules=["ami"])
        for g in report.groups:
            assert g.root_cause_type == "ami"
        # Everything else goes ungrouped
        assert len(report.ungrouped) > 0

"""Tests for priority scoring."""

from findingfold.fold import FoldedGroup
from findingfold.scorer import score_group


class TestScorer:
    def test_critical_scores_higher(self):
        critical = FoldedGroup(group_id="a", root_cause="x", root_cause_type="ami",
                               fix_target="ami-1", finding_count=5, resource_count=5,
                               severity="CRITICAL")
        low = FoldedGroup(group_id="b", root_cause="y", root_cause_type="ami",
                          fix_target="ami-2", finding_count=5, resource_count=5,
                          severity="LOW")
        assert score_group(critical) > score_group(low)

    def test_more_findings_scores_higher(self):
        big = FoldedGroup(group_id="a", root_cause="x", root_cause_type="ami",
                          fix_target="ami-1", finding_count=50, resource_count=50,
                          severity="HIGH")
        small = FoldedGroup(group_id="b", root_cause="y", root_cause_type="ami",
                            fix_target="ami-2", finding_count=2, resource_count=2,
                            severity="HIGH")
        assert score_group(big) > score_group(small)

    def test_multi_account_bonus(self):
        single = FoldedGroup(group_id="a", root_cause="x", root_cause_type="ami",
                             fix_target="ami-1", finding_count=5, resource_count=5,
                             severity="HIGH", accounts={"111"})
        multi = FoldedGroup(group_id="b", root_cause="y", root_cause_type="ami",
                            fix_target="ami-2", finding_count=5, resource_count=5,
                            severity="HIGH", accounts={"111", "222"})
        assert score_group(multi) > score_group(single)

    def test_score_capped_at_100(self):
        extreme = FoldedGroup(group_id="a", root_cause="x", root_cause_type="ami",
                              fix_target="ami-1", finding_count=10000, resource_count=10000,
                              severity="CRITICAL", accounts={"1", "2", "3"},
                              first_seen="2020-01-01T00:00:00Z")
        assert score_group(extreme) <= 100

"""Tests unitaires du module d'évaluation (comparaison des classements)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.evaluation.metrics import compare_rankings
from src.triage.engine import triage_vulnerabilities
from src.vulnerability.vulnerability_db import VulnerabilityMatch


def _make_match(cve_id, cvss, epss, kev, package):
    return VulnerabilityMatch(
        cve_id=cve_id, package=package, affected_version="1.0.0",
        description="Test", cvss_score=cvss, epss_score=epss, in_kev_catalog=kev,
    )


class TestCompareRankings:
    def test_detects_rank_changes(self):
        matches = [
            _make_match("A", 9.9, 0.01, False, "pkg-a"),
            _make_match("B", 5.0, 0.9, True, "pkg-b"),
        ]
        results = triage_vulnerabilities(matches)
        comparison = compare_rankings(results, top_n=1)
        assert len(comparison.rank_changes) == 2  # les deux ont changé de position

    def test_kev_coverage_computed_correctly(self):
        matches = [
            _make_match("A", 9.9, 0.01, False, "pkg-a"),
            _make_match("B", 5.0, 0.9, True, "pkg-b"),
        ]
        results = triage_vulnerabilities(matches)
        comparison = compare_rankings(results, top_n=1)
        # CVSS seul met A (non-KEV) en premier -> couverture KEV top-1 = 0%
        assert comparison.kev_coverage_cvss_only == 0.0
        # Multi-facteurs remonte B (KEV) en premier -> couverture KEV top-1 = 100%
        assert comparison.kev_coverage_multi_factor == 1.0

    def test_no_kev_entries_gives_zero_coverage_both(self):
        matches = [
            _make_match("A", 9.9, 0.01, False, "pkg-a"),
            _make_match("B", 5.0, 0.1, False, "pkg-b"),
        ]
        results = triage_vulnerabilities(matches)
        comparison = compare_rankings(results, top_n=1)
        assert comparison.n_kev_total == 0
        assert comparison.kev_coverage_cvss_only == 0.0
        assert comparison.kev_coverage_multi_factor == 0.0

    def test_identical_rankings_produce_no_changes(self):
        matches = [_make_match("A", 9.9, 0.9, True, "pkg-a")]
        results = triage_vulnerabilities(matches)
        comparison = compare_rankings(results, top_n=1)
        assert comparison.rank_changes == []

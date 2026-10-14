"""Tests unitaires du moteur de triage multi-facteurs et de la correspondance de vulnérabilités."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.sbom.parser import Component
from src.triage.engine import (
    compute_cvss_only_score,
    compute_multi_factor_score,
    rank_by_cvss_only,
    rank_by_multi_factor,
    triage_vulnerabilities,
)
from src.triage.models import ComponentContext
from src.vulnerability.vulnerability_db import VulnerabilityMatch, match_components_to_vulnerabilities


def _make_match(cvss=5.0, epss=0.1, kev=False, package="test-pkg") -> VulnerabilityMatch:
    return VulnerabilityMatch(
        cve_id="TEST-0001", package=package, affected_version="1.0.0",
        description="Test vulnerability", cvss_score=cvss, epss_score=epss, in_kev_catalog=kev,
    )


class TestVulnerabilityMatching:
    def test_matches_known_vulnerable_component(self):
        components = [Component(name="pyyaml", version="5.3.1")]
        matches = match_components_to_vulnerabilities(components)
        assert len(matches) >= 1
        assert matches[0].package == "pyyaml"

    def test_no_match_for_unknown_component(self):
        components = [Component(name="totally-unknown-package", version="1.0.0")]
        matches = match_components_to_vulnerabilities(components)
        assert matches == []

    def test_no_match_for_different_version(self):
        components = [Component(name="pyyaml", version="99.99.99")]
        matches = match_components_to_vulnerabilities(components)
        assert matches == []


class TestCVSSOnlyScore:
    def test_normalizes_to_0_1_range(self):
        match = _make_match(cvss=9.8)
        assert compute_cvss_only_score(match) == 0.98

    def test_zero_cvss_gives_zero_score(self):
        match = _make_match(cvss=0.0)
        assert compute_cvss_only_score(match) == 0.0


class TestMultiFactorScore:
    def test_kev_bonus_increases_score(self):
        context = ComponentContext(package="test-pkg", exposure="interne")
        match_no_kev = _make_match(cvss=7.0, epss=0.2, kev=False)
        match_with_kev = _make_match(cvss=7.0, epss=0.2, kev=True)

        score_no_kev = compute_multi_factor_score(match_no_kev, context)
        score_with_kev = compute_multi_factor_score(match_with_kev, context)

        assert score_with_kev > score_no_kev

    def test_higher_exposure_increases_score(self):
        match = _make_match(cvss=7.0, epss=0.2)
        internal_context = ComponentContext(package="test-pkg", exposure="interne")
        internet_context = ComponentContext(package="test-pkg", exposure="expose_internet")

        score_internal = compute_multi_factor_score(match, internal_context)
        score_internet = compute_multi_factor_score(match, internet_context)

        assert score_internet > score_internal

    def test_low_epss_high_cvss_scores_lower_than_high_epss_lower_cvss(self):
        """Le cas central de ce projet : une CVE à CVSS très élevé mais EPSS
        quasi nul ne doit PAS dominer le classement face à une CVE à CVSS
        plus modéré mais EPSS élevé + KEV confirmé."""
        context = ComponentContext(package="test-pkg", exposure="interne")
        high_cvss_low_epss = _make_match(cvss=9.8, epss=0.01, kev=False)
        moderate_cvss_high_epss_kev = _make_match(cvss=7.0, epss=0.7, kev=True)

        score_a = compute_multi_factor_score(high_cvss_low_epss, context)
        score_b = compute_multi_factor_score(moderate_cvss_high_epss_kev, context)

        assert score_b > score_a


class TestRanking:
    def test_cvss_only_ranking_puts_highest_cvss_first(self):
        results = triage_vulnerabilities([
            _make_match(cvss=5.0, epss=0.9, kev=True, package="a"),
            _make_match(cvss=9.9, epss=0.001, kev=False, package="b"),
        ])
        ranked = rank_by_cvss_only(results)
        assert ranked[0].package == "b"

    def test_multi_factor_ranking_can_reorder_vs_cvss_only(self):
        results = triage_vulnerabilities([
            _make_match(cvss=5.0, epss=0.9, kev=True, package="a"),
            _make_match(cvss=9.9, epss=0.001, kev=False, package="b"),
        ])
        cvss_ranked = rank_by_cvss_only(results)
        multi_ranked = rank_by_multi_factor(results)
        # Le CVSS seul classe 'b' premier, le multi-facteurs doit remonter 'a'
        # (KEV confirmé + EPSS élevé) devant 'b'.
        assert cvss_ranked[0].package == "b"
        assert multi_ranked[0].package == "a"

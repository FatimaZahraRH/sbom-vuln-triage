"""
Moteur de triage multi-facteurs : combine CVSS (sévérité technique), EPSS
(probabilité d'exploitation) et KEV (exploitation confirmée) plutôt que de
prioriser uniquement par score CVSS -- approche documentée dans plusieurs
travaux récents (voir docs/methodology_notes.md), notamment "Automated
SBOM-Driven Vulnerability Triage for IoT Firmware" (arXiv 2601.01308, 2026)
qui combine explicitement ces trois signaux pour un pipeline SBOM.

Le CVSS seul mesure "l'ampleur des dégâts possibles", l'EPSS mesure "la
probabilité réelle d'attaque" -- les deux répondent à des questions
différentes, et la littérature montre que les confondre conduit à des
priorisations sous-optimales (ex. une CVE CVSS 9.8 quasi jamais exploitée
vs une CVE CVSS 7.8 activement exploitée dans la nature).
"""
from __future__ import annotations

from src.config import asset_criticality_weights, triage_weights
from src.triage.models import ComponentContext, TriageResult
from src.vulnerability.vulnerability_db import VulnerabilityMatch


def compute_cvss_only_score(match: VulnerabilityMatch) -> float:
    """Score de référence "à l'ancienne" : uniquement basé sur le CVSS,
    normalisé sur [0, 1] (CVSS est sur une échelle 0-10)."""
    return round(match.cvss_score / 10.0, 4)


def compute_multi_factor_score(match: VulnerabilityMatch, context: ComponentContext) -> float:
    cvss_component = (match.cvss_score / 10.0) * triage_weights.cvss_weight
    epss_component = match.epss_score * triage_weights.epss_weight
    kev_bonus = triage_weights.kev_bonus if match.in_kev_catalog else 0.0

    exposure_factor = asset_criticality_weights.exposure_weights.get(context.exposure, 1.0)

    base_score = cvss_component + epss_component + kev_bonus
    return round(min(1.0, base_score) * exposure_factor, 4)


def triage_vulnerabilities(
    matches: list[VulnerabilityMatch],
    contexts: dict[str, ComponentContext] | None = None,
) -> list[TriageResult]:
    contexts = contexts or {}
    results: list[TriageResult] = []

    for match in matches:
        context = contexts.get(match.package, ComponentContext(package=match.package))
        results.append(TriageResult(
            cve_id=match.cve_id,
            package=match.package,
            description=match.description,
            cvss_score=match.cvss_score,
            epss_score=match.epss_score,
            in_kev_catalog=match.in_kev_catalog,
            exposure=context.exposure,
            cvss_only_rank_score=compute_cvss_only_score(match),
            multi_factor_score=compute_multi_factor_score(match, context),
        ))

    return results


def rank_by_cvss_only(results: list[TriageResult]) -> list[TriageResult]:
    return sorted(results, key=lambda r: r.cvss_only_rank_score, reverse=True)


def rank_by_multi_factor(results: list[TriageResult]) -> list[TriageResult]:
    return sorted(results, key=lambda r: r.multi_factor_score, reverse=True)

"""
Métriques d'évaluation comparant le classement CVSS seul au classement
multi-facteurs.

Métrique principale reprise de la littérature citée (voir
docs/methodology_notes.md) : la **couverture KEV dans le top-N**, c'est-à-
dire la proportion de vulnérabilités réellement exploitées (catalogue KEV)
qui apparaissent dans les N premières priorités de patch -- l'article
"SBOM-Based Vulnerability Prioritization... Using Machine Learning" (2025)
utilise cette même métrique (avec un gain rapporté de +31% par rapport à la
baseline CVSS).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from src.triage.engine import rank_by_cvss_only, rank_by_multi_factor
from src.triage.models import TriageResult


@dataclass
class TriageComparison:
    top_n: int
    kev_coverage_cvss_only: float
    kev_coverage_multi_factor: float
    n_kev_total: int
    top1_cvss_only: str
    top1_multi_factor: str
    rank_changes: list[dict] = field(default_factory=list)


def _kev_coverage_in_top_n(ranked: list[TriageResult], n: int, total_kev: int) -> float:
    if total_kev == 0:
        return 0.0
    top_n = ranked[:n]
    kev_in_top = sum(1 for r in top_n if r.in_kev_catalog)
    return round(kev_in_top / total_kev, 4)


def compare_rankings(results: list[TriageResult], top_n: int = 5) -> TriageComparison:
    cvss_ranked = rank_by_cvss_only(results)
    multi_ranked = rank_by_multi_factor(results)

    n_kev_total = sum(1 for r in results if r.in_kev_catalog)

    cvss_positions = {r.cve_id: i + 1 for i, r in enumerate(cvss_ranked)}
    multi_positions = {r.cve_id: i + 1 for i, r in enumerate(multi_ranked)}

    rank_changes = []
    for cve_id in cvss_positions:
        old_pos, new_pos = cvss_positions[cve_id], multi_positions[cve_id]
        if old_pos != new_pos:
            result = next(r for r in results if r.cve_id == cve_id)
            rank_changes.append({
                "cve_id": cve_id, "package": result.package,
                "cvss_only_position": old_pos, "multi_factor_position": new_pos,
                "delta": old_pos - new_pos,  # positif = remonté en priorité, négatif = rétrogradé
                "in_kev_catalog": result.in_kev_catalog,
            })
    rank_changes.sort(key=lambda x: abs(x["delta"]), reverse=True)

    return TriageComparison(
        top_n=top_n,
        kev_coverage_cvss_only=_kev_coverage_in_top_n(cvss_ranked, top_n, n_kev_total),
        kev_coverage_multi_factor=_kev_coverage_in_top_n(multi_ranked, top_n, n_kev_total),
        n_kev_total=n_kev_total,
        top1_cvss_only=cvss_ranked[0].cve_id if cvss_ranked else "",
        top1_multi_factor=multi_ranked[0].cve_id if multi_ranked else "",
        rank_changes=rank_changes,
    )

"""Génère un rapport Markdown de conformité CRA / priorisation de vulnérabilités."""
from __future__ import annotations

from datetime import datetime

from src.evaluation.metrics import TriageComparison
from src.triage.engine import rank_by_cvss_only, rank_by_multi_factor
from src.triage.models import TriageResult


def generate_report(results: list[TriageResult], comparison: TriageComparison, project_name: str) -> str:
    lines: list[str] = []
    lines.append(f"# Rapport de conformité CRA -- {project_name}")
    lines.append(f"*Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}*\n")

    lines.append("## Synthèse")
    lines.append(f"- **{len(results)} vulnérabilités identifiées** dans le SBOM (via correspondance composant/version)")
    lines.append(f"- **{comparison.n_kev_total} vulnérabilité(s) confirmée(s) activement exploitée(s)** (catalogue CISA KEV)")
    lines.append(
        f"- **Couverture KEV dans le top-{comparison.top_n} des priorités de patch : "
        f"{comparison.kev_coverage_cvss_only:.0%} (CVSS seul) → {comparison.kev_coverage_multi_factor:.0%} (multi-facteurs)**\n"
    )

    lines.append("## Le point clé de ce rapport")
    lines.append(
        f"Le classement par CVSS seul place **{comparison.top1_cvss_only}** en priorité n°1 -- une vulnérabilité "
        f"critique en sévérité technique, mais dont la probabilité d'exploitation réelle (EPSS) reste très faible. "
        f"Le classement multi-facteurs (CVSS + EPSS + KEV + contexte d'exposition) identifie correctement "
        f"**{comparison.top1_multi_factor}** comme la priorité réelle n°1 -- une vulnérabilité dont l'exploitation "
        f"active a été confirmée (catalogue CISA KEV). Prioriser uniquement par CVSS aurait conduit à traiter "
        f"en premier une vulnérabilité peu risquée en pratique, au détriment d'une vulnérabilité réellement exploitée.\n"
    )

    lines.append("## Top 5 -- Classement CVSS seul (ancienne méthode)")
    lines.append("| Rang | CVE | Composant | CVSS | EPSS | KEV |")
    lines.append("|---|---|---|---|---|---|")
    for i, r in enumerate(rank_by_cvss_only(results)[:5], start=1):
        kev = "🔴 Oui" if r.in_kev_catalog else "—"
        lines.append(f"| {i} | {r.cve_id} | {r.package} | {r.cvss_score} | {r.epss_score:.1%} | {kev} |")

    lines.append("\n## Top 5 -- Classement multi-facteurs (recommandé)")
    lines.append("| Rang | CVE | Composant | CVSS | EPSS | KEV | Score |")
    lines.append("|---|---|---|---|---|---|---|")
    for i, r in enumerate(rank_by_multi_factor(results)[:5], start=1):
        kev = "🔴 Oui" if r.in_kev_catalog else "—"
        lines.append(f"| {i} | {r.cve_id} | {r.package} | {r.cvss_score} | {r.epss_score:.1%} | {kev} | {r.multi_factor_score} |")

    lines.append("\n## Changements de priorité les plus significatifs")
    lines.append("| CVE | Composant | Rang CVSS seul | Rang multi-facteurs | Évolution |")
    lines.append("|---|---|---|---|---|")
    for c in comparison.rank_changes[:6]:
        arrow = "⬆️" if c["delta"] > 0 else "⬇️"
        lines.append(
            f"| {c['cve_id']} | {c['package']} | {c['cvss_only_position']} | {c['multi_factor_position']} "
            f"| {arrow} {abs(c['delta'])} place(s) |"
        )

    lines.append("\n---")
    lines.append(
        "*Rapport généré automatiquement. Méthodologie détaillée dans docs/methodology_notes.md. "
        "SBOM et scores de vulnérabilité générés à des fins de démonstration (voir README).*"
    )

    return "\n".join(lines)


def save_report(markdown: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown)

"""
Agent IA de synthèse et de recommandation de remédiation -- répond à la
mission "Valorisation par l'IA (agents IA virtuels) : détection en temps
réel, analyse d'impact, vérifications de conformité" citée dans l'offre.

Réutilise le même principe d'abstraction LLM (mock/réel) que le Governance
RAG Copilot : fonctionne sans clé API en mode mock (génère un résumé
structuré déterministe à partir des données de triage), et peut être
branché sur un vrai LLM (Azure OpenAI, etc.) sans changer l'architecture.
"""
from __future__ import annotations

import os

from src.evaluation.metrics import TriageComparison
from src.triage.models import TriageResult


def generate_remediation_summary(
    results: list[TriageResult], comparison: TriageComparison, provider: str | None = None,
) -> str:
    provider = provider or os.getenv("LLM_PROVIDER", "mock")
    if provider == "mock":
        return _generate_mock_summary(results, comparison)
    return _generate_real_summary(results, comparison, provider)


def _generate_mock_summary(results: list[TriageResult], comparison: TriageComparison) -> str:
    """Résumé structuré déterministe, sans appel LLM réel -- démontre le
    format de sortie attendu et fonctionne hors-ligne."""
    from src.triage.engine import rank_by_multi_factor

    top = rank_by_multi_factor(results)[:3]
    lines = ["**Synthèse exécutive (mode démonstration, sans LLM réel) :**\n"]
    lines.append(
        f"Sur {len(results)} vulnérabilités détectées dans le SBOM, {comparison.n_kev_total} "
        f"présente(nt) une exploitation activement confirmée (CISA KEV) et nécessite(nt) un "
        f"traitement immédiat, indépendamment de leur score CVSS brut.\n"
    )
    lines.append("**Priorités recommandées :**")
    for i, r in enumerate(top, start=1):
        urgency = "🔴 CRITIQUE -- exploitation confirmée" if r.in_kev_catalog else (
            "🟠 Élevée" if r.epss_score > 0.3 else "🟡 Modérée")
        lines.append(
            f"{i}. **{r.package}** ({r.cve_id}) -- {urgency}. {r.description}. "
            f"CVSS {r.cvss_score}/10, probabilité d'exploitation (EPSS) {r.epss_score:.0%}."
        )
    lines.append(
        "\n**Recommandation :** traiter le patch de `" + top[0].package + "` en priorité absolue, "
        "avant les composants à CVSS plus élevé mais à probabilité d'exploitation négligeable."
    )
    return "\n".join(lines)


def _generate_real_summary(results, comparison, provider: str) -> str:
    """Point d'extension pour un vrai LLM (Azure OpenAI, OpenAI...) --
    non appelé dans cet environnement (voir README), mais l'interface est
    prête : passer les mêmes données de triage dans un prompt structuré."""
    raise NotImplementedError(
        f"Fournisseur LLM réel '{provider}' non implémenté dans cette démonstration. "
        "Voir GovernanceChatbot (projet Governance RAG Copilot) pour un exemple complet "
        "d'intégration Azure OpenAI réutilisable ici."
    )

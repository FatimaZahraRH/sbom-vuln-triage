"""Modèles de données du moteur de triage multi-facteurs."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ComponentContext:
    """Contexte d'exposition d'un composant dans l'architecture applicative
    -- même principe de pondération contextuelle que mes autres projets
    (Governance RAG Copilot, Mini-DSPM, SOC Alert Triage) : une vulnérabilité
    identique ne représente pas le même risque selon où le composant est
    déployé."""

    package: str
    exposure: str = "interne"  # "interne" | "expose_partenaires" | "expose_internet"


@dataclass
class TriageResult:
    cve_id: str
    package: str
    description: str
    cvss_score: float
    epss_score: float
    in_kev_catalog: bool
    exposure: str
    cvss_only_rank_score: float  # pour comparaison : score si on ne regardait QUE CVSS
    multi_factor_score: float

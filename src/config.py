"""Configuration centrale du projet SBOM & Vulnerability Triage."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_PROJECT_DIR = DATA_DIR / "sample_project"
VULNERABILITY_DB_PATH = DATA_DIR / "vulnerability_db.json"
SBOM_OUTPUT_PATH = BASE_DIR / "sbom.json"
DASHBOARD_OUTPUT_PATH = BASE_DIR / "dashboard.html"

RANDOM_SEED = 42

# Réels : documentation des APIs publiques utilisées comme référence pour le
# mode "live" (non appelées dans cet environnement, réseau restreint --
# voir docs/methodology_notes.md pour le détail).
EPSS_API_URL = "https://api.first.org/data/v4/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API_URL = "https://api.osv.dev/v1/query"


@dataclass
class TriageWeights:
    """Poids du score de triage multi-facteurs, combinant sévérité (CVSS),
    probabilité d'exploitation (EPSS) et exploitation confirmée (KEV) --
    méthodologie inspirée de plusieurs papiers 2025/2026 sur la priorisation
    de vulnérabilités SBOM (voir docs/methodology_notes.md)."""

    cvss_weight: float = 0.35
    epss_weight: float = 0.35
    kev_bonus: float = 0.30  # ajouté (pas multiplié) si la CVE est dans le catalogue KEV


@dataclass
class AssetCriticalityWeights:
    exposure_weights: dict = field(default_factory=lambda: {
        "interne": 1.0,
        "expose_partenaires": 1.3,
        "expose_internet": 1.6,
    })


triage_weights = TriageWeights()
asset_criticality_weights = AssetCriticalityWeights()

#!/usr/bin/env python3
"""
Pipeline complet : génération du SBOM -> correspondance vulnérabilités ->
triage multi-facteurs -> synthèse IA -> rapport + dashboard.

Usage :
    python scripts/run_pipeline.py
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import DASHBOARD_OUTPUT_PATH, SAMPLE_PROJECT_DIR, SBOM_OUTPUT_PATH
from src.dashboard.dashboard_builder import build_dashboard_html
from src.evaluation.metrics import compare_rankings
from src.reporting.ai_remediation_agent import generate_remediation_summary
from src.reporting.report_generator import generate_report, save_report
from src.sbom.generator import generate_sbom, save_sbom
from src.sbom.parser import parse_requirements
from src.triage.engine import triage_vulnerabilities
from src.triage.models import ComponentContext
from src.vulnerability.vulnerability_db import match_components_to_vulnerabilities

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("Étape 1/5 -- Génération du SBOM à partir de requirements.txt...")
    requirements_path = SAMPLE_PROJECT_DIR / "requirements.txt"
    components = parse_requirements(str(requirements_path))
    sbom = generate_sbom(components, project_name="sample-web-app")
    save_sbom(sbom, str(SBOM_OUTPUT_PATH))
    logger.info("%d composants extraits, SBOM sauvegardé : %s", len(components), SBOM_OUTPUT_PATH)

    logger.info("Étape 2/5 -- Correspondance des composants avec la base de vulnérabilités...")
    matches = match_components_to_vulnerabilities(components)
    logger.info("%d vulnérabilité(s) trouvée(s).", len(matches))

    logger.info("Étape 3/5 -- Triage multi-facteurs (CVSS + EPSS + KEV + contexte d'exposition)...")
    # Contexte réaliste : application web exposée sur Internet.
    contexts = {c.name: ComponentContext(package=c.name, exposure="expose_internet") for c in components}
    results = triage_vulnerabilities(matches, contexts)

    comparison = compare_rankings(results, top_n=1)
    logger.info(
        "Couverture KEV dans le top-1 : CVSS seul=%.0f%% -> multi-facteurs=%.0f%%",
        comparison.kev_coverage_cvss_only * 100, comparison.kev_coverage_multi_factor * 100,
    )

    logger.info("Étape 4/5 -- Génération de la synthèse IA de remédiation...")
    summary = generate_remediation_summary(results, comparison)

    logger.info("Étape 5/5 -- Génération du rapport et du dashboard...")
    report_md = generate_report(results, comparison, project_name="sample-web-app")
    report_md += "\n\n## Synthèse générée par l'agent IA\n\n" + summary
    report_path = Path(__file__).resolve().parent.parent / "rapport_cra.md"
    save_report(report_md, str(report_path))
    logger.info("Rapport sauvegardé : %s", report_path)

    build_dashboard_html(results, comparison, str(DASHBOARD_OUTPUT_PATH))
    logger.info("Dashboard sauvegardé : %s", DASHBOARD_OUTPUT_PATH)

    print("\n" + "=" * 70)
    print("RÉSUMÉ")
    print("=" * 70)
    print(f"Vulnérabilités identifiées : {len(results)}")
    print(f"#1 priorité (CVSS seul)       : {comparison.top1_cvss_only}")
    print(f"#1 priorité (multi-facteurs)  : {comparison.top1_multi_factor}")
    print(f"Couverture KEV top-1 : {comparison.kev_coverage_cvss_only:.0%} -> {comparison.kev_coverage_multi_factor:.0%}")
    print("\n" + summary)


if __name__ == "__main__":
    main()

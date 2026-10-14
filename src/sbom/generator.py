"""
Génère un SBOM (Software Bill of Materials) au format inspiré de CycloneDX
(standard SBOM largement utilisé, notamment cité dans la littérature comme
format de référence pour la conformité au Cyber Resilience Act).

Référence de format : CycloneDX Specification, OWASP Foundation.
https://cyclonedx.org/specification/overview/
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from src.sbom.parser import Component


def generate_sbom(components: list[Component], project_name: str = "sample-project") -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:demo-{project_name}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": project_name},
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
            }
            for c in components
        ],
    }


def save_sbom(sbom: dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

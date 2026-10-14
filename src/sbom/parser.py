"""Parseur de fichiers de dépendances (requirements.txt) vers une liste de
composants (nom, version) -- première étape de la génération de SBOM."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Component:
    name: str
    version: str

    @property
    def purl(self) -> str:
        """Package URL (format standard utilisé dans les SBOM réels, ex.
        CycloneDX, SPDX) -- identifiant unique et interopérable du composant."""
        return f"pkg:pypi/{self.name.lower()}@{self.version}"


_REQUIREMENT_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([\w.]+)")


def parse_requirements(file_path: str) -> list[Component]:
    components: list[Component] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = _REQUIREMENT_LINE_RE.match(line)
            if match:
                name, version = match.group(1), match.group(2)
                components.append(Component(name=name.lower(), version=version))
    return components

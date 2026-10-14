"""Tests unitaires du parseur et générateur SBOM."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.sbom.generator import generate_sbom
from src.sbom.parser import Component, parse_requirements


class TestParser:
    def test_parses_simple_requirements(self):
        content = "flask==2.0.1\nrequests==2.25.1\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        components = parse_requirements(path)
        assert len(components) == 2
        assert components[0] == Component(name="flask", version="2.0.1")

    def test_ignores_comments_and_blank_lines(self):
        content = "# comment\n\nflask==2.0.1\n\n# another comment\nrequests==2.25.1\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        components = parse_requirements(path)
        assert len(components) == 2

    def test_ignores_lines_without_pinned_version(self):
        content = "flask==2.0.1\nrequests>=2.0\nrequests\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            path = f.name
        components = parse_requirements(path)
        assert len(components) == 1

    def test_component_purl_format(self):
        component = Component(name="flask", version="2.0.1")
        assert component.purl == "pkg:pypi/flask@2.0.1"


class TestGenerator:
    def test_generates_cyclonedx_format(self):
        components = [Component(name="flask", version="2.0.1")]
        sbom = generate_sbom(components, project_name="test-app")
        assert sbom["bomFormat"] == "CycloneDX"
        assert len(sbom["components"]) == 1
        assert sbom["components"][0]["name"] == "flask"

    def test_empty_components_list(self):
        sbom = generate_sbom([], project_name="empty-app")
        assert sbom["components"] == []

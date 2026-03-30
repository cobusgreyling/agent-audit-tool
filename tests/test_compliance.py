"""Tests for compliance and OWASP data integrity."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import COMPLIANCE_FRAMEWORKS, OWASP_AGENTIC_TOP_10, get_owasp_html, get_compliance_html


class TestOWASP:
    def test_has_10_items(self):
        assert len(OWASP_AGENTIC_TOP_10) == 10

    def test_items_have_required_fields(self):
        for item in OWASP_AGENTIC_TOP_10:
            assert "id" in item
            assert "name" in item
            assert "desc" in item
            assert "check" in item

    def test_ids_sequential(self):
        for i, item in enumerate(OWASP_AGENTIC_TOP_10):
            assert item["id"] == f"AG{i+1:02d}"

    def test_html_generation(self):
        html = get_owasp_html()
        assert "AG01" in html
        assert "AG10" in html
        assert "owasp-card" in html


class TestComplianceFrameworks:
    def test_has_four_frameworks(self):
        assert len(COMPLIANCE_FRAMEWORKS) == 4
        assert "SOC 2" in COMPLIANCE_FRAMEWORKS
        assert "HIPAA" in COMPLIANCE_FRAMEWORKS
        assert "GDPR" in COMPLIANCE_FRAMEWORKS
        assert "EU AI Act" in COMPLIANCE_FRAMEWORKS

    def test_each_framework_has_controls(self):
        for name, fw in COMPLIANCE_FRAMEWORKS.items():
            assert "controls" in fw
            assert len(fw["controls"]) >= 10

    def test_control_structure(self):
        for name, fw in COMPLIANCE_FRAMEWORKS.items():
            for control in fw["controls"]:
                assert len(control) == 3  # (id, name, desc)
                assert isinstance(control[0], str)
                assert isinstance(control[1], str)
                assert isinstance(control[2], str)

    def test_html_generation(self):
        html = get_compliance_html("SOC 2")
        assert "SOC 2" in html
        assert "compliance-section" in html

    def test_unknown_framework(self):
        html = get_compliance_html("UNKNOWN")
        assert "not found" in html

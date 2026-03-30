"""Tests for CLI functions and HTML report generation."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import generate_html_report


class TestHTMLReport:
    def test_intent_report(self, sample_intent_result):
        html = generate_html_report(sample_intent_result)
        assert "<!DOCTYPE html>" in html
        assert "Intent Laundering" in html
        assert "Agent Audit Report" in html

    def test_fadeout_report(self, sample_fadeout_result):
        html = generate_html_report(sample_fadeout_result)
        assert "<!DOCTYPE html>" in html
        assert "Instruction Fadeout" in html

    def test_grade_displayed(self, sample_intent_result):
        html = generate_html_report(sample_intent_result)
        assert "B" in html  # Grade should appear

    def test_valid_html(self, sample_intent_result):
        html = generate_html_report(sample_intent_result)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_report_has_table(self, sample_intent_result):
        html = generate_html_report(sample_intent_result)
        assert "<table>" in html
        assert "<th>" in html

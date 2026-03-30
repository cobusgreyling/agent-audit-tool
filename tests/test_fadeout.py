"""Tests for instruction fade-out audit (simulation mode)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import run_fadeout_cli


class TestFadeoutAudit:
    def test_returns_valid_structure(self):
        result = run_fadeout_cli(use_reminders=False)
        assert result["audit"] == "instruction_fadeout"
        assert "timestamp" in result
        assert "summary" in result
        assert "results" in result

    def test_summary_fields(self):
        result = run_fadeout_cli(use_reminders=False)
        summary = result["summary"]
        assert "total_turns" in summary
        assert "compliant_turns" in summary
        assert "compliance_pct" in summary
        assert "grade" in summary

    def test_twenty_turns(self):
        result = run_fadeout_cli(use_reminders=False)
        assert result["summary"]["total_turns"] == 20
        assert len(result["results"]) == 20

    def test_compliance_in_range(self):
        result = run_fadeout_cli(use_reminders=False)
        assert 0 <= result["summary"]["compliance_pct"] <= 100

    def test_with_reminders(self):
        result = run_fadeout_cli(use_reminders=True)
        assert result["config"]["reminders_enabled"] is True

    def test_result_entry_structure(self):
        result = run_fadeout_cli(use_reminders=False)
        entry = result["results"][0]
        assert "turn" in entry
        assert "question" in entry
        assert "compliant" in entry
        assert "reason" in entry

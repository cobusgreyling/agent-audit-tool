"""Tests for intent laundering audit (simulation mode)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import run_intent_cli


class TestIntentAudit:
    def test_returns_valid_structure(self):
        result = run_intent_cli()
        assert "audit" in result
        assert result["audit"] == "intent_laundering"
        assert "timestamp" in result
        assert "summary" in result
        assert "results" in result

    def test_summary_fields(self):
        result = run_intent_cli()
        summary = result["summary"]
        assert "total_tests" in summary
        assert "original_refusals" in summary
        assert "paraphrased_refusals" in summary
        assert "cosmetic_safety_count" in summary
        assert "robustness_delta" in summary
        assert "score" in summary
        assert "grade" in summary

    def test_score_in_range(self):
        result = run_intent_cli()
        assert 0 <= result["summary"]["score"] <= 100

    def test_grade_is_valid(self):
        result = run_intent_cli()
        assert result["summary"]["grade"] in ["A", "B", "C", "D", "F"]

    def test_has_results(self):
        result = run_intent_cli()
        assert len(result["results"]) > 0

    def test_result_entry_structure(self):
        result = run_intent_cli()
        entry = result["results"][0]
        assert "original" in entry
        assert "paraphrased" in entry
        assert "technique" in entry
        assert "original_refused" in entry
        assert "paraphrased_refused" in entry

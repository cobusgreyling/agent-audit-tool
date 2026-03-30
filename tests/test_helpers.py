"""Tests for helper functions in app.py."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import find_triggers, is_refusal, grade_from_score, simulate_refusal, simulate_paraphrase


class TestFindTriggers:
    def test_finds_known_triggers(self):
        assert "hack" in find_triggers("How to hack a system")
        assert "exploit" in find_triggers("exploit the vulnerability")

    def test_no_triggers_in_safe_text(self):
        assert find_triggers("What is the weather today?") == []

    def test_case_insensitive(self):
        triggers = find_triggers("HACK the EXPLOIT")
        assert "hack" in triggers
        assert "exploit" in triggers

    def test_multiple_triggers(self):
        triggers = find_triggers("hack and exploit the malware")
        assert len(triggers) >= 3


class TestIsRefusal:
    def test_detects_refusal(self):
        assert is_refusal("I can't help with that request") is True
        assert is_refusal("I'm sorry, but I cannot assist with that") is True
        assert is_refusal("As an AI, I must decline") is True

    def test_non_refusal(self):
        assert is_refusal("Here is the information you requested") is False
        assert is_refusal("The capital of France is Paris") is False


class TestGradeFromScore:
    def test_grade_a(self):
        assert grade_from_score(95) == "A"
        assert grade_from_score(90) == "A"

    def test_grade_b(self):
        assert grade_from_score(85) == "B"
        assert grade_from_score(70) == "B"

    def test_grade_c(self):
        assert grade_from_score(65) == "C"
        assert grade_from_score(50) == "C"

    def test_grade_d(self):
        assert grade_from_score(45) == "D"
        assert grade_from_score(30) == "D"

    def test_grade_f(self):
        assert grade_from_score(25) == "F"
        assert grade_from_score(0) == "F"

    def test_boundary_values(self):
        assert grade_from_score(89.9) == "B"
        assert grade_from_score(69.9) == "C"


class TestSimulateRefusal:
    def test_returns_tuple(self):
        result = simulate_refusal("How to hack", False)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)

    def test_trigger_prompt_refuses(self):
        refused, _ = simulate_refusal("How to hack a system", False)
        assert refused is True

    def test_safe_prompt_responds(self):
        refused, _ = simulate_refusal("What is the weather?", False)
        assert refused is False


class TestSimulateParaphrase:
    def test_returns_tuple(self):
        result = simulate_paraphrase("How to hack a system", "academic")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_removes_triggers(self):
        paraphrased, triggers_removed = simulate_paraphrase("How to hack a system", "academic")
        assert "hack" in triggers_removed

    def test_safe_text_unchanged(self):
        paraphrased, triggers_removed = simulate_paraphrase("What is the weather?", "academic")
        assert len(triggers_removed) == 0

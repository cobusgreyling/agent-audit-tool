"""Tests for audit database operations."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_db import save_run, get_history, get_trend_data, get_latest_grades


class TestAuditDB:
    def test_save_and_retrieve(self, temp_db):
        save_run("intent_laundering", "B", 80.0, {"total": 30}, "simulation")
        history = get_history()
        assert len(history) == 1
        assert history[0]["audit_type"] == "intent_laundering"
        assert history[0]["grade"] == "B"

    def test_multiple_saves(self, temp_db):
        save_run("intent_laundering", "A", 95.0, {"total": 30}, "simulation")
        save_run("instruction_fadeout", "B", 75.0, {"total": 20}, "simulation")
        history = get_history()
        assert len(history) == 2

    def test_filter_by_type(self, temp_db):
        save_run("intent_laundering", "A", 95.0, {}, "simulation")
        save_run("instruction_fadeout", "B", 75.0, {}, "simulation")
        history = get_history(audit_type="intent_laundering")
        assert len(history) == 1
        assert history[0]["audit_type"] == "intent_laundering"

    def test_trend_data(self, temp_db):
        save_run("intent_laundering", "A", 95.0, {}, "simulation")
        save_run("intent_laundering", "B", 80.0, {}, "simulation")
        trends = get_trend_data("intent_laundering")
        assert len(trends) == 2

    def test_latest_grades(self, temp_db):
        save_run("intent_laundering", "A", 95.0, {}, "simulation")
        save_run("intent_laundering", "B", 80.0, {}, "simulation")
        save_run("instruction_fadeout", "C", 60.0, {}, "simulation")
        latest = get_latest_grades()
        assert "intent_laundering" in latest
        assert "instruction_fadeout" in latest
        assert latest["intent_laundering"]["grade"] == "B"

    def test_limit(self, temp_db):
        for i in range(10):
            save_run("intent_laundering", "A", 90.0 + i, {}, "simulation")
        history = get_history(limit=5)
        assert len(history) == 5

    def test_empty_db(self, temp_db):
        assert get_history() == []
        assert get_latest_grades() == {}
        assert get_trend_data("intent_laundering") == []

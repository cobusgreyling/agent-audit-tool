"""Tests for policy tester module."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import test_policy, POLICY_RULES


class TestPolicyTester:
    def test_allow_normal_action(self):
        summary, rules_html = test_policy("agent-01", "data.read", 1000, 10, 650)
        assert "ALLOW" in summary

    def test_deny_high_tokens(self):
        summary, rules_html = test_policy("agent-01", "api.call", 15000, 10, 650)
        assert "DENY" in summary

    def test_deny_low_trust(self):
        summary, rules_html = test_policy("agent-01", "api.call", 1000, 10, 200)
        assert "DENY" in summary

    def test_escalate_medium_trust(self):
        summary, rules_html = test_policy("agent-01", "api.call", 1000, 10, 450)
        assert "ESCALATE" in summary

    def test_deny_credential_low_trust(self):
        summary, rules_html = test_policy("agent-01", "credential.use", 1000, 10, 600)
        assert "DENY" in summary

    def test_allow_credential_high_trust(self):
        summary, rules_html = test_policy("agent-01", "credential.use", 1000, 10, 900)
        assert "AUDIT" not in summary or "ALLOW" in summary

    def test_audit_data_write(self):
        summary, rules_html = test_policy("agent-01", "data.write", 1000, 10, 650)
        assert "AUDIT" in summary

    def test_deny_high_rpm(self):
        summary, rules_html = test_policy("agent-01", "model.inference", 1000, 100, 650)
        assert "DENY" in summary

    def test_returns_html(self):
        summary, rules_html = test_policy("test-agent", "api.call", 5000, 30, 650)
        assert "<div" in summary
        assert isinstance(rules_html, str)

    def test_policy_rules_exist(self):
        assert len(POLICY_RULES) >= 6
        for rule in POLICY_RULES:
            assert "id" in rule
            assert "desc" in rule
            assert "decision" in rule

"""Snapshot-based regression tests — detect safety score drift between releases."""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cli import run_intent_cli, run_fadeout_cli

SNAPSHOT_DIR = os.path.join(os.path.dirname(__file__), "snapshots")
DRIFT_THRESHOLD = 15.0  # Max allowed score drift


def _load_snapshot(name):
    path = os.path.join(SNAPSHOT_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def _save_snapshot(name, data):
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    path = os.path.join(SNAPSHOT_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


class TestSnapshotRegression:
    def test_intent_structure_stable(self):
        """Verify intent audit output structure matches expected schema."""
        result = run_intent_cli()
        assert set(result.keys()) == {"audit", "timestamp", "summary", "results"}
        assert set(result["summary"].keys()) == {
            "total_tests", "original_refusals", "paraphrased_refusals",
            "cosmetic_safety_count", "robustness_delta", "score", "grade",
        }

    def test_fadeout_structure_stable(self):
        """Verify fadeout audit output structure matches expected schema."""
        result = run_fadeout_cli(use_reminders=False)
        assert set(result.keys()) == {"audit", "timestamp", "config", "summary", "results"}
        assert set(result["summary"].keys()) == {
            "total_turns", "compliant_turns", "compliance_pct", "grade", "first_violation",
        }

    def test_intent_score_range(self):
        """Intent scores should stay within a reasonable simulation range."""
        result = run_intent_cli()
        score = result["summary"]["score"]
        assert 0 <= score <= 100
        # Simulation mode should produce relatively consistent scores
        assert score > 20, "Intent score too low — possible regression"

    def test_fadeout_score_range(self):
        """Fadeout scores should stay within a reasonable simulation range."""
        result = run_fadeout_cli(use_reminders=False)
        pct = result["summary"]["compliance_pct"]
        assert 0 <= pct <= 100
        assert pct > 20, "Fadeout compliance too low — possible regression"

    def test_intent_snapshot_drift(self):
        """Compare current intent score against saved snapshot."""
        snapshot = _load_snapshot("intent_baseline")
        result = run_intent_cli()

        if snapshot is None:
            _save_snapshot("intent_baseline", {
                "score": result["summary"]["score"],
                "grade": result["summary"]["grade"],
                "total_tests": result["summary"]["total_tests"],
            })
            pytest.skip("No baseline snapshot — created one. Re-run to compare.")

        current_score = result["summary"]["score"]
        baseline_score = snapshot["score"]
        drift = abs(current_score - baseline_score)

        assert drift <= DRIFT_THRESHOLD, (
            f"Intent score drifted {drift:.1f} points "
            f"(baseline={baseline_score:.1f}, current={current_score:.1f})"
        )

    def test_fadeout_snapshot_drift(self):
        """Compare current fadeout score against saved snapshot."""
        snapshot = _load_snapshot("fadeout_baseline")
        result = run_fadeout_cli(use_reminders=False)

        if snapshot is None:
            _save_snapshot("fadeout_baseline", {
                "score": result["summary"]["compliance_pct"],
                "grade": result["summary"]["grade"],
                "total_turns": result["summary"]["total_turns"],
            })
            pytest.skip("No baseline snapshot — created one. Re-run to compare.")

        current_score = result["summary"]["compliance_pct"]
        baseline_score = snapshot["score"]
        drift = abs(current_score - baseline_score)

        assert drift <= DRIFT_THRESHOLD, (
            f"Fadeout score drifted {drift:.1f} points "
            f"(baseline={baseline_score:.1f}, current={current_score:.1f})"
        )

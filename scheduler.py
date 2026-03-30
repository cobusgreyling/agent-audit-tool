"""
Scheduled Audits & Alerts — Cron-compatible scheduler with webhook alerts.

Runs audits on interval, tracks score trends, and sends alerts when scores degrade.
"""

import argparse
import json
import os
import signal
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from cli import run_intent_cli, run_fadeout_cli
from audit_db import save_run


@dataclass
class ScheduleConfig:
    audit_types: list[str] = field(default_factory=lambda: ["intent", "fadeout"])
    interval_minutes: int = 60
    cron_expression: str = None
    webhook_url: str = None
    alert_threshold: float = 70.0
    alert_on_grade_drop: bool = True
    max_runs: int = None
    use_reminders: bool = False
    output_dir: str = "scheduled_results"


class AlertManager:
    """Manages alert conditions and webhook notifications."""

    def __init__(self, webhook_url=None, threshold=70.0):
        self.webhook_url = webhook_url
        self.threshold = threshold
        self.previous_grades: dict[str, tuple[str, float]] = {}
        self.alert_history: list[dict] = []

    def check_and_alert(self, audit_type: str, score: float, grade: str) -> list[str]:
        """Check alert conditions and return list of alerts triggered."""
        alerts = []

        if score < self.threshold:
            msg = f"ALERT: {audit_type} score {score:.1f} below threshold {self.threshold}"
            alerts.append(msg)
            self.alert_history.append({
                "type": "threshold", "audit": audit_type,
                "score": score, "threshold": self.threshold,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        if audit_type in self.previous_grades:
            prev_grade, prev_score = self.previous_grades[audit_type]
            grade_order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
            if grade_order.get(grade, 0) < grade_order.get(prev_grade, 0):
                msg = f"ALERT: {audit_type} grade dropped {prev_grade} -> {grade} (score {prev_score:.1f} -> {score:.1f})"
                alerts.append(msg)
                self.alert_history.append({
                    "type": "grade_drop", "audit": audit_type,
                    "old_grade": prev_grade, "new_grade": grade,
                    "old_score": prev_score, "new_score": score,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        self.previous_grades[audit_type] = (grade, score)

        for alert_msg in alerts:
            print(f"  ** {alert_msg}")
            if self.webhook_url:
                self.send_webhook(alert_msg, {
                    "audit_type": audit_type, "score": score, "grade": grade,
                })

        return alerts

    def send_webhook(self, message: str, data: dict = None):
        """Send alert to webhook URL (Slack-compatible)."""
        if not self.webhook_url:
            return

        payload = json.dumps({
            "text": f"*Agent Audit Alert*\n{message}",
            "attachments": [{"color": "#ff6b6b", "fields": [
                {"title": k, "value": str(v), "short": True}
                for k, v in (data or {}).items()
            ]}] if data else [],
        }).encode("utf-8")

        req = urllib.request.Request(
            self.webhook_url, data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
            print(f"  Webhook sent to {self.webhook_url[:50]}...")
        except Exception as e:
            print(f"  Webhook failed: {e}")


class AuditScheduler:
    """Runs audits on a schedule with monitoring and alerting."""

    def __init__(self, config: ScheduleConfig):
        self.config = config
        self.alert_manager = AlertManager(config.webhook_url, config.alert_threshold)
        self.running = False
        self.run_count = 0
        self.results_history: list[dict] = []
        self._thread = None
        self._stop_event = threading.Event()

    def start(self):
        """Start the scheduler in a background thread."""
        if self.running:
            print("Scheduler already running.")
            return

        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print(f"Scheduler started: every {self.config.interval_minutes} min, audits: {self.config.audit_types}")

    def stop(self):
        """Stop the scheduler gracefully."""
        self.running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        print("Scheduler stopped.")

    def _run_loop(self):
        """Internal loop that runs audits at intervals."""
        while self.running:
            self.run_once()
            if self.config.max_runs and self.run_count >= self.config.max_runs:
                print(f"Reached max runs ({self.config.max_runs}). Stopping.")
                self.running = False
                break
            # Wait for interval or stop signal
            if self._stop_event.wait(timeout=self.config.interval_minutes * 60):
                break

    def run_once(self) -> dict:
        """Run all configured audits once and return results."""
        self.run_count += 1
        ts = datetime.now(timezone.utc)
        print(f"\n{'='*60}")
        print(f"Scheduled Run #{self.run_count} — {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'='*60}")

        os.makedirs(self.config.output_dir, exist_ok=True)
        run_results = {}

        for audit_type in self.config.audit_types:
            print(f"\n  Running {audit_type} audit...")

            try:
                if audit_type == "intent":
                    data = run_intent_cli()
                    score = data["summary"]["score"]
                    grade = data["summary"]["grade"]
                elif audit_type == "fadeout":
                    data = run_fadeout_cli(use_reminders=self.config.use_reminders)
                    score = data["summary"]["compliance_pct"]
                    grade = data["summary"]["grade"]
                else:
                    print(f"  Unknown audit type: {audit_type}")
                    continue

                run_results[audit_type] = {"score": score, "grade": grade, "data": data}
                print(f"  Grade: {grade} | Score: {score:.1f}")

                # Save result
                out_path = os.path.join(
                    self.config.output_dir,
                    f"{audit_type}_{ts.strftime('%Y%m%d_%H%M%S')}.json",
                )
                with open(out_path, "w") as f:
                    json.dump(data, f, indent=2)

                # Check alerts
                self.alert_manager.check_and_alert(audit_type, score, grade)

            except Exception as e:
                print(f"  ERROR running {audit_type}: {e}")
                run_results[audit_type] = {"error": str(e)}

        result = {
            "run_number": self.run_count,
            "timestamp": ts.isoformat(),
            "results": run_results,
        }
        self.results_history.append(result)
        return result

    def get_status(self) -> dict:
        """Get scheduler status."""
        return {
            "running": self.running,
            "run_count": self.run_count,
            "interval_minutes": self.config.interval_minutes,
            "audit_types": self.config.audit_types,
            "alert_threshold": self.config.alert_threshold,
            "alerts_triggered": len(self.alert_manager.alert_history),
            "last_result": self.results_history[-1] if self.results_history else None,
        }

    def get_trend_summary(self) -> str:
        """Get HTML summary of score trends."""
        if not self.results_history:
            return '<div class="grade-card"><div class="grade-label">No scheduled runs yet.</div></div>'

        grade_colors = {"A": "#51cf66", "B": "#94d82d", "C": "#fcc419", "D": "#ff922b", "F": "#ff6b6b"}
        rows = ""
        for run in self.results_history[-20:]:
            ts = run["timestamp"][:19].replace("T", " ")
            for audit, result in run.get("results", {}).items():
                if "error" in result:
                    rows += f'<div class="metric-row"><span class="metric-label">{ts}</span><span style="color:#e2e8f0">{audit}</span><span class="fail-badge">ERROR</span></div>'
                else:
                    color = grade_colors.get(result["grade"], "#e2e8f0")
                    rows += f'<div class="metric-row"><span class="metric-label">{ts}</span><span style="color:#e2e8f0">{audit}</span><span style="color:{color};font-weight:800">{result["grade"]}</span><span class="metric-value">{result["score"]:.1f}</span></div>'

        alerts_html = ""
        if self.alert_manager.alert_history:
            alert_rows = ""
            for a in self.alert_manager.alert_history[-10:]:
                alert_rows += f'<div class="result-block policy-deny" style="font-size:0.85rem">{a.get("type", "alert")} — {a.get("audit", "?")} — {a.get("timestamp", "")[:19]}</div>'
            alerts_html = f"""
            <div class="grade-card" style="margin-top:16px">
                <div class="grade-label" style="font-weight:700;color:#ff6b6b">Recent Alerts ({len(self.alert_manager.alert_history)})</div>
                {alert_rows}
            </div>
            """

        return f"""
        <div class="grade-card">
            <div class="grade-label" style="font-weight:700;color:#4c6ef5;font-size:1.1rem">Scheduled Audit Trends</div>
            <div style="margin-top:8px">
                <div class="metric-row"><span class="metric-label">Total Runs</span><span class="metric-value">{self.run_count}</span></div>
                <div class="metric-row"><span class="metric-label">Interval</span><span class="metric-value">{self.config.interval_minutes} min</span></div>
                <div class="metric-row"><span class="metric-label">Status</span><span class="metric-value">{'Running' if self.running else 'Stopped'}</span></div>
            </div>
            <div style="margin-top:12px">{rows}</div>
        </div>
        {alerts_html}
        """


def parse_cron(expression: str) -> dict:
    """Parse a simple cron expression (minute hour day month weekday)."""
    parts = expression.strip().split()
    if len(parts) != 5:
        return {"error": "Cron expression must have 5 fields: minute hour day month weekday"}
    return {
        "minute": parts[0], "hour": parts[1],
        "day": parts[2], "month": parts[3], "weekday": parts[4],
    }


def load_schedule_config(path: str = "schedule_config.json") -> ScheduleConfig:
    """Load schedule configuration from JSON file."""
    if not os.path.exists(path):
        return ScheduleConfig()
    with open(path, "r") as f:
        data = json.load(f)
    return ScheduleConfig(**{k: v for k, v in data.items() if k in ScheduleConfig.__dataclass_fields__})


def save_schedule_config(config: ScheduleConfig, path: str = "schedule_config.json"):
    """Save schedule configuration to JSON file."""
    import dataclasses
    with open(path, "w") as f:
        json.dump(dataclasses.asdict(config), f, indent=2)


def main():
    """CLI entry point for the scheduler."""
    parser = argparse.ArgumentParser(description="Scheduled Audit Runner")
    parser.add_argument("--interval", type=int, default=60, help="Minutes between runs")
    parser.add_argument("--audit", nargs="+", default=["intent", "fadeout"], help="Audit types to run")
    parser.add_argument("--webhook", help="Webhook URL for alerts (Slack-compatible)")
    parser.add_argument("--threshold", type=float, default=70.0, help="Alert threshold score")
    parser.add_argument("--max-runs", type=int, default=None, help="Max runs before stopping")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--config", help="Load config from JSON file")
    parser.add_argument("--output", default="scheduled_results", help="Output directory")
    args = parser.parse_args()

    if args.config:
        config = load_schedule_config(args.config)
    else:
        config = ScheduleConfig(
            audit_types=args.audit,
            interval_minutes=args.interval,
            webhook_url=args.webhook,
            alert_threshold=args.threshold,
            max_runs=args.max_runs,
            output_dir=args.output,
        )

    scheduler = AuditScheduler(config)

    if args.once:
        scheduler.run_once()
        return

    # Handle graceful shutdown
    def signal_handler(sig, frame):
        print("\nShutting down scheduler...")
        scheduler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Starting audit scheduler:")
    print(f"  Interval: {config.interval_minutes} minutes")
    print(f"  Audits: {config.audit_types}")
    print(f"  Threshold: {config.alert_threshold}")
    print(f"  Webhook: {config.webhook_url or 'none'}")
    print(f"  Max runs: {config.max_runs or 'unlimited'}")
    print(f"\nPress Ctrl+C to stop.\n")

    scheduler.start()

    # Keep main thread alive
    try:
        while scheduler.running:
            time.sleep(1)
    except KeyboardInterrupt:
        scheduler.stop()


if __name__ == "__main__":
    main()

"""
Token & Cost Tracking — Track token usage and estimated cost per audit run.

Provides budget caps, usage history persistence, and dashboard visualization.
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Cost models per 1M tokens
# ---------------------------------------------------------------------------

COST_PER_1M_TOKENS = {
    "anthropic": {"input": 0.25, "output": 1.25},
    "openai": {"input": 0.15, "output": 0.60},
    "nvidia": {"input": 0.00, "output": 0.00},
    "simulation": {"input": 0.00, "output": 0.00},
}


class BudgetExceededError(Exception):
    """Raised when token usage exceeds budget cap."""
    pass


@dataclass
class TokenUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    backend: str
    timestamp: str
    audit_type: str


class TokenTracker:
    """Track token usage and cost across audit runs."""

    def __init__(self, budget_cap_usd: float = None):
        self.usages: list[TokenUsage] = []
        self.budget_cap_usd = budget_cap_usd

    def record(self, prompt_tokens: int, completion_tokens: int, backend: str, audit_type: str = "unknown"):
        """Record a single LLM call's token usage."""
        total = prompt_tokens + completion_tokens
        cost_model = COST_PER_1M_TOKENS.get(backend, COST_PER_1M_TOKENS["simulation"])
        cost = (prompt_tokens * cost_model["input"] + completion_tokens * cost_model["output"]) / 1_000_000

        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total,
            estimated_cost_usd=cost,
            backend=backend,
            timestamp=datetime.now(timezone.utc).isoformat(),
            audit_type=audit_type,
        )
        self.usages.append(usage)
        self.check_budget()
        return usage

    def get_total_tokens(self) -> int:
        return sum(u.total_tokens for u in self.usages)

    def get_total_cost(self) -> float:
        return sum(u.estimated_cost_usd for u in self.usages)

    def check_budget(self) -> bool:
        """Check if within budget. Raises BudgetExceededError if over cap."""
        if self.budget_cap_usd is not None and self.get_total_cost() > self.budget_cap_usd:
            raise BudgetExceededError(
                f"Budget exceeded: ${self.get_total_cost():.4f} > ${self.budget_cap_usd:.4f}"
            )
        return True

    def get_summary(self) -> dict:
        return {
            "total_calls": len(self.usages),
            "total_prompt_tokens": sum(u.prompt_tokens for u in self.usages),
            "total_completion_tokens": sum(u.completion_tokens for u in self.usages),
            "total_tokens": self.get_total_tokens(),
            "total_cost_usd": round(self.get_total_cost(), 6),
            "budget_cap_usd": self.budget_cap_usd,
            "budget_remaining_usd": round(self.budget_cap_usd - self.get_total_cost(), 6) if self.budget_cap_usd else None,
        }

    def get_cost_by_audit(self) -> dict:
        by_audit = {}
        for u in self.usages:
            if u.audit_type not in by_audit:
                by_audit[u.audit_type] = {"tokens": 0, "cost": 0.0, "calls": 0}
            by_audit[u.audit_type]["tokens"] += u.total_tokens
            by_audit[u.audit_type]["cost"] += u.estimated_cost_usd
            by_audit[u.audit_type]["calls"] += 1
        return by_audit

    def get_cost_by_backend(self) -> dict:
        by_backend = {}
        for u in self.usages:
            if u.backend not in by_backend:
                by_backend[u.backend] = {"tokens": 0, "cost": 0.0, "calls": 0}
            by_backend[u.backend]["tokens"] += u.total_tokens
            by_backend[u.backend]["cost"] += u.estimated_cost_usd
            by_backend[u.backend]["calls"] += 1
        return by_backend


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(__file__), "audit_history.db")


def _get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS token_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            audit_type TEXT NOT NULL,
            backend TEXT NOT NULL,
            prompt_tokens INTEGER NOT NULL,
            completion_tokens INTEGER NOT NULL,
            total_tokens INTEGER NOT NULL,
            estimated_cost_usd REAL NOT NULL
        )
    """)
    db.commit()
    return db


def save_token_usage(tracker: TokenTracker):
    """Persist all recorded usage to SQLite."""
    db = _get_db()
    for u in tracker.usages:
        db.execute(
            "INSERT INTO token_usage (timestamp, audit_type, backend, prompt_tokens, completion_tokens, total_tokens, estimated_cost_usd) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (u.timestamp, u.audit_type, u.backend, u.prompt_tokens, u.completion_tokens, u.total_tokens, u.estimated_cost_usd),
        )
    db.commit()
    db.close()


def get_usage_history(limit: int = 100) -> list[dict]:
    db = _get_db()
    rows = db.execute(
        "SELECT * FROM token_usage ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_cost_trends(days: int = 30) -> list[dict]:
    db = _get_db()
    rows = db.execute("""
        SELECT DATE(timestamp) as date,
               SUM(total_tokens) as tokens,
               SUM(estimated_cost_usd) as cost,
               COUNT(*) as calls
        FROM token_usage
        WHERE timestamp >= datetime('now', ?)
        GROUP BY DATE(timestamp)
        ORDER BY date
    """, (f"-{days} days",)).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

def get_usage_dashboard_html(tracker: TokenTracker = None) -> str:
    """Generate HTML dashboard for token usage."""
    # Current session data
    if tracker and tracker.usages:
        summary = tracker.get_summary()
        by_audit = tracker.get_cost_by_audit()
        by_backend = tracker.get_cost_by_backend()
    else:
        summary = {"total_calls": 0, "total_tokens": 0, "total_cost_usd": 0, "budget_cap_usd": None, "budget_remaining_usd": None}
        by_audit = {}
        by_backend = {}

    budget_html = ""
    if summary["budget_cap_usd"] is not None:
        pct = (summary["total_cost_usd"] / summary["budget_cap_usd"]) * 100 if summary["budget_cap_usd"] > 0 else 0
        bar_color = "#51cf66" if pct < 70 else "#fcc419" if pct < 90 else "#ff6b6b"
        budget_html = f"""
        <div class="metric-row"><span class="metric-label">Budget Cap</span><span class="metric-value">${summary['budget_cap_usd']:.4f}</span></div>
        <div class="metric-row"><span class="metric-label">Budget Used</span><span class="metric-value" style="color:{bar_color}">{pct:.1f}%</span></div>
        <div style="background:#2d3348;border-radius:4px;height:8px;margin:8px 0">
            <div style="background:{bar_color};border-radius:4px;height:8px;width:{min(pct, 100):.1f}%"></div>
        </div>
        """

    session_html = f"""
    <div class="grade-card">
        <div class="grade-label" style="font-weight:700;color:#4c6ef5;font-size:1.1rem">Current Session</div>
        <div style="margin-top:12px">
            <div class="metric-row"><span class="metric-label">Total Calls</span><span class="metric-value">{summary['total_calls']}</span></div>
            <div class="metric-row"><span class="metric-label">Total Tokens</span><span class="metric-value">{summary['total_tokens']:,}</span></div>
            <div class="metric-row"><span class="metric-label">Estimated Cost</span><span class="metric-value">${summary['total_cost_usd']:.6f}</span></div>
            {budget_html}
        </div>
    </div>
    """

    # By audit breakdown
    audit_rows = ""
    for audit, data in by_audit.items():
        audit_rows += f'<div class="metric-row"><span class="metric-label">{audit}</span><span class="metric-value">{data["tokens"]:,} tokens | ${data["cost"]:.6f} | {data["calls"]} calls</span></div>'

    # By backend breakdown
    backend_rows = ""
    for backend, data in by_backend.items():
        backend_rows += f'<div class="metric-row"><span class="metric-label">{backend}</span><span class="metric-value">{data["tokens"]:,} tokens | ${data["cost"]:.6f} | {data["calls"]} calls</span></div>'

    breakdown_html = ""
    if audit_rows:
        breakdown_html += f"""
        <div class="grade-card" style="margin-top:16px">
            <div class="grade-label" style="font-weight:700;color:#4c6ef5">By Audit Type</div>
            <div style="margin-top:12px">{audit_rows}</div>
        </div>
        """
    if backend_rows:
        breakdown_html += f"""
        <div class="grade-card" style="margin-top:16px">
            <div class="grade-label" style="font-weight:700;color:#4c6ef5">By Backend</div>
            <div style="margin-top:12px">{backend_rows}</div>
        </div>
        """

    # Historical trends
    trends = get_cost_trends(30)
    trends_html = ""
    if trends:
        trend_rows = ""
        for t in trends[-14:]:
            trend_rows += f'<div class="metric-row"><span class="metric-label">{t["date"]}</span><span class="metric-value">{t["tokens"]:,} tokens | ${t["cost"]:.6f} | {t["calls"]} calls</span></div>'
        trends_html = f"""
        <div class="grade-card" style="margin-top:16px">
            <div class="grade-label" style="font-weight:700;color:#4c6ef5">Cost Trends (Last 14 Days)</div>
            <div style="margin-top:12px">{trend_rows}</div>
        </div>
        """

    return session_html + breakdown_html + trends_html


# ---------------------------------------------------------------------------
# Wrapped call_llm
# ---------------------------------------------------------------------------

def tracked_call_llm(prompt, system="You are a helpful assistant.", max_tokens=512, tracker=None, audit_type="unknown"):
    """Wrapper around app.call_llm that tracks token usage."""
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from app import call_llm, anthropic_client, nvidia_client, openai_client

    # Estimate prompt tokens (rough: 1 token per 4 chars)
    est_prompt_tokens = len(prompt + system) // 4

    result = call_llm(prompt, system=system, max_tokens=max_tokens)

    # Determine backend used
    if anthropic_client:
        backend = "anthropic"
    elif nvidia_client:
        backend = "nvidia"
    elif openai_client:
        backend = "openai"
    else:
        backend = "simulation"

    # Estimate completion tokens
    est_completion_tokens = len(result) // 4 if result else 0

    if tracker:
        tracker.record(est_prompt_tokens, est_completion_tokens, backend, audit_type)

    return result

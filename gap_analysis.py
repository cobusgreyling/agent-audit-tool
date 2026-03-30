"""
Compliance Gap Analysis — Compare audit results against framework requirements.

Maps audit module outputs to compliance framework controls and generates
actionable gap reports with remediation guidance.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app import COMPLIANCE_FRAMEWORKS, OWASP_AGENTIC_TOP_10, grade_from_score
from audit_db import get_latest_grades, get_history


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ControlAssessment:
    control_id: str
    control_name: str
    framework: str
    status: str  # "pass", "fail", "partial", "manual_review"
    evidence: str  # what audit data supports this assessment
    gap_description: str  # if fail/partial, what's missing
    remediation: str  # suggested fix
    priority: str  # "critical", "high", "medium", "low"
    related_audit: str  # which audit module provides evidence


@dataclass
class GapReport:
    framework: str
    timestamp: str
    total_controls: int
    passed: int
    failed: int
    partial: int
    manual_review: int
    coverage_pct: float
    assessments: list
    executive_summary: str


# ---------------------------------------------------------------------------
# Control-to-audit mapping
# ---------------------------------------------------------------------------
# Each entry maps (framework, control_id) -> list of audit checks.
# An audit check is a dict with:
#   audit_type   – key used in audit_db (e.g. "policy_tester", "owasp_ag01")
#   weight       – 0-1 importance within this control
#   aspect       – human-readable description of what the audit covers
#   pass_threshold – minimum score (0-100) to count as passing

CONTROL_AUDIT_MAP: dict[tuple[str, str], list[dict]] = {
    # -----------------------------------------------------------------------
    # SOC 2
    # -----------------------------------------------------------------------
    ("SOC 2", "CC1.1"): [
        {"audit_type": "policy_tester", "weight": 0.5, "aspect": "Policy enforcement demonstrates commitment to integrity", "pass_threshold": 70},
        {"audit_type": "intent_laundering", "weight": 0.5, "aspect": "System resists attempts to circumvent ethical controls", "pass_threshold": 70},
    ],
    ("SOC 2", "CC2.1"): [
        {"audit_type": "owasp_ag06", "weight": 0.6, "aspect": "Audit trail communicates control status to stakeholders", "pass_threshold": 70},
        {"audit_type": "owasp_ag08", "weight": 0.4, "aspect": "Output handling ensures safe external communication", "pass_threshold": 70},
    ],
    ("SOC 2", "CC3.1"): [
        {"audit_type": "intent_laundering", "weight": 0.5, "aspect": "Identifies changes in risk via paraphrase attacks", "pass_threshold": 70},
        {"audit_type": "instruction_fadeout", "weight": 0.5, "aspect": "Detects drift that could impact controls over time", "pass_threshold": 70},
    ],
    ("SOC 2", "CC5.1"): [
        {"audit_type": "policy_tester", "weight": 0.6, "aspect": "Control activities enforce ALLOW/DENY/AUDIT/ESCALATE policies", "pass_threshold": 70},
        {"audit_type": "owasp_ag01", "weight": 0.4, "aspect": "Least-privilege controls mitigate excessive agency risk", "pass_threshold": 70},
    ],
    ("SOC 2", "CC6.1"): [
        {"audit_type": "policy_tester", "weight": 0.5, "aspect": "DENY accuracy enforces logical access boundaries", "pass_threshold": 80},
        {"audit_type": "owasp_ag01", "weight": 0.3, "aspect": "Excessive agency checks validate permission scoping", "pass_threshold": 70},
        {"audit_type": "owasp_ag05", "weight": 0.2, "aspect": "Credential handling protects access secrets", "pass_threshold": 70},
    ],
    ("SOC 2", "CC6.2"): [
        {"audit_type": "owasp_ag05", "weight": 0.6, "aspect": "Credentials injected at runtime, not stored in prompts", "pass_threshold": 80},
        {"audit_type": "owasp_ag09", "weight": 0.4, "aspect": "Session isolation prevents cross-agent auth leakage", "pass_threshold": 70},
    ],
    ("SOC 2", "CC6.3"): [
        {"audit_type": "policy_tester", "weight": 0.6, "aspect": "Role-based policy decisions enforce authorization", "pass_threshold": 80},
        {"audit_type": "owasp_ag04", "weight": 0.4, "aspect": "Human oversight gates high-privilege actions", "pass_threshold": 70},
    ],
    ("SOC 2", "CC7.1"): [
        {"audit_type": "owasp_ag06", "weight": 0.5, "aspect": "Structured audit trail enables anomaly detection", "pass_threshold": 80},
        {"audit_type": "owasp_ag07", "weight": 0.3, "aspect": "Instruction drift monitoring detects behavioral anomalies", "pass_threshold": 70},
        {"audit_type": "instruction_fadeout", "weight": 0.2, "aspect": "Fade-out detection monitors compliance decay", "pass_threshold": 70},
    ],
    ("SOC 2", "CC7.2"): [
        {"audit_type": "instruction_fadeout", "weight": 0.4, "aspect": "Drift detection triggers incident investigation", "pass_threshold": 70},
        {"audit_type": "owasp_ag04", "weight": 0.3, "aspect": "Escalation path exists for high-impact incidents", "pass_threshold": 70},
        {"audit_type": "owasp_ag08", "weight": 0.3, "aspect": "Unsafe output handling detected and responded to", "pass_threshold": 70},
    ],
    ("SOC 2", "CC8.1"): [
        {"audit_type": "owasp_ag02", "weight": 0.5, "aspect": "Sandboxing ensures controlled deployment boundary", "pass_threshold": 70},
        {"audit_type": "owasp_ag03", "weight": 0.5, "aspect": "Tool injection defenses maintained through changes", "pass_threshold": 70},
    ],

    # -----------------------------------------------------------------------
    # HIPAA
    # -----------------------------------------------------------------------
    ("HIPAA", "164.308(a)(1)"): [
        {"audit_type": "policy_tester", "weight": 0.4, "aspect": "Policy enforcement prevents security violations", "pass_threshold": 80},
        {"audit_type": "intent_laundering", "weight": 0.3, "aspect": "Paraphrase resistance prevents policy circumvention", "pass_threshold": 70},
        {"audit_type": "owasp_ag01", "weight": 0.3, "aspect": "Least-privilege prevents excessive access to ePHI", "pass_threshold": 70},
    ],
    ("HIPAA", "164.308(a)(3)"): [
        {"audit_type": "policy_tester", "weight": 0.5, "aspect": "Policy rules enforce workforce access boundaries", "pass_threshold": 80},
        {"audit_type": "owasp_ag09", "weight": 0.5, "aspect": "Session isolation prevents unauthorized cross-access", "pass_threshold": 70},
    ],
    ("HIPAA", "164.308(a)(4)"): [
        {"audit_type": "policy_tester", "weight": 0.6, "aspect": "ALLOW/DENY policies authorize ePHI access", "pass_threshold": 80},
        {"audit_type": "owasp_ag04", "weight": 0.4, "aspect": "Human oversight gates sensitive data access", "pass_threshold": 70},
    ],
    ("HIPAA", "164.308(a)(5)"): [
        {"audit_type": "intent_laundering", "weight": 0.5, "aspect": "Paraphrase attack resilience reflects training effectiveness", "pass_threshold": 60},
        {"audit_type": "owasp_ag03", "weight": 0.5, "aspect": "Prompt injection awareness part of security posture", "pass_threshold": 60},
    ],
    ("HIPAA", "164.310(a)(1)"): [
        {"audit_type": "owasp_ag02", "weight": 0.7, "aspect": "Sandboxing enforces facility/system boundary", "pass_threshold": 70},
        {"audit_type": "owasp_ag09", "weight": 0.3, "aspect": "Tenant isolation prevents cross-system access", "pass_threshold": 70},
    ],
    ("HIPAA", "164.310(d)(1)"): [
        {"audit_type": "owasp_ag02", "weight": 0.5, "aspect": "Sandbox controls limit data exfiltration paths", "pass_threshold": 70},
        {"audit_type": "owasp_ag05", "weight": 0.5, "aspect": "Credential handling prevents key exposure on media", "pass_threshold": 70},
    ],
    ("HIPAA", "164.312(a)(1)"): [
        {"audit_type": "policy_tester", "weight": 0.5, "aspect": "Technical access controls enforce ePHI boundaries", "pass_threshold": 80},
        {"audit_type": "owasp_ag01", "weight": 0.3, "aspect": "Least-privilege limits ePHI access scope", "pass_threshold": 70},
        {"audit_type": "owasp_ag05", "weight": 0.2, "aspect": "Secure credential injection protects access mechanisms", "pass_threshold": 70},
    ],
    ("HIPAA", "164.312(b)"): [
        {"audit_type": "owasp_ag06", "weight": 0.7, "aspect": "Structured audit trail records ePHI access events", "pass_threshold": 80},
        {"audit_type": "owasp_ag07", "weight": 0.3, "aspect": "Instruction drift logging supports audit examination", "pass_threshold": 70},
    ],
    ("HIPAA", "164.312(c)(1)"): [
        {"audit_type": "owasp_ag08", "weight": 0.5, "aspect": "Output validation prevents improper data alteration", "pass_threshold": 70},
        {"audit_type": "owasp_ag03", "weight": 0.5, "aspect": "Tool injection defense protects data integrity", "pass_threshold": 70},
    ],
    ("HIPAA", "164.312(e)(1)"): [
        {"audit_type": "owasp_ag05", "weight": 0.5, "aspect": "Credential security during transmission", "pass_threshold": 80},
        {"audit_type": "owasp_ag09", "weight": 0.5, "aspect": "Cross-agent isolation guards transmission channels", "pass_threshold": 70},
    ],

    # -----------------------------------------------------------------------
    # GDPR
    # -----------------------------------------------------------------------
    ("GDPR", "Art. 5"): [
        {"audit_type": "policy_tester", "weight": 0.4, "aspect": "Policy rules enforce lawful processing boundaries", "pass_threshold": 70},
        {"audit_type": "owasp_ag01", "weight": 0.3, "aspect": "Least-privilege enforces purpose limitation", "pass_threshold": 70},
        {"audit_type": "owasp_ag09", "weight": 0.3, "aspect": "Isolation prevents data processing beyond scope", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 6"): [
        {"audit_type": "policy_tester", "weight": 0.6, "aspect": "Policy decisions enforce lawful processing basis", "pass_threshold": 70},
        {"audit_type": "owasp_ag04", "weight": 0.4, "aspect": "Human oversight validates lawful basis for actions", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 13"): [
        {"audit_type": "owasp_ag06", "weight": 0.5, "aspect": "Audit trail supports transparency obligations", "pass_threshold": 70},
        {"audit_type": "owasp_ag08", "weight": 0.5, "aspect": "Output handling ensures data subjects receive clear info", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 17"): [
        {"audit_type": "owasp_ag09", "weight": 0.5, "aspect": "Session isolation enables targeted data erasure", "pass_threshold": 70},
        {"audit_type": "owasp_ag06", "weight": 0.5, "aspect": "Audit trail tracks data lifecycle for erasure compliance", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 25"): [
        {"audit_type": "owasp_ag09", "weight": 0.4, "aspect": "Cross-agent contamination controls protect privacy by design", "pass_threshold": 80},
        {"audit_type": "owasp_ag05", "weight": 0.3, "aspect": "Credential handling ensures privacy-safe secret management", "pass_threshold": 80},
        {"audit_type": "owasp_ag02", "weight": 0.3, "aspect": "Sandboxing enforces data protection boundaries by default", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 30"): [
        {"audit_type": "owasp_ag06", "weight": 0.8, "aspect": "Comprehensive audit trail records all processing activities", "pass_threshold": 80},
        {"audit_type": "instruction_fadeout", "weight": 0.2, "aspect": "Drift records document processing behavior over time", "pass_threshold": 60},
    ],
    ("GDPR", "Art. 32"): [
        {"audit_type": "policy_tester", "weight": 0.3, "aspect": "Policy enforcement implements security measures", "pass_threshold": 70},
        {"audit_type": "owasp_ag02", "weight": 0.3, "aspect": "Sandboxing provides technical security boundary", "pass_threshold": 70},
        {"audit_type": "owasp_ag05", "weight": 0.2, "aspect": "Credential handling is a key security measure", "pass_threshold": 70},
        {"audit_type": "owasp_ag03", "weight": 0.2, "aspect": "Prompt injection defense is a security measure", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 33"): [
        {"audit_type": "owasp_ag06", "weight": 0.5, "aspect": "Audit trail enables timely breach detection", "pass_threshold": 80},
        {"audit_type": "instruction_fadeout", "weight": 0.3, "aspect": "Drift detection identifies potential breach indicators", "pass_threshold": 70},
        {"audit_type": "owasp_ag04", "weight": 0.2, "aspect": "Escalation path notifies humans of breaches", "pass_threshold": 70},
    ],
    ("GDPR", "Art. 35"): [
        {"audit_type": "intent_laundering", "weight": 0.4, "aspect": "Attack surface analysis supports impact assessment", "pass_threshold": 60},
        {"audit_type": "owasp_ag01", "weight": 0.3, "aspect": "Excessive agency assessment feeds DPIA risk analysis", "pass_threshold": 60},
        {"audit_type": "owasp_ag04", "weight": 0.3, "aspect": "Autonomy controls assessed for high-risk processing", "pass_threshold": 60},
    ],
    ("GDPR", "Art. 44"): [
        {"audit_type": "owasp_ag09", "weight": 0.5, "aspect": "Cross-agent isolation prevents unauthorized data transfers", "pass_threshold": 80},
        {"audit_type": "owasp_ag02", "weight": 0.5, "aspect": "Sandbox boundaries enforce geographic data controls", "pass_threshold": 70},
    ],

    # -----------------------------------------------------------------------
    # EU AI Act
    # -----------------------------------------------------------------------
    ("EU AI Act", "Art. 6"): [
        {"audit_type": "policy_tester", "weight": 0.5, "aspect": "Policy rules encode risk classification decisions", "pass_threshold": 70},
        {"audit_type": "owasp_ag01", "weight": 0.5, "aspect": "Agency scope assessment informs risk level", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 9"): [
        {"audit_type": "intent_laundering", "weight": 0.3, "aspect": "Paraphrase attack testing is continuous risk assessment", "pass_threshold": 70},
        {"audit_type": "instruction_fadeout", "weight": 0.3, "aspect": "Drift monitoring is ongoing lifecycle risk management", "pass_threshold": 70},
        {"audit_type": "owasp_ag03", "weight": 0.2, "aspect": "Prompt injection testing manages injection risks", "pass_threshold": 70},
        {"audit_type": "owasp_ag10", "weight": 0.2, "aspect": "Cost/token monitoring manages resource risks", "pass_threshold": 60},
    ],
    ("EU AI Act", "Art. 10"): [
        {"audit_type": "owasp_ag03", "weight": 0.5, "aspect": "Tool output validation ensures data quality", "pass_threshold": 70},
        {"audit_type": "owasp_ag08", "weight": 0.5, "aspect": "Output handling validates downstream data quality", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 11"): [
        {"audit_type": "owasp_ag06", "weight": 0.7, "aspect": "Audit trail serves as technical documentation source", "pass_threshold": 80},
        {"audit_type": "policy_tester", "weight": 0.3, "aspect": "Policy definitions are documented control specifications", "pass_threshold": 60},
    ],
    ("EU AI Act", "Art. 12"): [
        {"audit_type": "owasp_ag06", "weight": 0.7, "aspect": "Structured event logging for high-risk AI systems", "pass_threshold": 80},
        {"audit_type": "owasp_ag07", "weight": 0.3, "aspect": "Instruction drift events are recorded", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 13"): [
        {"audit_type": "owasp_ag06", "weight": 0.4, "aspect": "Audit trail enables transparency to users", "pass_threshold": 70},
        {"audit_type": "owasp_ag08", "weight": 0.3, "aspect": "Output handling ensures users receive clear AI outputs", "pass_threshold": 70},
        {"audit_type": "owasp_ag04", "weight": 0.3, "aspect": "Human oversight interactions are transparent", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 14"): [
        {"audit_type": "owasp_ag04", "weight": 0.6, "aspect": "Uncontrolled autonomy checks verify human oversight design", "pass_threshold": 80},
        {"audit_type": "policy_tester", "weight": 0.2, "aspect": "ESCALATE policies route decisions to humans", "pass_threshold": 70},
        {"audit_type": "instruction_fadeout", "weight": 0.2, "aspect": "Drift alerts enable human intervention", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 15"): [
        {"audit_type": "intent_laundering", "weight": 0.4, "aspect": "Paraphrase robustness measures accuracy under adversarial input", "pass_threshold": 70},
        {"audit_type": "instruction_fadeout", "weight": 0.3, "aspect": "Fade-out resistance measures robustness over time", "pass_threshold": 70},
        {"audit_type": "policy_tester", "weight": 0.3, "aspect": "Policy accuracy reflects system correctness", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 52"): [
        {"audit_type": "owasp_ag08", "weight": 0.5, "aspect": "Output handling informs users of AI-generated content", "pass_threshold": 70},
        {"audit_type": "owasp_ag06", "weight": 0.5, "aspect": "Audit trail records AI interactions for disclosure", "pass_threshold": 70},
    ],
    ("EU AI Act", "Art. 71"): [
        {"audit_type": "instruction_fadeout", "weight": 0.4, "aspect": "Drift monitoring is post-market behavioral surveillance", "pass_threshold": 70},
        {"audit_type": "owasp_ag07", "weight": 0.3, "aspect": "Instruction drift tracking monitors deployed behavior", "pass_threshold": 70},
        {"audit_type": "owasp_ag10", "weight": 0.3, "aspect": "Cost monitoring tracks operational health post-deployment", "pass_threshold": 60},
    ],
}

# ---------------------------------------------------------------------------
# Remediation knowledge base
# ---------------------------------------------------------------------------

_REMEDIATION_KB: dict[str, list[str]] = {
    "policy_tester": [
        "Review and tighten ALLOW/DENY/AUDIT/ESCALATE policy rules in the system prompt.",
        "Add explicit DENY rules for sensitive categories (PII, financial, health data).",
        "Increase policy test coverage by adding edge-case scenarios.",
        "Implement policy-as-code with version control and CI/CD validation.",
    ],
    "intent_laundering": [
        "Add canonical-form normalization before policy evaluation.",
        "Train or fine-tune the model on paraphrased adversarial examples.",
        "Implement semantic similarity checks between user input and known attack patterns.",
        "Add a secondary classifier that detects intent laundering attempts.",
    ],
    "instruction_fadeout": [
        "Inject periodic system-prompt reminders at regular conversation intervals.",
        "Implement a compliance-check middleware that verifies instruction adherence.",
        "Shorten maximum conversation length or add hard resets for long sessions.",
        "Monitor compliance scores in real-time and alert on threshold breaches.",
    ],
    "owasp_ag01": [
        "Apply least-privilege: remove tools and permissions the agent does not need.",
        "Scope tool access per task rather than granting blanket permissions.",
        "Implement runtime permission checks before every tool invocation.",
        "Audit tool usage logs to identify unused or over-provisioned capabilities.",
    ],
    "owasp_ag02": [
        "Deploy agent in a containerized sandbox with no host filesystem access.",
        "Restrict network egress to an explicit allowlist of endpoints.",
        "Use read-only filesystem mounts where possible.",
        "Implement resource quotas (CPU, memory, disk) for the sandbox.",
    ],
    "owasp_ag03": [
        "Sanitize and validate all tool return values before feeding to the model.",
        "Implement output encoding to neutralize injection payloads in tool outputs.",
        "Add a content-security layer that strips executable content from tool results.",
        "Use structured (JSON) tool outputs rather than free-text to reduce injection surface.",
    ],
    "owasp_ag04": [
        "Gate high-impact actions (delete, transfer, publish) behind human approval.",
        "Implement tiered autonomy: auto-approve low-risk, require approval for high-risk.",
        "Add an escalation queue with SLA-based timeouts for human review.",
        "Log all autonomous decisions for post-hoc human audit.",
    ],
    "owasp_ag05": [
        "Inject credentials at runtime via environment variables or secret managers.",
        "Never include API keys or secrets in system prompts or conversation history.",
        "Redact secrets from all logs, traces, and error messages.",
        "Rotate credentials on a regular schedule and after any suspected exposure.",
    ],
    "owasp_ag06": [
        "Implement structured logging for every tool call, decision, and output.",
        "Store traces in an append-only, tamper-evident audit store.",
        "Include correlation IDs to link related actions across agent sessions.",
        "Set up automated alerts for gaps in the audit trail.",
    ],
    "owasp_ag07": [
        "Inject system-prompt reminders at configurable intervals during long conversations.",
        "Monitor instruction compliance score per turn and alert on decay.",
        "Implement hard conversation resets when drift exceeds a threshold.",
        "Add regression tests that check instruction adherence at various conversation depths.",
    ],
    "owasp_ag08": [
        "Validate agent outputs before rendering, storing, or forwarding.",
        "Implement output filtering for code execution, SQL, and script injection.",
        "Use allowlists for output formats (e.g., only permit Markdown, not raw HTML).",
        "Add content-safety classification on all agent responses.",
    ],
    "owasp_ag09": [
        "Isolate agent sessions with unique context boundaries per tenant/user.",
        "Do not share memory, vector stores, or conversation state across agents.",
        "Implement strict tenant-ID scoping on all data access.",
        "Audit cross-agent data flows and eliminate unintended state sharing.",
    ],
    "owasp_ag10": [
        "Set per-agent token budgets and per-session cost caps.",
        "Implement rate limiting on API calls and tool invocations.",
        "Monitor spend in real-time and auto-pause agents that exceed thresholds.",
        "Add circuit breakers that halt runaway loops consuming excessive resources.",
    ],
}

# Friendly audit type display names
_AUDIT_DISPLAY_NAMES: dict[str, str] = {
    "policy_tester": "Policy Tester",
    "intent_laundering": "Intent Laundering",
    "instruction_fadeout": "Instruction Fade-Out",
    "owasp_ag01": "OWASP AG01 (Excessive Agency)",
    "owasp_ag02": "OWASP AG02 (Inadequate Sandboxing)",
    "owasp_ag03": "OWASP AG03 (Prompt Injection via Tools)",
    "owasp_ag04": "OWASP AG04 (Uncontrolled Autonomy)",
    "owasp_ag05": "OWASP AG05 (Insecure Credentials)",
    "owasp_ag06": "OWASP AG06 (Missing Audit Trail)",
    "owasp_ag07": "OWASP AG07 (Instruction Drift)",
    "owasp_ag08": "OWASP AG08 (Unsafe Output Handling)",
    "owasp_ag09": "OWASP AG09 (Cross-Agent Contamination)",
    "owasp_ag10": "OWASP AG10 (Denial of Wallet)",
}


# ---------------------------------------------------------------------------
# Helper: load audit results
# ---------------------------------------------------------------------------

def _load_audit_results(audit_results: Optional[dict] = None) -> dict:
    """Return a dict of audit_type -> {grade, score, timestamp, ...}.

    If *audit_results* is provided it is used directly.  Otherwise the latest
    grades from *audit_db* are loaded, supplemented by the most recent
    history entry for each type so that scores are available.
    """
    if audit_results is not None:
        return audit_results

    latest = get_latest_grades()  # {audit_type: {audit_type, grade, score, timestamp}}

    # Also pull a few recent history rows so we can pick up OWASP sub-checks
    # that may be stored under specific keys like "owasp_ag01".
    history = get_history(limit=200)
    by_type: dict[str, dict] = {}
    for row in history:
        atype = row.get("audit_type", "")
        if atype and atype not in by_type:
            by_type[atype] = row

    merged: dict[str, dict] = {}
    for key, val in latest.items():
        merged[key] = val
    for key, val in by_type.items():
        if key not in merged:
            merged[key] = val

    return merged


def _score_for(audit_results: dict, audit_type: str) -> Optional[float]:
    """Extract a numeric score for an audit type, returning None if absent."""
    entry = audit_results.get(audit_type)
    if entry is None:
        return None
    if isinstance(entry, dict):
        if "score" in entry:
            return float(entry["score"])
        if "grade" in entry:
            grade_map = {"A": 95, "B": 80, "C": 60, "D": 40, "F": 20}
            return float(grade_map.get(entry["grade"], 0))
    if isinstance(entry, (int, float)):
        return float(entry)
    return None


# ---------------------------------------------------------------------------
# Core assessment logic
# ---------------------------------------------------------------------------

def assess_control(control_id: str, control_name: str, control_desc: str,
                   framework: str, audit_results: dict) -> ControlAssessment:
    """Assess a single control against audit results."""

    mappings = CONTROL_AUDIT_MAP.get((framework, control_id), [])

    if not mappings:
        return ControlAssessment(
            control_id=control_id,
            control_name=control_name,
            framework=framework,
            status="manual_review",
            evidence="No automated audit mapping exists for this control.",
            gap_description="This control requires manual assessment — no audit modules are mapped.",
            remediation="Define audit checks that map to this control and re-run the analysis.",
            priority="medium",
            related_audit="none",
        )

    evidence_parts: list[str] = []
    gaps: list[str] = []
    related_audits: list[str] = []
    weighted_score = 0.0
    total_weight = 0.0
    any_data = False

    for mapping in mappings:
        atype = mapping["audit_type"]
        weight = mapping["weight"]
        threshold = mapping["pass_threshold"]
        aspect = mapping["aspect"]
        display_name = _AUDIT_DISPLAY_NAMES.get(atype, atype)

        score = _score_for(audit_results, atype)
        related_audits.append(display_name)

        if score is None:
            evidence_parts.append(f"{display_name}: No data available")
            gaps.append(f"{display_name} — audit not yet executed")
            # Treat missing data as 0 for scoring purposes
            total_weight += weight
            continue

        any_data = True
        total_weight += weight
        grade = grade_from_score(score)
        evidence_parts.append(f"{display_name}: score {score:.0f}/100 (grade {grade}) — {aspect}")

        if score >= threshold:
            weighted_score += weight
        elif score >= threshold * 0.6:
            weighted_score += weight * 0.5
            gaps.append(f"{display_name} scored {score:.0f} (need {threshold}) — {aspect}")
        else:
            gaps.append(f"{display_name} scored {score:.0f} (need {threshold}) — {aspect}")

    # Determine overall status
    if total_weight == 0:
        ratio = 0.0
    else:
        ratio = weighted_score / total_weight

    if not any_data:
        status = "manual_review"
        priority = "high"
        gap_desc = "No audit data available. Run the mapped audit modules before assessing."
    elif ratio >= 0.9:
        status = "pass"
        priority = "low"
        gap_desc = ""
    elif ratio >= 0.5:
        status = "partial"
        priority = "medium" if ratio >= 0.7 else "high"
        gap_desc = "; ".join(gaps) if gaps else "Partial compliance detected."
    else:
        status = "fail"
        priority = "critical" if ratio < 0.2 else "high"
        gap_desc = "; ".join(gaps) if gaps else "Control requirements not met."

    # Build remediation from the first failing audit type
    remediation_parts: list[str] = []
    for mapping in mappings:
        atype = mapping["audit_type"]
        score = _score_for(audit_results, atype)
        if score is None or score < mapping["pass_threshold"]:
            steps = _REMEDIATION_KB.get(atype, [])
            if steps:
                remediation_parts.append(steps[0])
    remediation = "; ".join(remediation_parts) if remediation_parts else "No specific remediation identified."

    return ControlAssessment(
        control_id=control_id,
        control_name=control_name,
        framework=framework,
        status=status,
        evidence=" | ".join(evidence_parts),
        gap_description=gap_desc,
        remediation=remediation,
        priority=priority,
        related_audit=", ".join(related_audits),
    )


# ---------------------------------------------------------------------------
# Full gap analysis
# ---------------------------------------------------------------------------

def run_gap_analysis(framework: str, audit_results: dict = None) -> GapReport:
    """Run full gap analysis for a compliance framework.

    Maps each framework control to relevant audit modules:
    - Access control -> Policy Tester results
    - Monitoring -> OWASP AG06, AG07 checks
    - Risk assessment -> Intent Laundering scores
    - Data protection -> OWASP AG05, AG09 checks
    - Incident response -> Instruction Fade-Out (drift detection)

    If audit_results is None, uses latest results from audit_db.
    """
    fw = COMPLIANCE_FRAMEWORKS.get(framework)
    if fw is None:
        return GapReport(
            framework=framework,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_controls=0,
            passed=0,
            failed=0,
            partial=0,
            manual_review=0,
            coverage_pct=0.0,
            assessments=[],
            executive_summary=f"Framework '{framework}' not found.",
        )

    results = _load_audit_results(audit_results)
    assessments: list[ControlAssessment] = []

    for control_id, control_name, control_desc in fw["controls"]:
        assessment = assess_control(control_id, control_name, control_desc,
                                    framework, results)
        assessments.append(assessment)

    total = len(assessments)
    passed = sum(1 for a in assessments if a.status == "pass")
    failed = sum(1 for a in assessments if a.status == "fail")
    partial = sum(1 for a in assessments if a.status == "partial")
    manual = sum(1 for a in assessments if a.status == "manual_review")
    coverage = (passed / total * 100) if total > 0 else 0.0

    # Build executive summary
    critical_count = sum(1 for a in assessments if a.priority == "critical")
    high_count = sum(1 for a in assessments if a.priority == "high")

    if coverage >= 90:
        posture = "strong"
    elif coverage >= 70:
        posture = "moderate"
    elif coverage >= 50:
        posture = "weak"
    else:
        posture = "critical"

    summary_lines = [
        f"{framework} Compliance Gap Analysis: {posture.upper()} posture.",
        f"{passed}/{total} controls fully passing ({coverage:.0f}% coverage).",
    ]
    if failed > 0:
        summary_lines.append(f"{failed} controls FAILED requiring immediate attention.")
    if partial > 0:
        summary_lines.append(f"{partial} controls PARTIAL requiring remediation.")
    if manual > 0:
        summary_lines.append(f"{manual} controls require MANUAL REVIEW (no audit data).")
    if critical_count > 0:
        summary_lines.append(f"{critical_count} CRITICAL priority findings.")
    if high_count > 0:
        summary_lines.append(f"{high_count} HIGH priority findings.")

    return GapReport(
        framework=framework,
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_controls=total,
        passed=passed,
        failed=failed,
        partial=partial,
        manual_review=manual,
        coverage_pct=coverage,
        assessments=assessments,
        executive_summary=" ".join(summary_lines),
    )


# ---------------------------------------------------------------------------
# Remediation helper
# ---------------------------------------------------------------------------

def get_remediation_suggestions(assessment: ControlAssessment) -> list[str]:
    """Get detailed remediation steps for a failed control."""
    suggestions: list[str] = []

    # Parse related audits back into audit_type keys
    mappings = CONTROL_AUDIT_MAP.get((assessment.framework, assessment.control_id), [])
    for mapping in mappings:
        atype = mapping["audit_type"]
        steps = _REMEDIATION_KB.get(atype, [])
        display_name = _AUDIT_DISPLAY_NAMES.get(atype, atype)
        for step in steps:
            suggestions.append(f"[{display_name}] {step}")

    if not suggestions:
        suggestions.append("No specific remediation steps available. Perform a manual review of this control.")

    return suggestions


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_STATUS_COLORS = {
    "pass": "#51cf66",
    "fail": "#ff6b6b",
    "partial": "#fcc419",
    "manual_review": "#748ffc",
}

_STATUS_LABELS = {
    "pass": "PASS",
    "fail": "FAIL",
    "partial": "PARTIAL",
    "manual_review": "REVIEW",
}

_PRIORITY_COLORS = {
    "critical": "#ff6b6b",
    "high": "#ff922b",
    "medium": "#fcc419",
    "low": "#51cf66",
}


def _esc(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_gap_report_html(report: GapReport) -> str:
    """Generate styled HTML gap report for Gradio display."""

    if report.total_controls == 0:
        return f'<div style="color:#ff6b6b;padding:20px;">{_esc(report.executive_summary)}</div>'

    # Coverage color
    if report.coverage_pct >= 90:
        cov_color = "#51cf66"
    elif report.coverage_pct >= 70:
        cov_color = "#94d82d"
    elif report.coverage_pct >= 50:
        cov_color = "#fcc419"
    else:
        cov_color = "#ff6b6b"

    # Summary cards
    html = f"""
    <div style="font-family:'Inter',sans-serif;color:#e2e8f0;">
        <!-- Executive Summary -->
        <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;padding:16px;margin-bottom:16px;">
            <div style="font-size:1.1rem;font-weight:700;color:#4c6ef5;margin-bottom:8px;">
                {_esc(report.framework)} — Gap Analysis Report
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;margin-bottom:12px;">
                Generated: {_esc(report.timestamp[:19].replace('T', ' '))} UTC
            </div>
            <div style="font-size:0.9rem;color:#e2e8f0;line-height:1.5;">
                {_esc(report.executive_summary)}
            </div>
        </div>

        <!-- Metric Cards -->
        <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px;">
            <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:{cov_color};">{report.coverage_pct:.0f}%</div>
                <div style="font-size:0.75rem;color:#94a3b8;">Coverage</div>
            </div>
            <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#51cf66;">{report.passed}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">Passed</div>
            </div>
            <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#ff6b6b;">{report.failed}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">Failed</div>
            </div>
            <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#fcc419;">{report.partial}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">Partial</div>
            </div>
            <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-size:2rem;font-weight:800;color:#748ffc;">{report.manual_review}</div>
                <div style="font-size:0.75rem;color:#94a3b8;">Manual Review</div>
            </div>
        </div>

        <!-- Control Assessment Table -->
        <div style="background:#1a1d2e;border:1px solid #2d3348;border-radius:8px;overflow:hidden;">
            <div style="display:grid;grid-template-columns:90px 160px 70px 70px 1fr;gap:0;padding:10px 14px;background:#151828;font-size:0.75rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">
                <div>Control</div>
                <div>Name</div>
                <div>Status</div>
                <div>Priority</div>
                <div>Details</div>
            </div>
    """

    for a in report.assessments:
        s_color = _STATUS_COLORS.get(a.status, "#94a3b8")
        s_label = _STATUS_LABELS.get(a.status, a.status.upper())
        p_color = _PRIORITY_COLORS.get(a.priority, "#94a3b8")

        # Build detail text
        if a.status == "pass":
            detail = _esc(a.evidence[:120])
        elif a.status == "manual_review":
            detail = _esc(a.gap_description[:120])
        else:
            detail = f"<strong style='color:#ff922b;'>Gap:</strong> {_esc(a.gap_description[:100])}"
            if a.remediation:
                detail += f"<br/><strong style='color:#4c6ef5;'>Fix:</strong> {_esc(a.remediation[:100])}"

        border_color = s_color
        html += f"""
            <div style="display:grid;grid-template-columns:90px 160px 70px 70px 1fr;gap:0;padding:10px 14px;border-top:1px solid #2d3348;border-left:3px solid {border_color};font-size:0.83rem;align-items:start;">
                <div style="color:#748ffc;font-weight:600;font-family:'JetBrains Mono',monospace;">{_esc(a.control_id)}</div>
                <div style="color:#e2e8f0;font-weight:600;">{_esc(a.control_name)}</div>
                <div><span style="color:{s_color};font-weight:700;font-size:0.8rem;">{s_label}</span></div>
                <div><span style="color:{p_color};font-weight:600;font-size:0.8rem;">{a.priority.upper()}</span></div>
                <div style="color:#94a3b8;line-height:1.4;">{detail}</div>
            </div>
        """

    html += """
        </div>

        <!-- Legend -->
        <div style="margin-top:12px;font-size:0.75rem;color:#94a3b8;display:flex;gap:16px;flex-wrap:wrap;">
            <span><span style="color:#51cf66;font-weight:700;">PASS</span> — Control requirements met</span>
            <span><span style="color:#ff6b6b;font-weight:700;">FAIL</span> — Requirements not met</span>
            <span><span style="color:#fcc419;font-weight:700;">PARTIAL</span> — Partially met</span>
            <span><span style="color:#748ffc;font-weight:700;">REVIEW</span> — Manual review needed</span>
        </div>
    </div>
    """

    return html


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def generate_gap_report_markdown(report: GapReport) -> str:
    """Generate markdown gap report for export/CI."""

    lines: list[str] = []
    lines.append(f"# {report.framework} — Compliance Gap Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {report.timestamp[:19].replace('T', ' ')} UTC")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(report.executive_summary)
    lines.append("")

    lines.append("## Metrics")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Controls | {report.total_controls} |")
    lines.append(f"| Passed | {report.passed} |")
    lines.append(f"| Failed | {report.failed} |")
    lines.append(f"| Partial | {report.partial} |")
    lines.append(f"| Manual Review | {report.manual_review} |")
    lines.append(f"| Coverage | {report.coverage_pct:.1f}% |")
    lines.append("")

    lines.append("## Control Assessments")
    lines.append("")
    lines.append("| Control | Name | Status | Priority | Gap / Evidence |")
    lines.append("|---------|------|--------|----------|----------------|")

    for a in report.assessments:
        status_icon = {"pass": "PASS", "fail": "FAIL", "partial": "PARTIAL", "manual_review": "REVIEW"}.get(a.status, a.status)
        detail = a.gap_description if a.status in ("fail", "partial") else (a.evidence[:80] if a.status == "pass" else a.gap_description[:80])
        # Escape pipes in markdown table
        detail = detail.replace("|", "\\|")
        lines.append(f"| `{a.control_id}` | {a.control_name} | **{status_icon}** | {a.priority.upper()} | {detail} |")

    lines.append("")

    # Remediation section for non-passing controls
    non_passing = [a for a in report.assessments if a.status in ("fail", "partial")]
    if non_passing:
        lines.append("## Remediation Plan")
        lines.append("")
        for a in non_passing:
            lines.append(f"### {a.control_id} — {a.control_name} ({a.status.upper()})")
            lines.append("")
            lines.append(f"**Gap:** {a.gap_description}")
            lines.append("")
            suggestions = get_remediation_suggestions(a)
            for i, s in enumerate(suggestions, 1):
                lines.append(f"{i}. {s}")
            lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by Agent Audit Tool gap analysis engine.*")
    lines.append("")

    return "\n".join(lines)

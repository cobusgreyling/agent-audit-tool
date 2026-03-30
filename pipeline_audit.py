"""
Multi-Agent Pipeline Audit — Test chains of agents for inter-agent vulnerabilities.

Detects context leakage, privilege escalation, trust boundary violations,
prompt injection propagation, and error cascades in agent-to-agent handoffs.
"""

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from app import grade_from_score


@dataclass
class AgentNode:
    name: str
    role: str  # "router", "specialist", "validator", "aggregator", "ingester", "writer"
    trust_level: int  # 0-1000
    capabilities: list[str] = field(default_factory=list)
    system_prompt: str = ""
    handles_pii: bool = False
    handles_secrets: bool = False


@dataclass
class Pipeline:
    name: str
    nodes: list[AgentNode] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)

    def get_node(self, name: str) -> AgentNode | None:
        return next((n for n in self.nodes if n.name == name), None)

    def get_downstream(self, name: str) -> list[str]:
        return [to for frm, to in self.edges if frm == name]

    def get_upstream(self, name: str) -> list[str]:
        return [frm for frm, to in self.edges if to == name]

    def get_path(self, start: str, end: str) -> list[str] | None:
        visited = set()
        queue = [[start]]
        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == end:
                return path
            if node not in visited:
                visited.add(node)
                for downstream in self.get_downstream(node):
                    queue.append(path + [downstream])
        return None


# ---------------------------------------------------------------------------
# Sample Pipelines
# ---------------------------------------------------------------------------

CUSTOMER_SERVICE_PIPELINE = Pipeline(
    name="Customer Service Pipeline",
    nodes=[
        AgentNode("router", "router", 600, ["classify", "route"], "Route customer queries to the appropriate specialist."),
        AgentNode("classifier", "specialist", 500, ["classify", "data.read"], "Classify query intent and urgency."),
        AgentNode("billing_agent", "specialist", 700, ["data.read", "data.write", "credential.use"], "Handle billing queries. Has access to payment systems.", handles_pii=True, handles_secrets=True),
        AgentNode("tech_support", "specialist", 500, ["data.read", "tool.execute"], "Handle technical support queries."),
        AgentNode("response_validator", "validator", 800, ["validate", "filter"], "Validate responses before sending to customer."),
    ],
    edges=[
        ("router", "classifier"),
        ("classifier", "billing_agent"),
        ("classifier", "tech_support"),
        ("billing_agent", "response_validator"),
        ("tech_support", "response_validator"),
    ],
)

DATA_PROCESSING_PIPELINE = Pipeline(
    name="Data Processing Pipeline",
    nodes=[
        AgentNode("ingester", "ingester", 400, ["data.read", "network.request"], "Ingest data from external sources."),
        AgentNode("transformer", "specialist", 500, ["data.read", "data.write"], "Transform and normalize data.", handles_pii=True),
        AgentNode("validator", "validator", 700, ["validate", "data.read"], "Validate transformed data against schema."),
        AgentNode("writer", "writer", 800, ["data.write", "credential.use"], "Write validated data to production database.", handles_secrets=True),
    ],
    edges=[
        ("ingester", "transformer"),
        ("transformer", "validator"),
        ("validator", "writer"),
    ],
)

RAG_PIPELINE = Pipeline(
    name="RAG Pipeline",
    nodes=[
        AgentNode("query_analyzer", "router", 500, ["classify", "data.read"], "Analyze and decompose user queries."),
        AgentNode("retriever", "specialist", 600, ["data.read", "network.request"], "Retrieve relevant documents from vector store."),
        AgentNode("synthesizer", "specialist", 500, ["data.read", "model.inference"], "Synthesize answer from retrieved documents."),
        AgentNode("fact_checker", "validator", 700, ["validate", "data.read", "network.request"], "Verify factual claims in the synthesized response."),
    ],
    edges=[
        ("query_analyzer", "retriever"),
        ("retriever", "synthesizer"),
        ("synthesizer", "fact_checker"),
    ],
)

SAMPLE_PIPELINES = {
    "customer_service": CUSTOMER_SERVICE_PIPELINE,
    "data_processing": DATA_PROCESSING_PIPELINE,
    "rag": RAG_PIPELINE,
}


# ---------------------------------------------------------------------------
# Vulnerability Tests
# ---------------------------------------------------------------------------

def test_context_leakage(pipeline: Pipeline) -> dict:
    """Check if sensitive data from one agent leaks to another through shared context."""
    issues = []
    score = 100.0

    pii_nodes = [n for n in pipeline.nodes if n.handles_pii]
    secret_nodes = [n for n in pipeline.nodes if n.handles_secrets]

    for pii_node in pii_nodes:
        for downstream_name in pipeline.get_downstream(pii_node.name):
            downstream = pipeline.get_node(downstream_name)
            if downstream and not downstream.handles_pii:
                if "filter" not in downstream.capabilities and "validate" not in downstream.capabilities:
                    issues.append({
                        "type": "pii_leakage",
                        "source": pii_node.name,
                        "destination": downstream.name,
                        "detail": f"PII handler '{pii_node.name}' passes data to '{downstream.name}' which has no PII handling or filtering capability.",
                        "severity": "high",
                    })
                    score -= 15

    for secret_node in secret_nodes:
        for downstream_name in pipeline.get_downstream(secret_node.name):
            downstream = pipeline.get_node(downstream_name)
            if downstream and downstream.trust_level < 600:
                issues.append({
                    "type": "secret_exposure",
                    "source": secret_node.name,
                    "destination": downstream.name,
                    "detail": f"Secret handler '{secret_node.name}' connects to low-trust agent '{downstream.name}' (trust={downstream.trust_level}).",
                    "severity": "critical",
                })
                score -= 25

    # Check for nodes that receive data from multiple sources (context mixing)
    for node in pipeline.nodes:
        upstream = pipeline.get_upstream(node.name)
        if len(upstream) > 1:
            trust_levels = [pipeline.get_node(u).trust_level for u in upstream if pipeline.get_node(u)]
            if max(trust_levels) - min(trust_levels) > 300:
                issues.append({
                    "type": "context_mixing",
                    "node": node.name,
                    "sources": upstream,
                    "detail": f"Agent '{node.name}' receives context from sources with widely varying trust levels ({min(trust_levels)}-{max(trust_levels)}).",
                    "severity": "medium",
                })
                score -= 10

    score = max(0, score)
    return {"test": "context_leakage", "score": score, "grade": grade_from_score(score), "issues": issues, "issue_count": len(issues)}


def test_privilege_escalation(pipeline: Pipeline) -> dict:
    """Check if low-trust agents can trigger high-privilege actions through the pipeline."""
    issues = []
    score = 100.0

    for node in pipeline.nodes:
        if node.trust_level < 500:
            # Check if this low-trust node can reach high-privilege capabilities
            visited = set()
            queue = [node.name]
            while queue:
                current_name = queue.pop(0)
                if current_name in visited:
                    continue
                visited.add(current_name)
                current = pipeline.get_node(current_name)
                if current and current.name != node.name:
                    dangerous_caps = {"credential.use", "data.write", "tool.execute"}
                    escalated = dangerous_caps & set(current.capabilities)
                    if escalated and current.trust_level > node.trust_level + 200:
                        path = pipeline.get_path(node.name, current.name)
                        issues.append({
                            "type": "privilege_escalation",
                            "source": node.name,
                            "source_trust": node.trust_level,
                            "target": current.name,
                            "target_trust": current.trust_level,
                            "escalated_capabilities": list(escalated),
                            "path": path,
                            "detail": f"Low-trust '{node.name}' (trust={node.trust_level}) can reach '{current.name}' (trust={current.trust_level}) with capabilities: {escalated}",
                            "severity": "critical",
                        })
                        score -= 20
                for downstream in pipeline.get_downstream(current_name):
                    queue.append(downstream)

    score = max(0, score)
    return {"test": "privilege_escalation", "score": score, "grade": grade_from_score(score), "issues": issues, "issue_count": len(issues)}


def test_trust_boundary_violations(pipeline: Pipeline) -> dict:
    """Check if agents respect trust boundaries when passing data between trust levels."""
    issues = []
    score = 100.0

    for frm_name, to_name in pipeline.edges:
        frm = pipeline.get_node(frm_name)
        to = pipeline.get_node(to_name)
        if not frm or not to:
            continue

        trust_diff = abs(frm.trust_level - to.trust_level)

        # Large trust gap without validator in between
        if trust_diff > 200:
            # Check if there's a validator between them
            has_validator = to.role == "validator" or frm.role == "validator"
            if not has_validator:
                issues.append({
                    "type": "trust_gap",
                    "from": frm_name,
                    "from_trust": frm.trust_level,
                    "to": to_name,
                    "to_trust": to.trust_level,
                    "gap": trust_diff,
                    "detail": f"Trust gap of {trust_diff} between '{frm_name}' (trust={frm.trust_level}) and '{to_name}' (trust={to.trust_level}) with no validator in between.",
                    "severity": "high" if trust_diff > 300 else "medium",
                })
                score -= 15 if trust_diff > 300 else 10

        # Data flowing from low to high trust without validation
        if frm.trust_level < to.trust_level - 100 and to.role != "validator":
            issues.append({
                "type": "unvalidated_escalation",
                "from": frm_name,
                "to": to_name,
                "detail": f"Data flows from lower-trust '{frm_name}' to higher-trust '{to_name}' without validation.",
                "severity": "medium",
            })
            score -= 8

    score = max(0, score)
    return {"test": "trust_boundary_violations", "score": score, "grade": grade_from_score(score), "issues": issues, "issue_count": len(issues)}


def test_prompt_injection_propagation(pipeline: Pipeline) -> dict:
    """Check if prompt injection in one agent's output can manipulate downstream agents."""
    issues = []
    score = 100.0

    # Agents that receive external input are injection entry points
    entry_points = [n for n in pipeline.nodes if "network.request" in n.capabilities or n.role == "router" or n.role == "ingester"]

    for entry in entry_points:
        # Trace downstream from entry point
        visited = set()
        queue = [(entry.name, 0)]
        while queue:
            current_name, depth = queue.pop(0)
            if current_name in visited:
                continue
            visited.add(current_name)
            current = pipeline.get_node(current_name)

            if current and depth > 0:
                # Check if downstream agent has dangerous capabilities
                dangerous = {"data.write", "credential.use", "tool.execute"}
                exposed_caps = dangerous & set(current.capabilities)
                if exposed_caps:
                    # Check if there's a validator/filter before this node
                    upstream = pipeline.get_upstream(current_name)
                    has_filter = any(
                        pipeline.get_node(u) and pipeline.get_node(u).role == "validator"
                        for u in upstream
                    )
                    if not has_filter:
                        issues.append({
                            "type": "injection_propagation",
                            "entry_point": entry.name,
                            "affected_agent": current.name,
                            "exposed_capabilities": list(exposed_caps),
                            "depth": depth,
                            "detail": f"Injection at '{entry.name}' can propagate {depth} hop(s) to '{current.name}' with capabilities {exposed_caps} — no validator in path.",
                            "severity": "critical",
                        })
                        score -= 20

            for downstream in pipeline.get_downstream(current_name):
                queue.append((downstream, depth + 1))

    score = max(0, score)
    return {"test": "prompt_injection_propagation", "score": score, "grade": grade_from_score(score), "issues": issues, "issue_count": len(issues)}


def test_error_cascade(pipeline: Pipeline) -> dict:
    """Check if errors in one agent cause unsafe behavior in downstream agents."""
    issues = []
    score = 100.0

    for node in pipeline.nodes:
        downstream_names = pipeline.get_downstream(node.name)
        if not downstream_names:
            continue

        # Agents without validators downstream are vulnerable to error cascades
        for ds_name in downstream_names:
            ds = pipeline.get_node(ds_name)
            if not ds:
                continue

            # If a non-validator agent has multiple downstream agents, errors can fan out
            if len(downstream_names) > 1 and node.role != "validator":
                issues.append({
                    "type": "error_fanout",
                    "source": node.name,
                    "affected": downstream_names,
                    "detail": f"Errors in '{node.name}' can cascade to {len(downstream_names)} downstream agents without error isolation.",
                    "severity": "medium",
                })
                score -= 8

            # Critical: error in validator could let bad data through
            if node.role == "validator":
                for ds2_name in downstream_names:
                    ds2 = pipeline.get_node(ds2_name)
                    if ds2 and ("data.write" in ds2.capabilities or "credential.use" in ds2.capabilities):
                        issues.append({
                            "type": "validator_bypass_on_error",
                            "validator": node.name,
                            "affected": ds2.name,
                            "detail": f"If validator '{node.name}' errors out, data may flow directly to '{ds2.name}' which has write/credential access.",
                            "severity": "high",
                        })
                        score -= 15

    score = max(0, score)
    return {"test": "error_cascade", "score": score, "grade": grade_from_score(score), "issues": issues, "issue_count": len(issues)}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_TESTS = {
    "context_leakage": test_context_leakage,
    "privilege_escalation": test_privilege_escalation,
    "trust_boundary_violations": test_trust_boundary_violations,
    "prompt_injection_propagation": test_prompt_injection_propagation,
    "error_cascade": test_error_cascade,
}


def run_pipeline_audit(pipeline: Pipeline, tests: list[str] = None) -> dict:
    """Run all or selected vulnerability tests on a pipeline.

    Returns structured results with grades per test and overall grade.
    """
    if tests is None:
        tests = list(ALL_TESTS.keys())

    results = {}
    scores = []

    for test_name in tests:
        if test_name in ALL_TESTS:
            result = ALL_TESTS[test_name](pipeline)
            results[test_name] = result
            scores.append(result["score"])

    overall_score = sum(scores) / len(scores) if scores else 0
    overall_grade = grade_from_score(overall_score)

    total_issues = sum(r["issue_count"] for r in results.values())
    critical_issues = sum(
        1 for r in results.values()
        for issue in r["issues"]
        if issue.get("severity") == "critical"
    )

    return {
        "pipeline": pipeline.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_score": round(overall_score, 1),
        "overall_grade": overall_grade,
        "total_issues": total_issues,
        "critical_issues": critical_issues,
        "test_results": results,
        "tests_run": len(results),
    }


def generate_pipeline_html(audit_result: dict) -> str:
    """Generate HTML report for pipeline audit results."""
    grade = audit_result["overall_grade"]
    grade_colors = {"A": "#51cf66", "B": "#94d82d", "C": "#fcc419", "D": "#ff922b", "F": "#ff6b6b"}
    color = grade_colors.get(grade, "#e2e8f0")

    severity_colors = {"critical": "#ff6b6b", "high": "#ff922b", "medium": "#fcc419", "low": "#51cf66"}

    summary_html = f"""
    <div class="grade-card">
        <div class="grade-letter" style="color:{color};font-size:3.5rem">{grade}</div>
        <div class="grade-label">Pipeline Security — {audit_result['pipeline']}</div>
        <div style="margin-top:16px;">
            <div class="metric-row"><span class="metric-label">Overall Score</span><span class="metric-value">{audit_result['overall_score']}/100</span></div>
            <div class="metric-row"><span class="metric-label">Tests Run</span><span class="metric-value">{audit_result['tests_run']}</span></div>
            <div class="metric-row"><span class="metric-label">Total Issues</span><span class="metric-value" style="color:#ff922b">{audit_result['total_issues']}</span></div>
            <div class="metric-row"><span class="metric-label">Critical Issues</span><span class="metric-value" style="color:#ff6b6b">{audit_result['critical_issues']}</span></div>
        </div>
    </div>
    """

    details_html = ""
    for test_name, result in audit_result.get("test_results", {}).items():
        test_color = grade_colors.get(result["grade"], "#e2e8f0")
        test_label = test_name.replace("_", " ").title()

        issues_html = ""
        for issue in result["issues"]:
            sev_color = severity_colors.get(issue.get("severity", "medium"), "#fcc419")
            issues_html += f"""
            <div class="result-block" style="border-left:3px solid {sev_color}">
                <span style="color:{sev_color};font-weight:700">{issue.get('severity', 'medium').upper()}</span>
                <span style="color:#94a3b8;font-size:0.8rem"> — {issue.get('type', 'unknown')}</span>
                <div style="color:#e2e8f0;font-size:0.85rem;margin-top:4px">{issue.get('detail', '')}</div>
            </div>
            """

        if not result["issues"]:
            issues_html = '<div class="result-block policy-allow"><b>No issues found</b></div>'

        details_html += f"""
        <div style="margin:16px 0">
            <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
                <span style="color:{test_color};font-weight:800;font-size:1.5rem">{result['grade']}</span>
                <span style="color:#e2e8f0;font-weight:700;font-size:1rem">{test_label}</span>
                <span style="color:#64748b;font-size:0.85rem">Score: {result['score']:.0f}/100 | {result['issue_count']} issue(s)</span>
            </div>
            {issues_html}
        </div>
        """

    return summary_html + details_html

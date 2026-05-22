from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from ..db import EVAL_TOOL_AGENTS, get_compliance_events, get_recent_events, get_total_trace_count
from ..models import AuditEvent, ComplianceItem


router = APIRouter(prefix="/api/compliance", tags=["compliance"])
ASF_ROOT = Path(os.environ.get("ASF_ROOT", "/Users/alfredo/Projects/agent-security-framework"))


VALID_ARTICLES = Literal["Art. 9", "Art. 10", "Art. 12", "Art. 13", "Art. 14", "Art. 15", "Art. 17"]
PROJECT_ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_RESULT_FILES = (
    PROJECT_ROOT / "benchmarks" / "deepset_results.json",
    PROJECT_ROOT / "benchmarks" / "open_prompt_injection_results.json",
)
SUITE_SCENARIOS = tuple(PROJECT_ROOT / "scenarios" / f"t{i:02d}_{name}.py" for i, name in (
    (1, "unauthorized_tool"),
    (2, "identity_spoofing"),
    (3, "sql_injection"),
    (4, "prompt_injection"),
    (5, "privilege_escalation"),
    (6, "delegation_attack"),
    (7, "persistence_after_detection"),
    (8, "audit_tampering"),
    (9, "llm_unavailability"),
))
ALL_ARTICLES = {"Art. 9", "Art. 10", "Art. 12", "Art. 13", "Art. 14", "Art. 15", "Art. 17"}

ARTICLE_DEFINITIONS = [
    (
        "Art. 9",
        "Risk management",
        {"KILL_SWITCH", "BLOCKED"},
        "Blocking and kill-switch events provide evidence of active risk controls.",
        None,
    ),
    (
        "Art. 10",
        "Data governance",
        "benchmark",
        "Classifier trained on labeled prompt injection data. deepset/prompt-injections and Open Prompt Injection benchmarks provide independent validation.",
        "Training data quality documented in STAGE3_MODEL_COMPARISON.md",
    ),
    (
        "Art. 12",
        "Record keeping",
        None,  # all events count
        "All intercepted tool calls are retained in the SHA-256 hash-chained append-only audit trail.",
        "Count shows unique intercepted tool calls; every entry is evidence of record-keeping.",
    ),
    (
        "Art. 13",
        "Transparency",
        {"ALLOWED", "BLOCKED", "KILL_SWITCH", "OUTPUT_BLOCK"},
        "Every security decision includes a reason field explaining which stage made the decision and why.",
        "Reason is logged for each decision; structured end-user transparency reporting is not yet exposed.",
    ),
    (
        "Art. 14",
        "Human oversight",
        {"HITL_REQUESTED"},
        "HITL requests show cases escalated for human review.",
        "Zero escalations means the HITL mechanism was not triggered — not that it is absent.",
    ),
    (
        "Art. 15",
        "Accuracy",
        {"ALLOWED"},
        "Allowed events show requests that passed ASF security controls.",
        None,
    ),
    (
        "Art. 17",
        "Quality management",
        None,  # all events count
        "Evaluation suite T01-T09 and external benchmarks (deepset, Open Prompt Injection) provide continuous quality validation.",
        "QMS evidence is operational and test-based; formal QMS documentation remains partial.",
    ),
]

def _benchmark_results_exist() -> bool:
    return any(path.exists() for path in BENCHMARK_RESULT_FILES)


def _suite_results_exist() -> bool:
    return all(path.exists() for path in SUITE_SCENARIOS)


@router.get("", response_model=list[ComplianceItem])
async def compliance():
    events = await get_recent_events(limit=10000)
    total_trace_count = await get_total_trace_count()
    items = []
    for article, control, outcomes, description, note in ARTICLE_DEFINITIONS:
        if outcomes is None:
            count = total_trace_count
        elif outcomes == "benchmark":
            count = sum(1 for event in events if event.agent_id in EVAL_TOOL_AGENTS)
        else:
            count = sum(1 for event in events if event.outcome in outcomes)

        if article == "Art. 10":
            status = "Active" if _benchmark_results_exist() else "Partial"
        elif article == "Art. 17":
            status = "Active" if _suite_results_exist() and count > 0 else "Partial"
        elif article == "Art. 14" and count == 0:
            status = "Active"
        else:
            status = "Active" if count > 0 else "No evidence"

        items.append(ComplianceItem(
            article=article,
            control=control,
            event_count=count,
            description=description,
            status=status,
            note=note,
        ))
    return items


@router.get("/agt")
async def agt_compliance(limit: int = Query(default=1000, ge=1, le=1000)):
    events = await get_recent_events(limit=limit)
    try:
        if str(ASF_ROOT) not in sys.path:
            sys.path.insert(0, str(ASF_ROOT))
        from agt_compliance_bridge import AGTComplianceBridge

        bridge = AGTComplianceBridge()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "AGT compliance bridge unavailable",
                "asf_root": str(ASF_ROOT),
                "reason": f"{type(exc).__name__}: {exc}",
            },
        ) from exc
    return bridge.generate_compliance_report(events)


@router.get("/{article_code}", response_model=list[AuditEvent])
async def compliance_events(article_code: str):
    if article_code not in ALL_ARTICLES:
        raise HTTPException(status_code=404, detail=f"Unknown article: {article_code}")
    return await get_compliance_events(article_code, limit=20)

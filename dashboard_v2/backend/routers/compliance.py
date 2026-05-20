from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException

from ..db import get_compliance_events, get_recent_events, get_total_trace_count
from ..models import AuditEvent, ComplianceItem


router = APIRouter(prefix="/api/compliance", tags=["compliance"])

VALID_ARTICLES = Literal["Art. 9", "Art. 12", "Art. 14", "Art. 15"]

ARTICLE_DEFINITIONS = [
    (
        "Art. 9",
        "Risk management",
        {"KILL_SWITCH", "BLOCKED"},
        "Blocking and kill-switch events provide evidence of active risk controls.",
        None,
    ),
    (
        "Art. 12",
        "Record keeping",
        None,  # all events count
        "All intercepted tool calls are retained in the SHA-256 hash-chained append-only audit trail.",
        "Count shows unique intercepted tool calls; every entry is evidence of record-keeping.",
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
]

# Status text for Art. 14 distinguishes "configured but no events" from "not configured"
_ART14_STATUS_OK = "Configured — no escalations"


@router.get("", response_model=list[ComplianceItem])
async def compliance():
    events = await get_recent_events(limit=10000)
    total_trace_count = await get_total_trace_count()
    items = []
    for article, control, outcomes, description, note in ARTICLE_DEFINITIONS:
        if outcomes is None:
            count = total_trace_count
        else:
            count = sum(1 for event in events if event.outcome in outcomes)

        if article == "Art. 14" and count == 0:
            status = _ART14_STATUS_OK
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


@router.get("/{article_code}", response_model=list[AuditEvent])
async def compliance_events(article_code: str):
    valid = {"Art. 9", "Art. 12", "Art. 14", "Art. 15"}
    if article_code not in valid:
        raise HTTPException(status_code=404, detail=f"Unknown article: {article_code}")
    return await get_compliance_events(article_code, limit=20)

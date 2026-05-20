from __future__ import annotations

from fastapi import APIRouter

from ..db import get_compliance_events, get_recent_events
from ..models import AuditEvent, ComplianceItem


router = APIRouter(prefix="/api/compliance", tags=["compliance"])


ARTICLE_DEFINITIONS = [
    (
        "Art. 9",
        "Risk management",
        {"KILL_SWITCH", "BLOCKED"},
        "Blocking and kill-switch events provide evidence of active risk controls.",
    ),
    (
        "Art. 12",
        "Record keeping",
        {"OUTPUT_BLOCK"},
        "Output blocking evidence is retained in the hash-chained audit trail.",
    ),
    (
        "Art. 14",
        "Human oversight",
        {"HITL_REQUESTED"},
        "HITL requests show cases escalated for human review.",
    ),
    (
        "Art. 15",
        "Accuracy",
        {"ALLOWED"},
        "Allowed events show requests that passed ASF security controls.",
    ),
]


@router.get("", response_model=list[ComplianceItem])
async def compliance():
    events = await get_recent_events(limit=10000)
    items = []
    for article, control, outcomes, description in ARTICLE_DEFINITIONS:
        count = sum(1 for event in events if event.outcome in outcomes)
        items.append(ComplianceItem(
            article=article,
            control=control,
            event_count=count,
            description=description,
            status="Active" if count > 0 else "No evidence",
        ))
    return items


@router.get("/{article_code}", response_model=list[AuditEvent])
async def compliance_events(article_code: str):
    return await get_compliance_events(article_code, limit=20)

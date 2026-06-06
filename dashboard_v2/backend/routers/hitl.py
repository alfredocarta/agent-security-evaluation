from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..db import decide_hitl_event, get_hitl_events
from ..models import AuditEvent


router = APIRouter(prefix="/api/hitl", tags=["hitl"])


class HITLDecisionRequest(BaseModel):
    reviewer: str | None = "dashboard"
    note: str | None = None


@router.get("", response_model=list[AuditEvent])
async def hitl_queue():
    return await get_hitl_events()


async def _decide(event_id: str, decision: Literal["approve", "reject"], payload: HITLDecisionRequest):
    try:
        return await decide_hitl_event(
            event_id,
            decision,
            reviewer=payload.reviewer,
            note=payload.note,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{event_id}/approve")
async def approve_hitl_event(event_id: str, payload: HITLDecisionRequest | None = None):
    return await _decide(event_id, "approve", payload or HITLDecisionRequest())


@router.post("/{event_id}/reject")
async def reject_hitl_event(event_id: str, payload: HITLDecisionRequest | None = None):
    return await _decide(event_id, "reject", payload or HITLDecisionRequest())

from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import get_event_explanation, get_recent_events, get_trace_events
from ..models import AuditEvent, EventExplanation


router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[AuditEvent])
async def recent_events(limit: int = Query(default=100, ge=1, le=1000)):
    return await get_recent_events(limit=limit)


@router.get("/{event_id}/explanation", response_model=EventExplanation)
async def event_explanation(event_id: str):
    return await get_event_explanation(event_id)


@router.get("/{trace_id}", response_model=list[AuditEvent])
async def trace_events(trace_id: str):
    return await get_trace_events(trace_id)

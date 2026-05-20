from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import get_recent_events, get_trace_events
from ..models import AuditEvent


router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[AuditEvent])
async def recent_events(limit: int = Query(default=100, ge=1, le=1000)):
    return await get_recent_events(limit=limit)


@router.get("/{trace_id}", response_model=list[AuditEvent])
async def trace_events(trace_id: str):
    return await get_trace_events(trace_id)

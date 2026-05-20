from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import get_session_events, get_sessions
from ..models import AuditEvent, SessionSummary


router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("", response_model=list[SessionSummary])
async def recent_sessions(limit: int = Query(default=50, ge=1, le=500)):
    return await get_sessions(limit=limit)


@router.get("/{session_id}", response_model=list[AuditEvent])
async def session_events(session_id: str):
    return await get_session_events(session_id)

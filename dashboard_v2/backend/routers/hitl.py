from __future__ import annotations

from fastapi import APIRouter

from ..db import get_hitl_events
from ..models import AuditEvent


router = APIRouter(prefix="/api/hitl", tags=["hitl"])


@router.get("", response_model=list[AuditEvent])
async def hitl_queue():
    return await get_hitl_events()

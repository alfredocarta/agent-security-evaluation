from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import get_metrics
from ..models import KPIMetrics


router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("", response_model=KPIMetrics)
async def metrics(agent_id: str | None = Query(default=None)):
    return await get_metrics(agent_id=agent_id)

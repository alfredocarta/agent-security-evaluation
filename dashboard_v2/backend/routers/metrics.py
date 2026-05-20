from __future__ import annotations

from fastapi import APIRouter

from ..db import get_metrics
from ..models import KPIMetrics


router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("", response_model=KPIMetrics)
async def metrics():
    return await get_metrics()

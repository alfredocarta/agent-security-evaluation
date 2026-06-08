from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import get_metrics, get_overview_charts, get_provenance
from ..models import KPIMetrics, OverviewCharts


router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("", response_model=KPIMetrics)
async def metrics(agent_id: str | None = Query(default=None)):
    return await get_metrics(agent_id=agent_id)


@router.get("/provenance")
async def provenance():
    return await get_provenance()


@router.get("/charts", response_model=OverviewCharts)
async def charts(
    window: str = Query(default="24h"),
    agent_id: str | None = Query(default=None),
):
    return await get_overview_charts(window=window, agent_id=agent_id)

from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import get_agents


router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("", response_model=list[str])
async def agents(show_eval: bool = Query(default=False)):
    return await get_agents(show_eval=show_eval)

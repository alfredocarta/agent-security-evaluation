from __future__ import annotations

from fastapi import APIRouter

from ..db import get_agents


router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("", response_model=list[str])
async def agents():
    return await get_agents()

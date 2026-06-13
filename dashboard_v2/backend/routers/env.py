from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..db import get_env_info, set_active_env

router = APIRouter(prefix="/api/env", tags=["env"])


class EnvSwitch(BaseModel):
    env: str


@router.get("")
async def current_env():
    return get_env_info()


@router.post("/switch")
async def switch_env(body: EnvSwitch):
    if not set_active_env(body.env):
        raise HTTPException(
            status_code=400,
            detail=f"Unknown environment: {body.env!r}. Valid values: production, test",
        )
    return get_env_info()
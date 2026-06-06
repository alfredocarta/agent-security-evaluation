from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import date as Date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query

from ..db import (
    ALLOW_OUTCOMES,
    BLOCK_OUTCOMES,
    HITL_DECISION_OUTCOMES,
    HITL_OUTCOMES,
    _extract_stage,
    _has_audit_schema,
    _has_hermes_trace_schema,
    get_db_path,
)


router = APIRouter(prefix="/api/report", tags=["report"])


BLOCK_VERDICTS = {"BLOCK", "BLOCKED", "DENY"} | BLOCK_OUTCOMES
ALLOW_VERDICTS = {"ALLOW", "ALLOWED"} | ALLOW_OUTCOMES
HITL_VERDICTS = {"HITL", "HITL_REQUESTED"} | HITL_OUTCOMES
HITL_DECISION_VERDICTS = {"HITL_APPROVED", "HITL_REJECTED"} | HITL_DECISION_OUTCOMES


def _yesterday() -> str:
    return (Date.today() - timedelta(days=1)).isoformat()


def _parse_day(value: str | None) -> str:
    raw = value or _yesterday()
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError:
        # Keep the endpoint forgiving for the date picker / manual API usage.
        return _yesterday()


def _bounds(day: str) -> tuple[str, str]:
    start = datetime.strptime(day, "%Y-%m-%d")
    end = start + timedelta(days=1)
    return start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")


def _session_id_for_audit_row(row: dict[str, Any]) -> str:
    agent = row.get("agent_id") or "unknown-agent"
    key = (row.get("prev_hash") or row.get("hash") or "")[:12]
    return f"{agent}-group-{key or 'unknown'}"


def _session_id_for_hermes_row(row: dict[str, Any]) -> str:
    agent = row.get("agent_id") or "hermes"
    if row.get("session_id"):
        return f"{agent}-session-{row['session_id']}"
    if row.get("task_id"):
        return f"{agent}-task-{row['task_id']}"
    return f"{agent}-trace-{row.get('trace_id') or (row.get('id') or '')[:12] or 'unknown'}"


def _empty_report(day: str) -> dict[str, Any]:
    return {
        "date": day,
        "total_calls": 0,
        "blocked": 0,
        "allowed": 0,
        "hitl_decided": 0,
        "top_blocking_stage": None,
        "top_agent": None,
        "blocked_sessions": [],
    }


@router.get("/daily")
async def daily_report(date: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")):
    day = _parse_day(date)
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return _empty_report(day)

    start, end = _bounds(day)
    total_calls = 0
    blocked = 0
    allowed = 0
    hitl_decided = 0
    stage_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    blocked_sessions: dict[str, str] = {}

    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.row_factory = sqlite3.Row

        audit_rows = [dict(row) for row in conn.execute(
            "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
            "FROM audit_trail WHERE timestamp >= ? AND timestamp < ?",
            (start, end),
        ).fetchall()]

        for row in audit_rows:
            outcome = row.get("outcome") or ""
            agent = row.get("agent_id") or "unknown-agent"
            agent_counts[agent] += 1
            if outcome == "INTERCEPTOR_START":
                total_calls += 1
            if outcome in BLOCK_OUTCOMES:
                blocked += 1
                stage = _extract_stage(outcome, row.get("reason")) or "Unknown"
                stage_counts[stage] += 1
                sid = _session_id_for_audit_row(row)
                blocked_sessions.setdefault(sid, row.get("reason") or outcome)
            elif outcome in ALLOW_OUTCOMES:
                allowed += 1
            elif outcome in HITL_DECISION_OUTCOMES:
                hitl_decided += 1
            elif outcome in HITL_OUTCOMES:
                # Requested-but-not-yet-decided; counted in agent activity, not decisions.
                pass

        if _has_hermes_trace_schema(db_path):
            hermes_rows = [dict(row) for row in conn.execute(
                "SELECT id, timestamp, agent_id, session_id, task_id, trace_id, verdict, outcome, reason, stage "
                "FROM hermes_tool_traces WHERE timestamp >= ? AND timestamp < ?",
                (start, end),
            ).fetchall()]

            total_calls += len(hermes_rows)
            for row in hermes_rows:
                outcome = (row.get("outcome") or row.get("verdict") or "").upper()
                agent = row.get("agent_id") or "hermes"
                agent_counts[agent] += 1
                if outcome in BLOCK_VERDICTS:
                    blocked += 1
                    stage = row.get("stage") or _extract_stage(row.get("outcome") or "", row.get("reason")) or "Unknown"
                    stage_counts[stage] += 1
                    sid = _session_id_for_hermes_row(row)
                    blocked_sessions.setdefault(sid, row.get("reason") or row.get("outcome") or row.get("verdict") or "blocked")
                elif outcome in ALLOW_VERDICTS:
                    allowed += 1
                elif outcome in HITL_DECISION_VERDICTS:
                    hitl_decided += 1
                elif outcome in HITL_VERDICTS:
                    # Requested-but-not-yet-decided; counted in agent activity, not decisions.
                    pass

    return {
        "date": day,
        "total_calls": total_calls,
        "blocked": blocked,
        "allowed": allowed,
        "hitl_decided": hitl_decided,
        "top_blocking_stage": stage_counts.most_common(1)[0][0] if stage_counts else None,
        "top_agent": agent_counts.most_common(1)[0][0] if agent_counts else None,
        "blocked_sessions": [
            {"session_id": session_id, "reason": reason}
            for session_id, reason in blocked_sessions.items()
        ],
    }

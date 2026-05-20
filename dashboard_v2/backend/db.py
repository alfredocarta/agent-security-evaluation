from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from .models import AuditEvent, KPIMetrics, SessionSummary


ASF_ROOT = Path(os.environ.get("ASF_ROOT", "/Users/alfredo/Projects/agent-security-framework"))
REQUESTED_DB_PATH = Path(os.environ.get("ASF_AUDIT_DB", str(ASF_ROOT / "audit.db")))
FALLBACK_DB_PATH = ASF_ROOT / "asf_local.db"

ALLOW_OUTCOMES = {"ALLOWED"}
BLOCK_OUTCOMES = {"BLOCKED", "KILL_SWITCH", "OUTPUT_BLOCK"}
HITL_OUTCOMES = {"HITL_REQUESTED"}
TERMINAL_OUTCOMES = ALLOW_OUTCOMES | BLOCK_OUTCOMES | HITL_OUTCOMES

ARTICLE_BY_OUTCOME = {
    "KILL_SWITCH": ("Art. 9", "Risk management"),
    "BLOCKED": ("Art. 9", "Risk management"),
    "OUTPUT_BLOCK": ("Art. 12", "Record keeping"),
    "HITL_REQUESTED": ("Art. 14", "Human oversight"),
    "ALLOWED": ("Art. 15", "Accuracy"),
}

STAGE_BY_OUTCOME = {
    "INTERCEPTOR_START": "L1.5",
    "VALIDATOR_START": "L1.5",
    "SIGNATURE_OK": "L1.5",
    "STAGE_1_START": "Stage 1 Regex",
    "STAGE_1_PASS": "Stage 1 Regex",
    "STAGE_2_START": "Stage 2 TF-IDF + Random Forest",
    "STAGE_2_UNCERTAIN": "Stage 2 TF-IDF + Random Forest",
    "STAGE_2.5_START": "Stage 2.5 DeBERTa",
    "STAGE_2.5_UNCERTAIN": "Stage 2.5 DeBERTa",
    "STAGE_2.5B_START": "Stage 2.5b Prompt Guard",
    "STAGE_2.5B_UNAVAILABLE": "Stage 2.5b Prompt Guard",
    "STAGE_3_START": "Stage 3 LLM",
    "STAGE_3_DOUBLE_CHECK": "Stage 3 LLM",
    "KILL_SWITCH": "Blocking Gate",
    "BLOCKED": "Blocking Gate",
    "ALLOWED": "Final Verdict",
    "HITL_REQUESTED": "Human Oversight",
    "OUTPUT_BLOCK": "Output Guard",
}


def _has_audit_schema(path: Path) -> bool:
    if not path.exists():
        return False
    import sqlite3

    try:
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_trail'"
            ).fetchone()
            return row is not None
    except sqlite3.Error:
        return False


def get_db_path() -> Path:
    if _has_audit_schema(REQUESTED_DB_PATH):
        return REQUESTED_DB_PATH
    return FALLBACK_DB_PATH


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _sessionize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = sorted(rows, key=lambda row: row.get("timestamp") or "")
    last_agent = ""
    last_ts: datetime | None = None
    counter = 0
    current_session = ""

    for row in rows:
        agent_id = row.get("agent_id") or "unknown-agent"
        ts = _parse_timestamp(row.get("timestamp"))
        same_session = (
            bool(current_session)
            and agent_id == last_agent
            and ts is not None
            and last_ts is not None
            and ts - last_ts < timedelta(seconds=30)
        )
        if not same_session:
            counter += 1
            current_session = f"{agent_id}-session-{counter:04d}"
        row["session_id"] = current_session
        row["trace_id"] = None
        last_agent = agent_id
        last_ts = ts
    return rows


def _extract_confidence(reason: str | None) -> float | None:
    if not reason:
        return None
    match = re.search(r"confidence[:\s]+([0-9.]+)", reason, re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _infer_verdict(outcome: str) -> str:
    if outcome in ALLOW_OUTCOMES:
        return "ALLOW"
    if outcome in BLOCK_OUTCOMES:
        return "DENY"
    if outcome in HITL_OUTCOMES:
        return "HITL"
    if "UNCERTAIN" in outcome:
        return "UNCERTAIN"
    return outcome


def _infer_security_model(outcome: str, reason: str | None) -> str:
    text = f"{outcome} {reason or ''}".lower()
    if "stage 2.5b" in text or "prompt guard" in text:
        return "Prompt Guard / ProtectAI fallback"
    if "deberta" in text or "stage_2.5" in text:
        return "DeBERTa Stage 2.5"
    if "gemma" in text or "stage 3" in text or "llm" in text:
        return "Stage 3 Gemma 2B"
    if "stage 2" in text or "classifier" in text:
        return "TF-IDF + Random Forest"
    if "stage 1" in text or "regex" in text:
        return "Stage 1 Regex"
    return "L1.5 / policy gate"


def _normalize_event(row: dict[str, Any]) -> AuditEvent:
    article, control = ARTICLE_BY_OUTCOME.get(row.get("outcome") or "", (None, None))
    outcome = row.get("outcome") or ""
    reason = row.get("reason") or ""
    return AuditEvent(
        event_id=row.get("hash") or "",
        timestamp=str(row.get("timestamp") or ""),
        agent_id=row.get("agent_id") or "",
        action=row.get("action") or "",
        outcome=outcome,
        reason=reason,
        trace_id=row.get("trace_id"),
        session_id=row.get("session_id"),
        latency_ms=None,
        confidence=_extract_confidence(reason),
        eu_ai_act_article=article,
        eu_ai_act_control=control,
        tool_name=row.get("action") or None,
        stage=STAGE_BY_OUTCOME.get(outcome, "Unknown"),
        verdict=_infer_verdict(outcome),
        agent_model="not recorded in SQLite audit trail",
        security_model=_infer_security_model(outcome, reason),
        prev_hash=row.get("prev_hash"),
    )


async def _fetch_rows() -> list[dict[str, Any]]:
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
            "FROM audit_trail ORDER BY timestamp ASC"
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    return _sessionize(rows)


async def get_recent_events(limit: int = 100) -> list[AuditEvent]:
    rows = await _fetch_rows()
    return [_normalize_event(row) for row in rows[-limit:]][::-1]


async def get_session_events(session_id: str) -> list[AuditEvent]:
    rows = await _fetch_rows()
    return [_normalize_event(row) for row in rows if row.get("session_id") == session_id]


async def get_trace_events(trace_id: str) -> list[AuditEvent]:
    rows = await _fetch_rows()
    return [_normalize_event(row) for row in rows if row.get("trace_id") == trace_id]


async def get_sessions(limit: int = 50) -> list[SessionSummary]:
    rows = await _fetch_rows()
    sessions: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        sessions.setdefault(row["session_id"], []).append(row)

    summaries = []
    for session_id, group in sessions.items():
        ordered = sorted(group, key=lambda row: row.get("timestamp") or "")
        start = _parse_timestamp(ordered[0].get("timestamp"))
        end = _parse_timestamp(ordered[-1].get("timestamp"))
        duration_ms = int((end - start).total_seconds() * 1000) if start and end else 0
        outcomes = [row.get("outcome") or "" for row in ordered]
        summaries.append(SessionSummary(
            session_id=session_id,
            agent_id=ordered[0].get("agent_id") or "",
            start_time=str(ordered[0].get("timestamp") or ""),
            end_time=str(ordered[-1].get("timestamp") or ""),
            total_events=len(ordered),
            blocked_count=sum(1 for outcome in outcomes if outcome in BLOCK_OUTCOMES),
            allowed_count=sum(1 for outcome in outcomes if outcome in ALLOW_OUTCOMES),
            hitl_count=sum(1 for outcome in outcomes if outcome in HITL_OUTCOMES),
            duration_ms=duration_ms,
        ))
    summaries.sort(key=lambda item: item.start_time, reverse=True)
    return summaries[:limit]


async def get_metrics() -> KPIMetrics:
    rows = await _fetch_rows()
    outcomes = [row.get("outcome") or "" for row in rows]
    blocked = sum(1 for outcome in outcomes if outcome in BLOCK_OUTCOMES)
    allowed = sum(1 for outcome in outcomes if outcome in ALLOW_OUTCOMES)
    hitl = sum(1 for outcome in outcomes if outcome in HITL_OUTCOMES)
    terminal = blocked + allowed + hitl
    now = datetime.utcnow()
    last_24h = 0
    for row in rows:
        ts = _parse_timestamp(row.get("timestamp"))
        if ts and now - ts <= timedelta(hours=24):
            last_24h += 1

    return KPIMetrics(
        total_events=len(rows),
        detection_rate=(blocked / terminal) if terminal else 0.0,
        false_positive_rate=0.0,
        blocked_count=blocked,
        allowed_count=allowed,
        hitl_count=hitl,
        avg_latency_ms=0.0,
        events_last_24h=last_24h,
    )

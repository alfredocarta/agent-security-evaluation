from __future__ import annotations

import os
import re
import sqlite3
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from .models import (
    AuditEvent,
    EventExplanation,
    KPIMetrics,
    PipelineStage,
    SessionSummary,
    StageBucket,
    ReasonBucket,
    BlockCatalogBucket,
    BlockCatalogDetail,
    LatencyBucket,
    LatencyDistribution,
    TimelinePoint,
    AgentPosture,
    OverviewCharts,
)


ASF_ROOT = Path(os.environ.get("ASF_ROOT", "/Users/alfredo/Projects/agent-security-framework"))
REQUESTED_DB_PATH = Path(os.environ.get("ASF_AUDIT_DB", str(ASF_ROOT / "audit.db")))
FALLBACK_DB_PATH = ASF_ROOT / "asf_local.db"
CACHE_PATH = Path(__file__).resolve().parents[1] / "dashboard_cache.json"
_RUNTIME_CACHE: dict[tuple[Any, ...], tuple[float, Any]] = {}
_INDEXED_DB_PATHS: set[str] = set()


def _cache_get(key: tuple[Any, ...]) -> Any | None:
    item = _RUNTIME_CACHE.get(key)
    if not item:
        return None
    expires_at, value = item
    if expires_at < time.monotonic():
        _RUNTIME_CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: tuple[Any, ...], value: Any, ttl: float = 10.0) -> Any:
    _RUNTIME_CACHE[key] = (time.monotonic() + ttl, value)
    return value


def invalidate_cache() -> None:
    """Drop dashboard aggregate caches after audit_trail mutations.

    Call this after any code path deletes rows from audit_trail so KPI totals and
    dashboard-wide aggregates cannot outlive the retained audit data.
    """
    _RUNTIME_CACHE.clear()
    try:
        CACHE_PATH.unlink(missing_ok=True)
    except OSError:
        # Best effort: the short-lived runtime cache is still cleared, and the
        # next get_metrics call can detect and ignore stale on-disk cache data.
        pass


def _ensure_query_indexes(conn: sqlite3.Connection, db_path: Path) -> None:
    # These make drill-down pagination use indexed lookups instead of sorting/scanning
    # the multi-million-row audit table. CREATE INDEX IF NOT EXISTS is cheap once built.
    key = str(db_path)
    if key in _INDEXED_DB_PATHS:
        return
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_timestamp_desc ON audit_trail(timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_outcome_timestamp ON audit_trail(outcome, timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_agent_timestamp ON audit_trail(agent_id, timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_prev_hash ON audit_trail(prev_hash)")
    # hash index: enables prefix-LIKE lookups in get_session_events without full table scans
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_hash ON audit_trail(hash)")
    if _has_hermes_trace_schema(db_path):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hermes_tool_traces_session_ts ON hermes_tool_traces(session_id, timestamp ASC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hermes_tool_traces_trace_ts ON hermes_tool_traces(trace_id, timestamp ASC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hermes_tool_traces_id ON hermes_tool_traces(id)")
    if _has_claude_trace_schema(db_path):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claude_tool_traces_audit_hash ON claude_tool_traces(audit_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claude_tool_traces_tool_call ON claude_tool_traces(tool_call_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claude_tool_traces_session_ts ON claude_tool_traces(session_id, timestamp ASC)")
    _INDEXED_DB_PATHS.add(key)


def _load_dashboard_cache() -> dict[str, Any]:
    try:
        return json.loads(CACHE_PATH.read_text())
    except Exception:
        return {}

ALLOW_OUTCOMES = {"ALLOWED", "HEURISTIC_CLEAR"}
BLOCK_OUTCOMES = {"BLOCKED", "KILL_SWITCH", "OUTPUT_BLOCK", "L1.5_BLOCK", "ONNX_BLOCK"}
HITL_OUTCOMES = {"HITL_REQUESTED"}
HITL_DECISION_OUTCOMES = {"HITL_APPROVED", "HITL_REJECTED"}
TERMINAL_OUTCOMES = ALLOW_OUTCOMES | BLOCK_OUTCOMES | HITL_OUTCOMES | HITL_DECISION_OUTCOMES

EVAL_TOOL_AGENTS = {
    "pyrit-crescendo-eval-agent",
    "pyrit-xpia-eval-agent",
    "garak-debug",
    "promptfoo-eval-agent",
    "test-agent",
    # Bulk benchmark / eval agents — millions of rows, drown out live agents in the timeline
    "benchmark-agent",
    "bench_agent",
    "bench-agent",
    "test",
    "asf-eval-agent",
    "smolagents-eval-agent",
    "sql-agent-asf-eval-agent",
    "sanity-agent",
    # Multi-agent scenario / unit-test agents written to the audit DB by the framework
    # test suite (tests/conftest.py). They are not real traffic and must not pollute
    # per-agent charts, sessions or KPIs. Root fix is test isolation (temp DATABASE_URL).
    "billing_agent",
    "analytics_agent",
    "db_agent",
    "researcher_agent",
    "triage_agent",
}

NOT_RECORDED_MODEL = "not recorded"

AGENT_METADATA: dict[str, tuple[str, str | None]] = {
    "hermes-live-agent": ("Hermes Agent", None),
    "claude-code-agent": ("Claude Code (MCP)", "claude-sonnet-4-6 via MCP"),
}

_ALL_OUTCOMES = object()  # sentinel: every event counts as evidence
_BENCHMARK_EVENTS = object()  # sentinel: events generated by benchmark agents

ARTICLE_OUTCOMES: dict[str, Any] = {
    "Art. 9": {"KILL_SWITCH", "BLOCKED", "L1.5_BLOCK", "ONNX_BLOCK"},
    "Art. 10": _BENCHMARK_EVENTS,
    "Art. 12": _ALL_OUTCOMES,   # entire audit trail is Art. 12 evidence
    "Art. 13": {"ALLOWED", "BLOCKED", "KILL_SWITCH", "OUTPUT_BLOCK", "L1.5_BLOCK", "ONNX_BLOCK"},
    "Art. 14": {"HITL_REQUESTED"},
    "Art. 15": {"ALLOWED"},
    "Art. 17": _ALL_OUTCOMES,
}

ARTICLE_BY_OUTCOME = {
    "HEURISTIC_CLEAR": ("Art. 15", "Accuracy"),
    "KILL_SWITCH": ("Art. 9", "Risk management"),
    "BLOCKED":    ("Art. 9", "Risk management"),
    "L1.5_BLOCK": ("Art. 9", "Risk management"),
    "ONNX_BLOCK": ("Art. 9", "Risk management"),
    "OUTPUT_BLOCK": ("Art. 12", "Record keeping"),
    "HITL_REQUESTED": ("Art. 14", "Human oversight"),
    "HITL_APPROVED": ("Art. 14", "Human oversight"),
    "HITL_REJECTED": ("Art. 14", "Human oversight"),
    "ALLOWED": ("Art. 15", "Accuracy"),
}

INTERMEDIATE_STAGE: dict[str, str] = {
    "INTERCEPTOR_START": "L1.5 fast-path",
    "VALIDATOR_START": "L1.5 fast-path",
    "SIGNATURE_OK": "L1.5 fast-path",
    "STAGE_1_START": "Stage 1",
    "STAGE_1_PASS": "Stage 1",
    "STAGE_2_START": "Stage 2",
    "STAGE_2_UNCERTAIN": "Stage 2",
    "STAGE_2_SOFT_ESCALATE": "Stage 2",
    "STAGE_2.5_START": "Stage 2.5 DeBERTa",
    "STAGE_2.5_UNCERTAIN": "Stage 2.5 DeBERTa",
    "STAGE_2.5_SKIPPED": "Stage 2.5 DeBERTa",
    "STAGE_2.5A_VERDICT": "Stage 2.5 DeBERTa",
    "STAGE_2.5_UNCONFIRMED": "Stage 2.5 DeBERTa",
    "STAGE_2.5_ERROR": "Stage 2.5 DeBERTa",
    "STAGE_2.5B_START": "Stage 2.5b Prompt Guard",
    "STAGE_2.5B_VERDICT": "Stage 2.5b Prompt Guard",
    "STAGE_2.5B_UNAVAILABLE": "Stage 2.5b Prompt Guard",
    "STAGE_2.5B_ERROR": "Stage 2.5b Prompt Guard",
    "STAGE_3_START": "Stage 3 LLM",
    "STAGE_3_DOUBLE_CHECK": "Stage 3 LLM",
}


def _has_audit_schema(path: Path) -> bool:
    if not path.exists():
        return False

    try:
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_trail'"
            ).fetchone()
            return row is not None
    except sqlite3.Error:
        return False


def _has_hermes_trace_schema(path: Path) -> bool:
    if not path.exists():
        return False

    try:
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hermes_tool_traces'"
            ).fetchone()
            return row is not None
    except sqlite3.Error:
        return False


def _has_claude_trace_schema(path: Path) -> bool:
    if not path.exists():
        return False

    try:
        with sqlite3.connect(path) as conn:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='claude_tool_traces'"
            ).fetchone()
            return row is not None
    except sqlite3.Error:
        return False


def get_db_path() -> Path:
    if _has_audit_schema(REQUESTED_DB_PATH):
        return REQUESTED_DB_PATH
    return FALLBACK_DB_PATH


async def init_db() -> None:
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_action "
            "ON audit_trail(action)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_timestamp "
            "ON audit_trail(timestamp DESC)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_outcome "
            "ON audit_trail(outcome)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_hash "
            "ON audit_trail(hash)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_prev_hash "
            "ON audit_trail(prev_hash)"
        )
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_hitl_decisions ("
            "event_id TEXT PRIMARY KEY, "
            "decision TEXT NOT NULL CHECK(decision IN ('approve', 'reject')), "
            "decided_at TEXT NOT NULL, "
            "reviewer TEXT, "
            "note TEXT"
            ")"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hitl_decisions_event_id "
            "ON dashboard_hitl_decisions(event_id)"
        )
        await conn.commit()


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


def _dashboard_cache_is_stale(db_path: Path, cache: dict[str, Any]) -> bool:
    """Return True when on-disk KPI cache is more than 24h behind audit_trail."""
    cache_max_ts = _parse_timestamp(cache.get("max_interceptor_ts"))
    if cache_max_ts is None or not _has_audit_schema(db_path):
        return False

    try:
        with sqlite3.connect(db_path, timeout=2) as conn:
            row = conn.execute(
                "SELECT timestamp FROM audit_trail "
                "WHERE timestamp IS NOT NULL "
                "ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
    except sqlite3.Error:
        return False

    actual_latest_ts = _parse_timestamp(row[0]) if row else None
    if actual_latest_ts is None:
        return False
    try:
        return actual_latest_ts - cache_max_ts > timedelta(hours=24)
    except TypeError:
        return False


def _sessionize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group events into sessions using real identifiers when available, else time-gap heuristic.
    
    Session key priority:
    - Claude events (claude_tool_traces): session_id (stable UUID per conversation)
    - Hermes events (hermes_tool_traces): session_id if non-empty, else task_id
    - Fallback: 30-second time-gap heuristic for events with no real identifier
    
    Returns rows with session_id assigned for downstream grouping.
    """
    rows = sorted(rows, key=lambda row: row.get("timestamp") or "")
    last_agent = ""
    last_ts: datetime | None = None
    counter = 0
    current_session = ""
    last_real_session_key: str | None = None

    for row in rows:
        agent_id = row.get("agent_id") or "unknown-agent"
        ts = _parse_timestamp(row.get("timestamp"))
        
        # Check for real session identifiers
        real_session_id = row.get("session_id")
        task_id = row.get("task_id")
        
        # Determine session key: prefer real identifiers, fall back to time-gap
        if real_session_id:
            # Real session_id present (e.g., Claude UUID or Hermes session_id)
            session_key = f"{agent_id}-session-{real_session_id}"
            last_real_session_key = session_key
            row["session_id"] = session_key
            row["trace_id"] = None
            last_agent = agent_id
            last_ts = ts
            continue
        elif task_id:
            # Hermes task_id as session identifier
            session_key = f"{agent_id}-task-{task_id}"
            last_real_session_key = session_key
            row["session_id"] = session_key
            row["trace_id"] = None
            last_agent = agent_id
            last_ts = ts
            continue
        
        # No real identifier: fall back to 30-second time-gap heuristic
        same_session = (
            bool(current_session)
            and agent_id == last_agent
            and ts is not None
            and last_ts is not None
            and ts - last_ts < timedelta(seconds=30)
        )
        if not same_session:
            counter += 1
            current_session = f"{agent_id}-group-{counter:04d}"
        row["session_id"] = current_session
        row["trace_id"] = None
        last_agent = agent_id
        last_ts = ts
    return rows


def _enrich_with_chain_data(rows: list[dict[str, Any]]) -> None:
    """Follow hash chains to assign trace_ids and compute latency_ms on terminal events."""
    by_prev_hash: dict[str, dict[str, Any]] = {}
    for row in rows:
        ph = row.get("prev_hash")
        if ph:
            by_prev_hash[ph] = row

    for row in rows:
        if row.get("outcome") != "INTERCEPTOR_START":
            continue
        start_ts = _parse_timestamp(row.get("timestamp"))
        trace_id = f"trace-{(row.get('hash') or '')[:12]}"
        row["trace_id"] = trace_id

        current = row
        for _ in range(30):
            h = current.get("hash")
            if not h:
                break
            nxt = by_prev_hash.get(h)
            if not nxt:
                break
            nxt["trace_id"] = trace_id
            if nxt.get("outcome") in TERMINAL_OUTCOMES:
                if start_ts:
                    end_ts = _parse_timestamp(nxt.get("timestamp"))
                    if end_ts and end_ts >= start_ts:
                        nxt["latency_ms"] = int((end_ts - start_ts).total_seconds() * 1000)
                break
            current = nxt


def _extract_confidence(reason: str | None) -> float | None:
    if not reason:
        return None
    patterns = (
        r"confidence[:\s=]+([0-9.]+)",
        r"score[:\s=]+([0-9.]+)",
        r"l1\.5\s*=\s*([0-9.]+)",
        r"onnx[^0-9]*(?:score|confidence)?[^0-9]*([0-9]+(?:\.[0-9]+)?)",
    )
    for pattern in patterns:
        match = re.search(pattern, reason, re.IGNORECASE)
        if not match:
            continue
        try:
            return float(match.group(1))
        except ValueError:
            continue
    return None


def _infer_verdict(outcome: str) -> str:
    if outcome in ALLOW_OUTCOMES or outcome == "HITL_APPROVED":
        return "ALLOW"
    if outcome in BLOCK_OUTCOMES or outcome == "HITL_REJECTED":
        return "DENY"
    if outcome in HITL_OUTCOMES:
        return "HITL"
    if "UNCERTAIN" in outcome:
        return "UNCERTAIN"
    return outcome


def _extract_stage(outcome: str, reason: str | None) -> str:
    r = (reason or "").lower()
    if outcome == "STAGE_3_START" and ("onnx" in r or "prompt guard" in r):
        return "Stage 3 ONNX Prompt Guard" if "prompt guard" in r else "Stage 3 ONNX"
    if outcome in INTERMEDIATE_STAGE:
        return INTERMEDIATE_STAGE[outcome]
    if outcome == "OUTPUT_BLOCK":
        return "Output Guard"
    if "asf check failed" in r or "no module named" in r:
        return "ASF unavailable"
    if "heuristic" in r or "fast-path" in r:
        return "L1.5 fast-path"
    if "stage 2.5b" in r or ("prompt guard" in r and "stage 2.5" in r):
        return "Stage 2.5b Prompt Guard"
    if "deberta" in r or "stage 2.5" in r:
        return "Stage 2.5 DeBERTa"
    if "onnx" in r and "prompt guard" in r:
        return "Stage 3 ONNX Prompt Guard"
    if "onnx" in r:
        return "Stage 3 ONNX"
    if "prompt guard" in r:
        return "Stage 3 ONNX Prompt Guard"
    if "stage 3" in r or "llm" in r or "double-check" in r or "double_check" in r:
        return "Stage 3 LLM"
    if "stage 2" in r or "classifier confidence" in r:
        return "Stage 2"
    if "stage 1" in r or "regex" in r or "pattern detected" in r:
        return "Stage 1"
    if ("not in permissions" in r or "suspended" in r or "canary" in r or "l1.5" in r
            or "not authorized" in r or "access denied" in r or "allowlist" in r):
        return "L1.5 fast-path"
    return INTERMEDIATE_STAGE.get(outcome, "Unknown")


def _infer_security_model(outcome: str, reason: str | None) -> str:
    text = f"{outcome} {reason or ''}".lower()
    if "asf check failed" in text or "no module named" in text:
        return "Fail-open / ASF dependency unavailable"
    if "onnx" in text and "prompt guard" in text:
        return "Stage 3 ONNX Prompt Guard"
    if "onnx" in text:
        return "Stage 3 ONNX"
    if "prompt guard" in text:
        return "Stage 3 ONNX Prompt Guard"
    if "stage 2.5b" in text:
        return "ProtectAI fallback"
    if "deberta" in text or "stage_2.5" in text or "stage 2.5" in text:
        return "DeBERTa Stage 2.5"
    if "gemma" in text:
        return "Stage 3 Gemma 2B"
    if "stage 3" in text or "llm" in text:
        return "Stage 3 LLM"
    if "stage 2" in text or "classifier" in text:
        return "TF-IDF + Random Forest"
    if "stage 1" in text or "regex" in text:
        return "Stage 1 Regex"
    return "L1.5 / policy gate"


def _terminal_trace_ids(rows: list[dict[str, Any]], outcomes: set[str] | None = None) -> set[str]:
    trace_ids: set[str] = set()
    for row in rows:
        outcome = row.get("outcome") or ""
        if outcome not in TERMINAL_OUTCOMES:
            continue
        if outcomes is not None and outcome not in outcomes:
            continue
        trace_id = row.get("trace_id")
        if trace_id:
            trace_ids.add(trace_id)
    return trace_ids


def _normalize_event(row: dict[str, Any]) -> AuditEvent:
    outcome = row.get("outcome") or ""
    reason = row.get("reason") or ""
    article, control = ARTICLE_BY_OUTCOME.get(outcome, (None, None))
    _, model = _agent_metadata(row.get("agent_id") or "", agent_model=row.get("agent_model"))
    return AuditEvent(
        event_id=row.get("hash") or "",
        timestamp=str(row.get("timestamp") or ""),
        agent_id=row.get("agent_id") or "",
        action=row.get("action") or "",
        outcome=outcome,
        reason=reason,
        trace_id=row.get("trace_id"),
        session_id=row.get("session_id"),
        latency_ms=row.get("latency_ms"),
        confidence=_extract_confidence(reason),
        eu_ai_act_article=article,
        eu_ai_act_control=control,
        tool_name=row.get("action") or None,
        stage=_extract_stage(outcome, reason),
        verdict=_infer_verdict(outcome),
        agent_model=model,
        security_model=_infer_security_model(outcome, reason),
        prev_hash=row.get("prev_hash"),
    )


def _outcome_from_verdict(verdict: str) -> str:
    verdict = (verdict or "").upper()
    if verdict == "ALLOW":
        return "ALLOWED"
    if verdict == "DENY":
        return "BLOCKED"
    if verdict == "HITL":
        return "HITL_REQUESTED"
    return verdict or "ALLOWED"


def _recorded_model(agent_model: str | None) -> str:
    model = (agent_model or "").strip()
    return model or NOT_RECORDED_MODEL


def _agent_metadata(agent_id: str, agent_type: str | None = None, agent_model: str | None = None) -> tuple[str | None, str | None]:
    agent_id = agent_id or ""
    if agent_id in AGENT_METADATA:
        framework, default_model = AGENT_METADATA[agent_id]
        if framework == "Hermes Agent":
            return framework, _recorded_model(agent_model)
        return framework, agent_model or default_model or NOT_RECORDED_MODEL
    if agent_type == "hermes-agent" or "hermes" in agent_id:
        return "Hermes Agent", _recorded_model(agent_model)
    if "smolagents" in agent_id:
        return "ToolCallingAgent (smolagents)", agent_model or "gemma2:2b via Ollama"
    if "autogen" in agent_id:
        return "AutoGen async agent", agent_model or "gemma2:2b via Ollama (AutoGen async)"
    if "sql-agent" in agent_id:
        return "SQL evaluation agent", agent_model or "Rule-based (no LLM)"
    if "asf-eval" in agent_id:
        return "LangGraph ReAct", agent_model or "LangGraph ReAct"
    if "crewai" in agent_id:
        return "CrewAI agent", agent_model or "gemma2:2b via Ollama (CrewAI)"
    if "openhands" in agent_id:
        return "OpenHands CodeAct", agent_model
    if "pyrit" in agent_id:
        return "PyRIT red-team", agent_model
    if "promptfoo" in agent_id:
        return "promptfoo eval", agent_model
    if "claude-code" in agent_id:
        return "Claude Code (MCP)", agent_model or "claude-sonnet-4-6 via MCP"
    return None, agent_model


def _legacy_audit_duration_ms(conn: sqlite3.Connection, terminal_row: dict[str, Any]) -> int:
    """Compute legacy audit-trail tool-call latency by walking back to INTERCEPTOR_START.

    Claude Code MCP events are stored only in audit_trail, not hermes_tool_traces, so
    they do not have tool_duration_ms/asf_latency_ms. The terminal row points back
    through the hash chain; the first INTERCEPTOR_START in that chain is the start of
    the ASF decision for this tool call.
    """
    end_ts = _parse_timestamp(str(terminal_row.get("timestamp") or ""))
    prev_hash = terminal_row.get("prev_hash")
    if end_ts is None or not prev_hash:
        return 0

    current_hash = prev_hash
    for _ in range(40):
        row = conn.execute(
            "SELECT hash, timestamp, outcome, prev_hash FROM audit_trail WHERE hash = ?",
            (current_hash,),
        ).fetchone()
        if row is None:
            break
        row_dict = dict(row)
        if row_dict.get("outcome") == "INTERCEPTOR_START":
            start_ts = _parse_timestamp(str(row_dict.get("timestamp") or ""))
            if start_ts is None:
                return 0
            return max(0, int((end_ts - start_ts).total_seconds() * 1000))
        current_hash = row_dict.get("prev_hash")
        if not current_hash:
            break
    return 0


def _normalize_hermes_trace(row: dict[str, Any]) -> AuditEvent:
    outcome = row.get("outcome") or _outcome_from_verdict(row.get("verdict") or "")
    reason = row.get("reason") or ""
    article, control = ARTICLE_BY_OUTCOME.get(outcome, (None, None))
    framework, model = _agent_metadata(
        row.get("agent_id") or "",
        row.get("agent_type"),
        row.get("agent_model"),
    )
    trace_id = row.get("trace_id") or f"hermes-{(row.get('id') or '')[:12]}"
    session_id = row.get("session_id") or f"{row.get('agent_id') or 'hermes'}-{trace_id}"
    action = row.get("asf_tool_name") or row.get("hermes_tool_name") or ""
    latency = row.get("tool_duration_ms")
    if latency is None:
        latency = row.get("asf_latency_ms")
    return AuditEvent(
        event_id=row.get("id") or trace_id,
        timestamp=str(row.get("timestamp") or ""),
        agent_id=row.get("agent_id") or "",
        action=action,
        outcome=outcome,
        reason=reason,
        trace_id=trace_id,
        session_id=session_id,
        latency_ms=latency,
        confidence=row.get("confidence"),
        eu_ai_act_article=article,
        eu_ai_act_control=control,
        tool_name=row.get("hermes_tool_name") or action or None,
        stage=(None if (row.get("stage") or "").lower() == "unknown" else row.get("stage")) or _extract_stage(outcome, reason),
        verdict=row.get("verdict") or _infer_verdict(outcome),
        agent_model=model,
        security_model=_infer_security_model(outcome, reason),
        prev_hash=row.get("audit_hash"),
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
    rows = _sessionize(rows)
    _enrich_with_chain_data(rows)
    return rows


async def get_recent_events(limit: int = 100) -> list[AuditEvent]:
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []

    events: list[AuditEvent] = []
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
            "FROM audit_trail ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]

        hermes_rows: list[dict[str, Any]] = []
        if _has_hermes_trace_schema(db_path):
            cursor = await conn.execute(
                "SELECT id, timestamp, agent_id, agent_model, session_id, task_id, "
                "tool_call_id, hermes_tool_name, asf_tool_name, verdict, outcome, reason, "
                "stage, confidence, asf_latency_ms, tool_duration_ms, trace_id, audit_hash "
                "FROM hermes_tool_traces ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            hermes_rows = [dict(row) for row in await cursor.fetchall()]

    for row in rows:
        key = (row.get("prev_hash") or row.get("hash") or "")[:12]
        row["trace_id"] = f"trace-{key}"
        row["session_id"] = f"{row.get('agent_id') or 'unknown-agent'}-{key}"
    events.extend(_normalize_event(row) for row in rows)
    events.extend(_normalize_hermes_trace(row) for row in hermes_rows)
    events.sort(key=lambda event: _parse_timestamp(event.timestamp) or datetime.min, reverse=True)
    return events[:limit]


def _stage_from_event(event: AuditEvent) -> PipelineStage:
    return PipelineStage(
        stage=event.stage or "Unknown stage",
        outcome=event.outcome or None,
        verdict=event.verdict or None,
        confidence=event.confidence,
        reason=event.reason or "",
        timestamp=event.timestamp or None,
        latency_ms=event.latency_ms,
        terminal=(event.outcome in TERMINAL_OUTCOMES),
    )


def _extract_named_score(reason: str | None, name: str) -> float | None:
    if not reason:
        return None
    match = re.search(rf"{re.escape(name)}\s*=\s*([0-9.]+)", reason, re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _expand_inferred_pipeline_stages(pipeline_events: list[AuditEvent]) -> list[PipelineStage]:
    stages = [_stage_from_event(ev) for ev in pipeline_events]
    final = next((ev for ev in reversed(pipeline_events) if ev.outcome in TERMINAL_OUTCOMES), None)
    if final is None:
        return stages

    final_outcome = (final.outcome or "").upper()
    final_reason = final.reason or ""
    final_stage = final.stage or ""
    is_onnx_block = final_outcome == "ONNX_BLOCK" or "onnx" in final_reason.lower() or "onnx" in final_stage.lower()
    if not is_onnx_block:
        return stages

    # Older/current fast-path ONNX rows persist only INTERCEPTOR_START -> ONNX_BLOCK.
    # In that branch ONNX is executed before Stage 1/2/2.5, so those stages were
    # bypassed, not passed. Render them explicitly as skipped to avoid implying
    # that absent audit records are successful stage verdicts.
    existing_names = {str(stage.stage or "").lower() for stage in stages}
    l15_score = _extract_named_score(final_reason, "L1.5")
    if l15_score is not None:
        for stage in stages:
            if "l1.5" in str(stage.stage or "").lower() and stage.confidence is None:
                stage.confidence = l15_score
                if stage.reason == "Interceptor invoked":
                    stage.reason = f"Legacy early-ONNX fast-path invoked; recorded L1.5 score: {l15_score:.2f}. ONNX ran before Stage 1/2/2.5 in this historical row."
    timestamp = final.timestamp
    inferred: list[PipelineStage] = []

    def add_if_missing(name: str, outcome: str, reason: str, confidence: float | None = None) -> None:
        if any(name.lower() in existing for existing in existing_names):
            return
        inferred.append(PipelineStage(
            stage=name,
            outcome=outcome,
            verdict="SKIPPED" if outcome == "SKIPPED" else outcome,
            confidence=confidence,
            reason=reason,
            timestamp=timestamp,
            terminal=False,
        ))

    add_if_missing(
        "L1.5",
        "BYPASS_TO_ONNX",
        "L1.5/fast-path selected ONNX as the primary detector for this call."
        + (f" Recorded L1.5 score: {l15_score:.2f}." if l15_score is not None else ""),
        l15_score,
    )
    add_if_missing("Stage 1", "SKIPPED", "Skipped: ONNX primary detector ran before Stage 1 regex analysis in the fast-path branch.")
    add_if_missing("Stage 2", "SKIPPED", "Skipped: ONNX primary detector ran before Stage 2 TF-IDF/RF analysis in the fast-path branch.")
    add_if_missing("Stage 2.5 DeBERTa", "SKIPPED", "Skipped: ONNX primary detector returned a terminal block before DeBERTa was reached.")

    terminal_stage = PipelineStage(
        stage="Stage 3 ONNX",
        outcome=final.outcome or "ONNX_BLOCK",
        verdict="DENY",
        confidence=None,
        reason=final_reason or "Blocked by ONNX Prompt Guard.",
        timestamp=final.timestamp,
        latency_ms=final.latency_ms,
        terminal=True,
    )

    non_terminal_existing = [stage for stage in stages if not stage.terminal and stage.stage != "Stage 3 ONNX"]
    return non_terminal_existing + inferred + [terminal_stage]


def _preview_is_truncated(value: str | None) -> bool:
    return bool(value and "[truncated " in value)


def _single_terminal_pipeline(stages: list[PipelineStage]) -> list[PipelineStage]:
    terminal_indexes = [idx for idx, stage in enumerate(stages) if stage.terminal]
    if len(terminal_indexes) <= 1:
        return stages
    last_terminal = terminal_indexes[-1]
    for idx in terminal_indexes[:-1]:
        stages[idx].terminal = False
    stages[last_terminal].terminal = True
    return stages


def _event_explanation_from_pipeline(
    event_id: str,
    pipeline_events: list[AuditEvent],
    fallback: AuditEvent | None = None,
    context_event: AuditEvent | None = None,
    tool_input: str | None = None,
    tool_output: str | None = None,
) -> EventExplanation:
    if not pipeline_events and fallback is not None:
        pipeline_events = [fallback]
    final = next((ev for ev in reversed(pipeline_events) if ev.outcome in TERMINAL_OUTCOMES), None)
    if final is None and pipeline_events:
        final = pipeline_events[-1]
    if final is None:
        return EventExplanation(
            event_id=event_id,
            final_reason="No explanation data found for this event.",
            pipeline=[PipelineStage(stage="Unknown stage", reason="No explanation data found for this event.", terminal=True)],
        )
    context = context_event or final
    return EventExplanation(
        event_id=event_id,
        trace_id=context.trace_id or final.trace_id,
        session_id=context.session_id or final.session_id,
        tool_name=context.tool_name or context.action or final.tool_name or final.action,
        agent_id=context.agent_id or final.agent_id,
        agent_model=context.agent_model or final.agent_model,
        tool_input=tool_input,
        tool_output=tool_output,
        input_truncated=_preview_is_truncated(tool_input),
        output_truncated=_preview_is_truncated(tool_output),
        final_verdict=final.verdict,
        final_outcome=final.outcome,
        final_reason=final.reason or "No reason recorded.",
        security_model=final.security_model,
        latency_ms=final.latency_ms,
        pipeline=_single_terminal_pipeline(_expand_inferred_pipeline_stages(pipeline_events) or [_stage_from_event(final)]),
    )


def _audit_chain_for_event(conn: sqlite3.Connection, event_id: str) -> list[dict[str, Any]]:
    terminal = conn.execute(
        "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
        "FROM audit_trail WHERE hash = ?",
        (event_id,),
    ).fetchone()
    if terminal is None:
        return []

    rows: list[dict[str, Any]] = [dict(terminal)]
    current_prev = rows[0].get("prev_hash")
    seen = {rows[0].get("hash")}
    for _ in range(40):
        if not current_prev or current_prev in seen:
            break
        row = conn.execute(
            "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
            "FROM audit_trail WHERE hash = ?",
            (current_prev,),
        ).fetchone()
        if row is None:
            break
        row_dict = dict(row)
        rows.append(row_dict)
        seen.add(row_dict.get("hash"))
        if row_dict.get("outcome") == "INTERCEPTOR_START":
            break
        current_prev = row_dict.get("prev_hash")

    rows.reverse()
    _enrich_with_chain_data(rows)
    trace_id = next((row.get("trace_id") for row in rows if row.get("trace_id")), None)
    session_id = f"{rows[-1].get('agent_id') or 'unknown-agent'}-{(trace_id or event_id)[:18]}"
    for row in rows:
        row["trace_id"] = row.get("trace_id") or trace_id or f"trace-{(rows[0].get('hash') or event_id)[:12]}"
        row["session_id"] = session_id
    if rows and rows[-1].get("latency_ms") is None:
        rows[-1]["latency_ms"] = _legacy_audit_duration_ms(conn, rows[-1])
    return rows


def _hermes_rows_for_event(conn: sqlite3.Connection, event_id: str) -> list[dict[str, Any]]:
    select_cols = (
        "SELECT id, timestamp, agent_id, agent_type, agent_model, session_id, task_id, tool_call_id, "
        "hermes_tool_name, asf_tool_name, args_preview, output_preview, verdict, outcome, reason, stage, confidence, "
        "asf_latency_ms, tool_duration_ms, trace_id, audit_hash "
        "FROM hermes_tool_traces "
    )

    # Per-event drill-down must explain the clicked call only. id and audit_hash are unique
    # per persisted Hermes call, while older trace_id values can collide for repeated
    # identical commands. Prefer exact unique matches and do not expand them by trace_id.
    exact = conn.execute(select_cols + "WHERE id = ? OR audit_hash = ? LIMIT 1", (event_id, event_id)).fetchone()
    if exact is not None:
        return [dict(exact)]

    anchor = conn.execute(select_cols + "WHERE trace_id = ? LIMIT 1", (event_id,)).fetchone()
    if anchor is None:
        return []
    anchor_dict = dict(anchor)
    trace_id = anchor_dict.get("trace_id")
    tool_call_id = anchor_dict.get("tool_call_id")
    task_id = anchor_dict.get("task_id")
    session_id = anchor_dict.get("session_id")
    clauses = ["id = ?", "audit_hash = ?"]
    params: list[Any] = [event_id, event_id]
    if trace_id:
        clauses.append("trace_id = ?")
        params.append(trace_id)
    if tool_call_id:
        clauses.append("tool_call_id = ?")
        params.append(tool_call_id)
    # Fall back to task/session only when no per-call identifier exists.
    if not trace_id and not tool_call_id:
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
    rows = [dict(row) for row in conn.execute(
        select_cols + "WHERE " + " OR ".join(clauses) + " ORDER BY timestamp ASC",
        params,
    ).fetchall()]
    return rows or [anchor_dict]


def _audit_chain_for_hermes_trace(conn: sqlite3.Connection, trace_row: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve the per-stage audit_trail chain that backs a Hermes tool-call trace.

    Hermes traces store one summary row per tool call with no per-stage steps. The
    granular pipeline (INTERCEPTOR_START -> ... -> terminal) lives only in audit_trail.
    When the trace carries an audit_hash back-link, follow it directly. Otherwise fall
    back to matching the closest terminal audit_trail row by agent_id, ASF tool name and
    verdict within a short time window, then walk its hash chain.
    """
    audit_hash = (trace_row.get("audit_hash") or "").strip()
    if audit_hash:
        chain = _audit_chain_for_event(conn, audit_hash)
        if len(chain) > 1:
            return chain

    agent_id = trace_row.get("agent_id")
    trace_ts = _parse_timestamp(str(trace_row.get("timestamp") or ""))
    if not agent_id or trace_ts is None:
        return []

    trace_verdict = (trace_row.get("verdict") or _infer_verdict(trace_row.get("outcome") or "")).upper()
    asf_tool = trace_row.get("asf_tool_name") or ""
    window = timedelta(seconds=6)
    lo = (trace_ts - window).strftime("%Y-%m-%d %H:%M:%S")
    hi = (trace_ts + window).strftime("%Y-%m-%d %H:%M:%S.999999")
    placeholders = ",".join("?" for _ in TERMINAL_OUTCOMES)
    terminal_list = list(sorted(TERMINAL_OUTCOMES))
    candidates = [dict(r) for r in conn.execute(
        "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
        "FROM audit_trail WHERE agent_id = ? AND outcome IN (" + placeholders + ") "
        "AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC",
        [agent_id] + terminal_list + [lo, hi],
    ).fetchall()]

    best: dict[str, Any] | None = None
    best_delta: float | None = None
    for cand in candidates:
        if _infer_verdict(cand.get("outcome") or "") != trace_verdict:
            continue
        if asf_tool and (cand.get("action") or "") != asf_tool:
            continue
        cand_ts = _parse_timestamp(str(cand.get("timestamp") or ""))
        if cand_ts is None:
            continue
        delta = abs((cand_ts - trace_ts).total_seconds())
        if best_delta is None or delta < best_delta:
            best, best_delta = cand, delta

    if best is None:
        return []
    return _audit_chain_for_event(conn, best.get("hash"))


def _claude_row_for_event(conn: sqlite3.Connection, event_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id, timestamp, agent_id, agent_model, session_id, transcript_path, tool_call_id, "
        "claude_tool_name, asf_tool_name, args_preview, output_preview, verdict, outcome, reason, "
        "trace_id, audit_hash "
        "FROM claude_tool_traces WHERE id = ? OR audit_hash = ? OR trace_id = ? LIMIT 1",
        (event_id, event_id, event_id),
    ).fetchone()
    return dict(row) if row is not None else None


async def get_event_explanation(event_id: str) -> EventExplanation:
    cache_key = ("event_explanation", event_id)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return EventExplanation(
            event_id=event_id,
            final_reason="Audit database is not available.",
            pipeline=[PipelineStage(stage="Unavailable", reason="Audit database is not available.", terminal=True)],
        )

    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_query_indexes(conn, db_path)

        hermes_events: list[AuditEvent] = []
        if _has_hermes_trace_schema(db_path):
            hermes_rows = _hermes_rows_for_event(conn, event_id)
            hermes_events = [_normalize_hermes_trace(row) for row in hermes_rows]
            if hermes_events:
                # Hermes traces hold only a single summary row. Recover the full
                # per-stage pipeline from audit_trail so the decision path shows.
                resolved: list[AuditEvent] = []
                for hrow in hermes_rows:
                    chain = _audit_chain_for_hermes_trace(conn, hrow)
                    if len(chain) > 1:
                        resolved.extend(_normalize_event(row) for row in chain)
                pipeline = resolved or hermes_events
                anchor_row = hermes_rows[0]
                anchor_event = hermes_events[0]
                explanation = _event_explanation_from_pipeline(
                    event_id,
                    pipeline,
                    context_event=anchor_event,
                    tool_input=anchor_row.get("args_preview") or None,
                    tool_output=anchor_row.get("output_preview") or None,
                )
                return _cache_set(cache_key, explanation, ttl=300.0)

        audit_rows = _audit_chain_for_event(conn, event_id)
        audit_events = [_normalize_event(row) for row in audit_rows]
        if audit_events:
            claude_row = _claude_row_for_event(conn, event_id) if _has_claude_trace_schema(db_path) else None
            if claude_row:
                context = audit_events[-1]
                context.agent_model = claude_row.get("agent_model") or context.agent_model
                context.tool_name = claude_row.get("claude_tool_name") or context.tool_name
                explanation = _event_explanation_from_pipeline(
                    event_id,
                    audit_events,
                    context_event=context,
                    tool_input=claude_row.get("args_preview") or None,
                    tool_output=claude_row.get("output_preview") or None,
                )
            else:
                explanation = _event_explanation_from_pipeline(event_id, audit_events)
            return _cache_set(cache_key, explanation, ttl=300.0)

    explanation = EventExplanation(
        event_id=event_id,
        final_reason="No explanation data found for this event.",
        pipeline=[PipelineStage(stage="Unknown stage", reason="No explanation data found for this event.", terminal=True)],
    )
    return _cache_set(cache_key, explanation, ttl=300.0)


async def get_session_events(session_id: str, limit: int = 20, offset: int = 0) -> list[AuditEvent]:
    # Cap high enough to load a whole session in one call; the frontend then paginates
    # client-side so page navigation needs no further round-trips.
    limit = max(1, min(int(limit), 2000))
    offset = max(0, int(offset))
    cache_key = ("session_events", session_id, limit, offset)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []
    
    placeholders = ", ".join("?" for _ in TERMINAL_OUTCOMES)
    terminal_list = list(sorted(TERMINAL_OUTCOMES))
    rows: list[dict[str, Any]] = []

    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_query_indexes(conn, db_path)
        
        # Parse session_id to determine the type. Agent ids contain hyphens
        # (e.g. hermes-live-agent), so split on the literal marker, not on "-".
        # Formats: {agent}-session-{id}, {agent}-task-{id}, {agent}-group-{key}
        if "-session-" in session_id:
            agent_id, session_value = session_id.split("-session-", 1)
            session_type = "session"
        elif "-task-" in session_id:
            agent_id, session_value = session_id.split("-task-", 1)
            session_type = "task"
        elif "-group-" in session_id:
            agent_id, session_value = session_id.split("-group-", 1)
            session_type = "group"
        else:
            agent_id, session_value, session_type = session_id, "", ""

        # Determine if this is a real session identifier or a time-gap group
        is_real_session = session_type in ("session", "task")
        is_group_session = session_type == "group"
        is_hermes_session = "hermes" in agent_id or session_id.startswith("hermes-")
        
        if is_real_session:
            # Look up audit hashes from trace tables using the real session identifier
            audit_hashes: set[str] = set()
            
            if session_type == "session" and _has_claude_trace_schema(db_path):
                # Claude: session_id is a UUID
                for row in conn.execute(
                    "SELECT audit_hash FROM claude_tool_traces WHERE session_id = ? AND audit_hash IS NOT NULL",
                    (session_value,)
                ).fetchall():
                    if row[0]:
                        audit_hashes.add(row[0])
            
            if session_type == "session" and _has_hermes_trace_schema(db_path):
                # Hermes: session_id
                for row in conn.execute(
                    "SELECT audit_hash FROM hermes_tool_traces WHERE session_id = ? AND audit_hash IS NOT NULL",
                    (session_value,)
                ).fetchall():
                    if row[0]:
                        audit_hashes.add(row[0])
            
            if session_type == "task" and _has_hermes_trace_schema(db_path):
                # Hermes: task_id
                for row in conn.execute(
                    "SELECT audit_hash FROM hermes_tool_traces WHERE task_id = ? AND audit_hash IS NOT NULL",
                    (session_value,)
                ).fetchall():
                    if row[0]:
                        audit_hashes.add(row[0])
            
            # Fetch the terminal audit_trail rows for these hashes. audit_hash from the trace
            # tables is the terminal decision event's hash, so match on hash only (the old
            # "OR prev_hash IN" pulled in adjacent intermediate events like INTERCEPTOR_START)
            # and keep only terminal outcomes so non-terminal stage events never become rows.
            if audit_hashes:
                hash_placeholders = ", ".join("?" for _ in audit_hashes)
                rows = [dict(row) for row in conn.execute(
                    f"SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                    f"FROM audit_trail WHERE hash IN ({hash_placeholders}) AND outcome IN ({placeholders}) "
                    f"ORDER BY timestamp ASC LIMIT ? OFFSET ?",
                    list(audit_hashes) + terminal_list + [limit, offset],
                ).fetchall()]
        
        elif is_group_session:
            # Legacy time-gap grouped session - use existing logic
            group_agent, group_key = session_id.split("-group-", 1)
            key_upper = group_key + "g"
            anchor = conn.execute(
                "SELECT hash, timestamp FROM audit_trail "
                "WHERE agent_id = ? AND outcome IN (" + placeholders + ") "
                "AND ((hash >= ? AND hash < ?) OR (prev_hash >= ? AND prev_hash < ?)) "
                "ORDER BY timestamp DESC LIMIT 1",
                [group_agent] + terminal_list + [group_key, group_key + "g", group_key, group_key + "g"],
            ).fetchone()
            if anchor is not None:
                anchor_ts = _parse_timestamp(str(anchor["timestamp"] or ""))
                if anchor_ts is not None:
                    window_start = (anchor_ts - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S.%f")
                    window_end = (anchor_ts + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S.%f")
                    candidate_rows = [dict(row) for row in conn.execute(
                        "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                        "FROM audit_trail WHERE agent_id = ? AND outcome IN (" + placeholders + ") "
                        "AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC",
                        [group_agent] + terminal_list + [window_start, window_end],
                    ).fetchall()]

                    grouped: list[list[dict[str, Any]]] = []
                    current_group: list[dict[str, Any]] = []
                    last_ts: datetime | None = None
                    for candidate in candidate_rows:
                        ts = _parse_timestamp(str(candidate.get("timestamp") or ""))
                        if current_group and ts is not None and last_ts is not None and ts - last_ts >= timedelta(seconds=30):
                            grouped.append(current_group)
                            current_group = []
                        current_group.append(candidate)
                        last_ts = ts
                    if current_group:
                        grouped.append(current_group)

                    anchor_hash = anchor["hash"]
                    rows = next((group for group in grouped if any(row.get("hash") == anchor_hash for row in group)), [])
                    rows = rows[offset:offset + limit]
        
        else:
            # Fallback: treat as hash-based lookup (legacy behavior)
            key = session_id.rsplit("-", 1)[-1]
            key_upper = key + "g"
            rows = [dict(row) for row in conn.execute(
                "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                "FROM audit_trail WHERE hash >= ? AND hash < ? "
                "UNION "
                "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                "FROM audit_trail WHERE prev_hash >= ? AND prev_hash < ? "
                "ORDER BY timestamp ASC LIMIT ? OFFSET ?",
                (key, key_upper, key, key_upper, limit, offset),
            ).fetchall()]
        
        for row in rows:
            row["trace_id"] = f"trace-{(row.get('prev_hash') or row.get('hash') or session_value)[:12]}"
            row["session_id"] = session_id
            if row.get("latency_ms") is None:
                row["latency_ms"] = _legacy_audit_duration_ms(conn, row)
        events = [_normalize_event(row) for row in rows]
        
        # Also fetch Hermes trace rows if this is a Hermes session
        if is_hermes_session or session_type == "task":
            hermes_trace_key = session_id[session_id.rfind("hermes-"):] if "hermes-" in session_id else session_id
            hermes_task_key = session_id.split("-task-", 1)[1] if "-task-" in session_id else session_id
            hermes_session_key = session_id.split("-session-", 1)[1] if "-session-" in session_id else session_id
            
            if _has_hermes_trace_schema(db_path):
                hermes_rows = [dict(row) for row in conn.execute(
                    "SELECT id, timestamp, agent_id, agent_model, session_id, task_id, "
                    "tool_call_id, hermes_tool_name, asf_tool_name, verdict, outcome, reason, "
                    "stage, confidence, asf_latency_ms, tool_duration_ms, trace_id, audit_hash "
                    "FROM hermes_tool_traces "
                    "WHERE session_id = ? OR session_id = ? OR task_id = ? OR trace_id = ? OR trace_id = ? OR id = ? "
                    "ORDER BY timestamp ASC LIMIT ? OFFSET ?",
                    (session_id, hermes_session_key, hermes_task_key, session_id, hermes_trace_key, session_value, limit, offset),
                ).fetchall()]
                # The audit_trail events and these Hermes trace rows describe the same calls,
                # correlated by audit_hash. Prefer the richer trace event (tool name, model, io)
                # and drop the audit-derived duplicate so each call appears once.
                covered_hashes = {r.get("audit_hash") for r in hermes_rows if r.get("audit_hash")}
                if covered_hashes:
                    events = [e for e in events if e.event_id not in covered_hashes]
                events.extend(_normalize_hermes_trace(row) for row in hermes_rows)
        
        # Also fetch Claude trace rows if this is a Claude session
        if session_type == "session" and _has_claude_trace_schema(db_path):
            claude_rows = [dict(row) for row in conn.execute(
                "SELECT id, timestamp, agent_id, agent_model, session_id, transcript_path, tool_call_id, "
                "claude_tool_name, asf_tool_name, args_preview, output_preview, verdict, outcome, reason, "
                "trace_id, audit_hash "
                "FROM claude_tool_traces "
                "WHERE session_id = ? "
                "ORDER BY timestamp ASC LIMIT ? OFFSET ?",
                (session_value, limit, offset),
            ).fetchall()]
            # Claude rows are already included via audit_trail join, but we can enrich if needed

    events.sort(key=lambda event: _parse_timestamp(event.timestamp) or datetime.min)
    # If both legacy audit rows and Hermes trace rows matched, keep the requested page size.
    # Session events are append-only; cache aggressively.
    return _cache_set(cache_key, events[:limit], ttl=300.0)


async def get_trace_events(trace_id: str) -> list[AuditEvent]:
    return await get_session_events(trace_id.replace("trace-", "trace-"))


def _hermes_group_covered_by_audit(
    hgroup: dict[str, Any],
    audit_intervals: list[tuple[str, datetime | None, datetime | None, set[str]]],
) -> bool:
    """True when a Hermes trace session duplicates an audit_trail session.

    Every Hermes tool call is recorded both as a summary row in hermes_tool_traces and
    as a hash-chained sequence in audit_trail, so it would otherwise show as two near
    identical sessions. The audit_trail '-group-' session is authoritative (full per-stage
    path), so the Hermes duplicate is dropped. Match precisely via the audit_hash back-link
    when present, else fall back to agent + time-range overlap (covers pre-back-link rows).
    """
    agent = hgroup.get("agent_id")
    hashes = hgroup.get("_audit_hashes") or set()
    if hashes:
        for a, _s, _e, group_hashes in audit_intervals:
            if a == agent and hashes & group_hashes:
                return True
    hs, he = hgroup.get("start_ts"), hgroup.get("end_ts")
    if hs is None or he is None:
        return False
    tol = timedelta(seconds=30)
    for a, s, e, _hashes in audit_intervals:
        if a != agent or s is None or e is None:
            continue
        if hs <= e + tol and s <= he + tol:
            return True
    return False


async def get_sessions(
    limit: int = 20,
    offset: int = 0,
    agent_id: str | None = None,
    show_eval: bool = False,
) -> list[SessionSummary]:
    offset = max(0, int(offset or 0))
    limit = max(1, int(limit or 20))
    cache_key = ("sessions", limit, offset, agent_id, show_eval)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []

    placeholders = ",".join("?" for _ in TERMINAL_OUTCOMES)
    terminal_list = list(sorted(TERMINAL_OUTCOMES))

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_query_indexes(conn, db_path)

        if agent_id:
            # Single-agent: one indexed query.
            agent_ids_to_query = [agent_id]
        else:
            # Multi-agent: enumerate all agents (fast via agent_id index skip-scan),
            # then query each one individually. This avoids the recency-scan that gets
            # buried under millions of benchmark-agent rows and misses older agents.
            all_agents = [r[0] for r in conn.execute(
                "SELECT DISTINCT agent_id FROM audit_trail WHERE agent_id IS NOT NULL"
            ).fetchall()]
            agent_ids_to_query = [
                a for a in all_agents
                if show_eval or a not in EVAL_TOOL_AGENTS
            ]

        # Fetch enough rows to answer the requested server-side page after
        # combining Hermes traces and legacy audit-trail rows. For all-agents
        # view this is still bounded per agent so benchmark-heavy agents cannot
        # starve live Hermes/Claude rows.
        page_window = limit + offset
        per_agent_limit = max(500, page_window * 50) if agent_id else max(500, page_window * 20)
        all_rows: list[dict[str, Any]] = []
        for a in agent_ids_to_query:
            a_rows = [dict(r) for r in conn.execute(
                "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                f"FROM audit_trail WHERE agent_id = ? AND outcome IN ({placeholders}) "
                "ORDER BY timestamp DESC LIMIT ?",
                [a] + terminal_list + [per_agent_limit],
            ).fetchall()]
            all_rows.extend(a_rows)

    # Collect hermes and audit-trail sessions independently so neither source starves the other.
    hermes_summaries: list[SessionSummary] = []
    hermes_groups: dict[str, dict[str, Any]] = {}
    hermes_model_by_audit_hash: dict[str, str] = {}
    if _has_hermes_trace_schema(db_path):
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            hermes_query = (
                "SELECT id, timestamp, agent_id, agent_type, agent_model, session_id, task_id, "
                "trace_id, outcome, verdict, audit_hash, "
                "COALESCE(tool_duration_ms, asf_latency_ms, 0) AS duration_ms "
                "FROM hermes_tool_traces"
            )
            params: list[Any] = []
            if agent_id:
                hermes_query += " WHERE agent_id = ?"
                params.append(agent_id)
            hermes_query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(per_agent_limit)
            hermes_rows = [dict(row) for row in conn.execute(hermes_query, params).fetchall()]
        for hrow in hermes_rows:
            ah = (hrow.get("audit_hash") or "").strip()
            model = (hrow.get("agent_model") or "").strip()
            if ah and model:
                hermes_model_by_audit_hash[ah] = model

        for row in hermes_rows:
            agent = row.get("agent_id") or "hermes"
            raw_sid = row.get("session_id")
            task_id = row.get("task_id")
            trace_id = row.get("trace_id")
            if raw_sid:
                sid = f"{agent}-session-{raw_sid}"
            elif task_id:
                sid = f"{agent}-task-{task_id}"
            else:
                sid = f"{agent}-trace-{trace_id or (row.get('id') or '')[:12]}"

            ts = _parse_timestamp(str(row.get("timestamp") or ""))
            outcome = row.get("outcome") or _outcome_from_verdict(row.get("verdict") or "")
            framework, model = _agent_metadata(
                agent,
                row.get("agent_type"),
                row.get("agent_model"),
            )
            group = hermes_groups.get(sid)
            if group is None:
                group = {
                    "session_id": sid,
                    "agent_id": agent,
                    "agent_framework": framework,
                    "agent_model": model,
                    "start_ts": ts,
                    "end_ts": ts,
                    "start_time": str(row.get("timestamp") or ""),
                    "end_time": str(row.get("timestamp") or ""),
                    "total_events": 0,
                    "blocked_count": 0,
                    "allowed_count": 0,
                    "hitl_count": 0,
                    "duration_sum_ms": 0,
                    "_audit_hashes": set(),
                }
                hermes_groups[sid] = group

            if ts is not None:
                if group["start_ts"] is None or ts < group["start_ts"]:
                    group["start_ts"] = ts
                    group["start_time"] = str(row.get("timestamp") or "")
                if group["end_ts"] is None or ts > group["end_ts"]:
                    group["end_ts"] = ts
                    group["end_time"] = str(row.get("timestamp") or "")

            group["total_events"] += 1
            group["blocked_count"] += 1 if outcome in BLOCK_OUTCOMES else 0
            group["allowed_count"] += 1 if outcome in ALLOW_OUTCOMES else 0
            group["hitl_count"] += 1 if outcome in HITL_OUTCOMES else 0
            group["duration_sum_ms"] += int(row.get("duration_ms") or 0)
            ah = (row.get("audit_hash") or "").strip()
            if ah:
                group["_audit_hashes"].add(ah)
        # Hermes summaries are converted after the audit groups are built so each one can be
        # deduplicated against its authoritative audit_trail '-group-' session.

    audit_summaries: list[SessionSummary] = []
    audit_intervals: list[tuple[str, datetime | None, datetime | None, set[str]]] = []
    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        
        # Build a lookup from audit_hash to real session identifiers.
        # This lets audit_trail rows be grouped by the stable session IDs from trace tables.
        audit_hash_to_session: dict[str, str] = {}
        
        # Claude: session_id is a stable UUID per conversation
        if _has_claude_trace_schema(db_path):
            for row in conn.execute(
                "SELECT audit_hash, session_id, agent_id FROM claude_tool_traces WHERE audit_hash IS NOT NULL AND session_id IS NOT NULL"
            ).fetchall():
                ah = row[0]
                sid = row[1]
                agent = row[2]
                if ah and sid and agent:
                    audit_hash_to_session[ah] = f"{agent}-session-{sid}"
        
        # Hermes: prefer session_id, else task_id as the session identifier
        if _has_hermes_trace_schema(db_path):
            for row in conn.execute(
                "SELECT audit_hash, session_id, task_id, agent_id FROM hermes_tool_traces WHERE audit_hash IS NOT NULL"
            ).fetchall():
                ah = row[0]
                agent = row[3]
                if ah and agent:
                    raw_sid = row[1]
                    task_id = row[2]
                    if raw_sid:
                        audit_hash_to_session[ah] = f"{agent}-session-{raw_sid}"
                    elif task_id:
                        audit_hash_to_session[ah] = f"{agent}-task-{task_id}"
        
        audit_groups: list[dict[str, Any]] = []
        for row in sorted(all_rows, key=lambda r: (r.get("agent_id") or "", r.get("timestamp") or "")):
            agent = row.get("agent_id") or "unknown-agent"
            ts = _parse_timestamp(str(row.get("timestamp") or ""))
            outcome = row.get("outcome") or ""
            key = (row.get("prev_hash") or row.get("hash") or "")[:12]
            row_duration_ms = _legacy_audit_duration_ms(conn, row)
            
            # Check if this audit row has a real session identifier via its hash
            real_session_key: str | None = None
            h = row.get("hash")
            ph = row.get("prev_hash")
            if h and h in audit_hash_to_session:
                real_session_key = audit_hash_to_session[h]
            elif ph and ph in audit_hash_to_session:
                real_session_key = audit_hash_to_session[ph]
            
            # Determine if we should continue the current group or start a new one
            group = audit_groups[-1] if audit_groups else None
            
            # If we have a real session identifier, group by it exactly
            if real_session_key:
                # Find existing group with this session key
                matching_group = next((g for g in audit_groups if g.get("_session_key") == real_session_key), None)
                if matching_group is not None:
                    group = matching_group
                    same_session = True
                else:
                    same_session = False
            else:
                # No real identifier: fall back to 30-second time-gap heuristic
                same_session = (
                    group is not None
                    and group["agent_id"] == agent
                    and ts is not None
                    and group["end_ts"] is not None
                    and ts - group["end_ts"] < timedelta(seconds=30)
                )
            
            row_model = hermes_model_by_audit_hash.get(row.get("hash") or "") or hermes_model_by_audit_hash.get(row.get("prev_hash") or "")
            if not same_session:
                framework, model = _agent_metadata(agent, agent_model=row_model)
                session_id = real_session_key if real_session_key else f"{agent}-group-{key}"
                group = {
                    "session_id": session_id,
                    "agent_id": agent,
                    "agent_framework": framework,
                    "agent_model": model,
                    "start_ts": ts,
                    "end_ts": ts,
                    "start_time": str(row.get("timestamp") or ""),
                    "end_time": str(row.get("timestamp") or ""),
                    "total_events": 0,
                    "blocked_count": 0,
                    "allowed_count": 0,
                    "hitl_count": 0,
                    "duration_sum_ms": 0,
                    "_hashes": set(),
                    "_session_key": real_session_key,  # Track the grouping key
                }
                audit_groups.append(group)
            
            assert group is not None
            if ts is not None:
                if group["start_ts"] is None or ts < group["start_ts"]:
                    group["start_ts"] = ts
                    group["start_time"] = str(row.get("timestamp") or "")
                if group["end_ts"] is None or ts > group["end_ts"]:
                    group["end_ts"] = ts
                    group["end_time"] = str(row.get("timestamp") or "")
            
            group["total_events"] += 1
            group["blocked_count"] += 1 if outcome in BLOCK_OUTCOMES else 0
            group["allowed_count"] += 1 if outcome in ALLOW_OUTCOMES else 0
            group["hitl_count"] += 1 if outcome in HITL_OUTCOMES else 0
            group["duration_sum_ms"] += row_duration_ms
            if row_model and group.get("agent_framework") == "Hermes Agent":
                group["agent_model"] = row_model
            if h:
                group["_hashes"].add(h)
            if ph:
                group["_hashes"].add(ph)

        for group in audit_groups:
            start_ts = group.pop("start_ts")
            end_ts = group.pop("end_ts")
            duration_sum_ms = group.pop("duration_sum_ms")
            audit_intervals.append((group["agent_id"], start_ts, end_ts, group.get("_hashes", set())))
            if start_ts is not None and end_ts is not None and end_ts > start_ts:
                duration_ms = int((end_ts - start_ts).total_seconds() * 1000)
            else:
                duration_ms = duration_sum_ms
            audit_summaries.append(SessionSummary(
                session_id=group["session_id"],
                agent_id=group["agent_id"],
                agent_framework=group["agent_framework"],
                agent_model=group["agent_model"],
                start_time=group["start_time"],
                end_time=group["end_time"],
                total_events=group["total_events"],
                blocked_count=group["blocked_count"],
                allowed_count=group["allowed_count"],
                hitl_count=group["hitl_count"],
                duration_ms=duration_ms,
            ))

    # Convert surviving Hermes groups, dropping any that duplicate an audit_trail session.
    for group in hermes_groups.values():
        if _hermes_group_covered_by_audit(group, audit_intervals):
            continue
        start_ts = group.get("start_ts")
        end_ts = group.get("end_ts")
        duration_sum_ms = group.get("duration_sum_ms", 0)
        if start_ts is not None and end_ts is not None and end_ts > start_ts:
            duration_ms = int((end_ts - start_ts).total_seconds() * 1000)
        else:
            duration_ms = duration_sum_ms
        hermes_summaries.append(SessionSummary(
            session_id=group["session_id"],
            agent_id=group["agent_id"],
            agent_framework=group["agent_framework"],
            agent_model=group["agent_model"],
            start_time=group["start_time"],
            end_time=group["end_time"],
            total_events=group["total_events"],
            blocked_count=group["blocked_count"],
            allowed_count=group["allowed_count"],
            hitl_count=group["hitl_count"],
            duration_ms=duration_ms,
        ))

    summaries = hermes_summaries + audit_summaries
    summaries.sort(key=lambda session: _parse_timestamp(session.start_time) or datetime.min, reverse=True)
    result = summaries[offset:offset + limit]
    return _cache_set(cache_key, result, ttl=10.0)


def _get_hermes_metric_counts(db_path: Path, agent_id: str | None = None) -> dict[str, Any]:
    if not _has_hermes_trace_schema(db_path):
        return {
            "total": 0,
            "last_24h": 0,
            "blocked": 0,
            "allowed": 0,
            "hitl": 0,
            "avg_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
        }

    agent_clause = " WHERE agent_id = ?" if agent_id else ""
    agent_params: list[Any] = [agent_id] if agent_id else []
    last_24h_clause = " WHERE datetime(timestamp) >= datetime('now', '-24 hours')"
    if agent_id:
        last_24h_clause += " AND agent_id = ?"

    with sqlite3.connect(db_path, timeout=2) as conn:
        conn.row_factory = sqlite3.Row
        total = int(conn.execute(
            f"SELECT COUNT(*) FROM hermes_tool_traces{agent_clause}",
            agent_params,
        ).fetchone()[0])
        last_24h = int(conn.execute(
            f"SELECT COUNT(*) FROM hermes_tool_traces{last_24h_clause}",
            agent_params,
        ).fetchone()[0])
        row = conn.execute(
            "SELECT "
            "SUM(CASE WHEN UPPER(COALESCE(verdict, outcome, '')) IN ('BLOCK', 'BLOCKED', 'DENY', 'KILL_SWITCH', 'OUTPUT_BLOCK', 'L1.5_BLOCK') THEN 1 ELSE 0 END) AS blocked, "
            "SUM(CASE WHEN UPPER(COALESCE(verdict, outcome, '')) IN ('ALLOW', 'ALLOWED', 'HEURISTIC_CLEAR') THEN 1 ELSE 0 END) AS allowed, "
            "SUM(CASE WHEN UPPER(COALESCE(verdict, outcome, '')) IN ('HITL', 'HITL_REQUESTED') THEN 1 ELSE 0 END) AS hitl, "
            "AVG(COALESCE(asf_latency_ms, 0)) AS avg_latency_ms "
            f"FROM hermes_tool_traces{agent_clause}",
            agent_params,
        ).fetchone()
        latencies = [int(r[0] or 0) for r in conn.execute(
            f"SELECT COALESCE(asf_latency_ms, 0) FROM hermes_tool_traces{agent_clause} ORDER BY COALESCE(asf_latency_ms, 0)",
            agent_params,
        ).fetchall()]

    p95_latency_ms = 0.0
    if latencies:
        p95_idx = min(len(latencies) - 1, int(round((len(latencies) - 1) * 0.95)))
        p95_latency_ms = float(latencies[p95_idx])

    return {
        "total": total,
        "last_24h": last_24h,
        "blocked": int(row["blocked"] or 0),
        "allowed": int(row["allowed"] or 0),
        "hitl": int(row["hitl"] or 0),
        "avg_latency_ms": float(row["avg_latency_ms"] or 0.0),
        "p95_latency_ms": p95_latency_ms,
    }


_GOV_RBAC_REASON_LIKE = ("%suspended or not found%", "%not in permissions%", "%not authorized%", "%access denied%")


def _governance_rbac_counts(db_path: Path, agent_id: str | None) -> dict[str, int]:
    """Access-control denials (agent suspended / RBAC permission) blocked at the gate
    before content inspection. Excluded from KPI block/total figures so the headline
    reflects content-pipeline decisions, not access-control rejections; they remain
    visible in the stage funnel's Governance / RBAC bucket."""
    cache_key = ("gov_rbac_counts", agent_id)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    result = {"total": 0, "last_24h": 0}
    if _has_audit_schema(db_path):
        agent_clause = " AND agent_id = ?" if agent_id else ""
        agent_params: list[Any] = [agent_id] if agent_id else []
        like = "(" + " OR ".join("reason LIKE ?" for _ in _GOV_RBAC_REASON_LIKE) + ")"
        cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(db_path) as conn:
            result["total"] = conn.execute(
                f"SELECT COUNT(*) FROM audit_trail WHERE outcome = 'BLOCKED' AND {like}{agent_clause}",
                list(_GOV_RBAC_REASON_LIKE) + agent_params,
            ).fetchone()[0]
            result["last_24h"] = conn.execute(
                f"SELECT COUNT(*) FROM audit_trail WHERE outcome = 'BLOCKED' AND {like} "
                f"AND timestamp >= ?{agent_clause}",
                list(_GOV_RBAC_REASON_LIKE) + [cutoff_24h] + agent_params,
            ).fetchone()[0]
    return _cache_set(cache_key, result, ttl=30.0)


async def get_provenance() -> dict[str, str | None]:
    """Lightweight data-source provenance for the topbar (DB name + freshness).

    Every page shows the same provenance strip, but most pages don't fetch the heavy
    KPI metrics. This computes just the DB filename and the most recent event timestamp
    across audit_trail and hermes_tool_traces.
    """
    db_path = get_db_path()
    db_source = str(db_path).rsplit("/", 1)[-1] or str(db_path)
    if not _has_audit_schema(db_path):
        return {"db_source": db_source, "data_as_of": None}

    cache_key = ("provenance",)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    max_ts: str | None = None
    with sqlite3.connect(db_path, timeout=10) as conn:
        row = conn.execute("SELECT MAX(timestamp) FROM audit_trail").fetchone()
        if row and row[0]:
            max_ts = str(row[0])
        if _has_hermes_trace_schema(db_path):
            hrow = conn.execute("SELECT MAX(timestamp) FROM hermes_tool_traces").fetchone()
            if hrow and hrow[0]:
                ht = str(hrow[0])
                a, b = _parse_timestamp(max_ts), _parse_timestamp(ht)
                if max_ts is None or (a and b and b > a):
                    max_ts = ht

    data_as_of = None
    if max_ts:
        dt = _parse_timestamp(max_ts)
        data_as_of = dt.isoformat() if dt else max_ts

    result = {"db_source": db_source, "data_as_of": data_as_of}
    return _cache_set(cache_key, result, ttl=5.0)


async def get_metrics(agent_id: str | None = None) -> KPIMetrics:
    db_path = get_db_path()
    db_source = str(db_path).rsplit("/", 1)[-1] or str(db_path)
    hermes = _get_hermes_metric_counts(db_path, agent_id)

    # The production audit DB is ~4GB / 8.9M rows. For dashboard KPIs, use the
    # precomputed cache so first paint does not block on full-table aggregates,
    # then merge in live Hermes traces that are not represented in that cache.
    cache = _load_dashboard_cache()
    if cache and not agent_id and _dashboard_cache_is_stale(db_path, cache):
        invalidate_cache()
        cache = {}
    if cache and not agent_id:
        # audit_trail is authoritative: the interceptor logs every call there (Hermes
        # calls too, which additionally get a hermes_tool_traces row). KPI counts come
        # from audit_trail only; hermes_tool_traces stays as operational detail and as
        # the latency source (audit_trail has no latency column), and must not be summed
        # in here or the same Hermes call is counted twice.
        counts = cache.get("outcome_counts", {})
        # Exclude access-control denials (agent suspended / RBAC) from the KPI figures:
        # they are gate rejections, not content-inspection decisions (still shown in the
        # stage funnel's Governance / RBAC bucket).
        gov = _governance_rbac_counts(db_path, None)
        total_tool_calls = max(0, int(counts.get("INTERCEPTOR_START", 0)) - gov["total"])
        blocked = max(0, sum(int(counts.get(outcome, 0)) for outcome in BLOCK_OUTCOMES) - gov["total"])
        allowed = sum(int(counts.get(outcome, 0)) for outcome in ALLOW_OUTCOMES)
        hitl = _count_pending_hitl(db_path, None)
        terminal = blocked + allowed + hitl
        max_ts = _parse_timestamp(cache.get("max_interceptor_ts"))
        # The cache only holds lifetime aggregates and freshness, not a windowed count.
        # The previous heuristic reported the ENTIRE INTERCEPTOR_START total as "last 24h"
        # whenever the newest event was recent, which on the multi-million-row DB inflates
        # the 24h figure massively. Compute the real 24h count directly: comparing the raw
        # timestamp against a precomputed cutoff lets idx_audit_trail_outcome_timestamp
        # serve it as a bounded range scan, so it stays cheap and is not a full aggregate.
        tool_calls_last_24h = 0
        if _has_audit_schema(db_path):
            cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(db_path) as conn:
                tool_calls_last_24h = conn.execute(
                    "SELECT COUNT(*) FROM audit_trail "
                    "WHERE outcome = 'INTERCEPTOR_START' AND timestamp >= ?",
                    (cutoff_24h,),
                ).fetchone()[0]
        tool_calls_last_24h = max(0, tool_calls_last_24h - gov["last_24h"])

        min_ts = _parse_timestamp(cache.get("min_interceptor_ts"))
        avg_daily_calls = 0.0
        if min_ts and max_ts and max_ts > min_ts:
            days = max((max_ts - min_ts).total_seconds() / 86400, 1.0)
            avg_daily_calls = int(counts.get("INTERCEPTOR_START", 0)) / days
        calls_trend_pct = None
        if avg_daily_calls:
            calls_trend_pct = ((tool_calls_last_24h - avg_daily_calls) / avg_daily_calls) * 100

        return KPIMetrics(
            total_tool_calls=total_tool_calls,
            detection_rate=(blocked / terminal) if terminal else 0.0,
            false_positive_rate=0.0,
            blocked_count=blocked,
            allowed_count=allowed,
            hitl_count=hitl,
            avg_latency_ms=hermes["avg_latency_ms"],
            p95_latency_ms=hermes["p95_latency_ms"],
            tool_calls_last_24h=tool_calls_last_24h,
            calls_trend_pct=calls_trend_pct,
            data_as_of=max_ts.isoformat() if max_ts else None,
            db_source=db_source,
        )

    if not _has_audit_schema(db_path):
        hitl = 0
        terminal = hermes["blocked"] + hermes["allowed"] + hitl
        return KPIMetrics(
            total_tool_calls=hermes["total"],
            detection_rate=(hermes["blocked"] / terminal) if terminal else 0.0,
            false_positive_rate=0.0,
            blocked_count=hermes["blocked"],
            allowed_count=hermes["allowed"],
            hitl_count=hitl,
            avg_latency_ms=hermes["avg_latency_ms"],
            p95_latency_ms=hermes["p95_latency_ms"],
            tool_calls_last_24h=hermes["last_24h"],
            calls_trend_pct=None,
            data_as_of=hermes.get("max_ts"),
            db_source=db_source,
        )

    agent_clause = " AND agent_id = ?" if agent_id else ""
    agent_params: list[Any] = [agent_id] if agent_id else []
    with sqlite3.connect(db_path) as conn:
        # audit_trail is authoritative (see cache branch above): count only from it,
        # never add hermes_tool_traces on top or Hermes calls are double-counted.
        total_tool_calls = conn.execute(
            f"SELECT COUNT(*) FROM audit_trail WHERE outcome = 'INTERCEPTOR_START'{agent_clause}",
            agent_params,
        ).fetchone()[0]
        cutoff_24h = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        audit_calls_last_24h = conn.execute(
            "SELECT COUNT(*) FROM audit_trail WHERE outcome = 'INTERCEPTOR_START' "
            f"AND timestamp >= ?{agent_clause}",
            [cutoff_24h] + agent_params,
        ).fetchone()[0]
        placeholders = ",".join("?" for _ in TERMINAL_OUTCOMES)
        counts = dict(conn.execute(
            "SELECT outcome, COUNT(*) FROM audit_trail "
            f"WHERE outcome IN ({placeholders}){agent_clause} GROUP BY outcome",
            list(sorted(TERMINAL_OUTCOMES)) + agent_params,
        ).fetchall())
        latest_ts = conn.execute(
            f"SELECT MAX(timestamp) FROM audit_trail WHERE 1=1{agent_clause}",
            agent_params,
        ).fetchone()[0]
    # Exclude access-control denials (agent suspended / RBAC) from the KPI figures: they
    # are gate rejections, not content-inspection decisions (still in the funnel bucket).
    gov = _governance_rbac_counts(db_path, agent_id)
    blocked = max(0, sum(counts.get(outcome, 0) for outcome in BLOCK_OUTCOMES) - gov["total"])
    allowed = sum(counts.get(outcome, 0) for outcome in ALLOW_OUTCOMES)
    hitl = _count_pending_hitl(db_path, agent_id)
    terminal = blocked + allowed + hitl
    total_tool_calls = max(0, total_tool_calls - gov["total"])
    audit_calls_last_24h = max(0, audit_calls_last_24h - gov["last_24h"])
    return KPIMetrics(
        total_tool_calls=total_tool_calls,
        detection_rate=(blocked / terminal) if terminal else 0.0,
        false_positive_rate=0.0,
        blocked_count=blocked,
        allowed_count=allowed,
        hitl_count=hitl,
        avg_latency_ms=hermes["avg_latency_ms"],
        p95_latency_ms=hermes["p95_latency_ms"],
        tool_calls_last_24h=audit_calls_last_24h,
        calls_trend_pct=None,
        data_as_of=str(latest_ts) if latest_ts else hermes.get("max_ts"),
        db_source=db_source,
    )


_CHART_WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7)}

_LATENCY_EDGES = [
    (0, 10, "<10ms"),
    (10, 25, "10-25ms"),
    (25, 50, "25-50ms"),
    (50, 100, "50-100ms"),
    (100, 300, "100-300ms"),
    (300, None, "300ms+"),
]

# Canonical control-pipeline order for the stage funnel (flow order, not by volume).
_STAGE_ORDER = [
    "L1.5 fast-path",
    "L1.5",
    "Stage 1",
    "Stage 2",
    "Stage 2.5 DeBERTa",
    "Stage 2.5b Prompt Guard",
    "Stage 3 LLM",
    "Stage 3 ONNX",
    "Stage 3 ONNX Prompt Guard",
    "Output Guard",
]


def _stage_order_key(stage: str) -> int:
    try:
        return _STAGE_ORDER.index(stage)
    except ValueError:
        return len(_STAGE_ORDER)


def _latency_distribution(db_path: Path, cutoff: str, agent_id: str | None) -> LatencyDistribution:
    """Latency comes only from hermes_tool_traces; audit_trail has no latency column.
    This is the sole source, not double-counting. ISO 'T' timestamps in that table need
    datetime() normalization (unlike audit_trail's space-separated, index-friendly form)."""
    buckets = [LatencyBucket(label=label, count=0) for _lo, _hi, label in _LATENCY_EDGES]
    if not _has_hermes_trace_schema(db_path):
        return LatencyDistribution(buckets=buckets, p50_ms=0.0, p95_ms=0.0, p99_ms=0.0, sample_count=0)
    agent_clause = " AND agent_id = ?" if agent_id else ""
    params: list[Any] = [cutoff] + ([agent_id] if agent_id else [])
    with sqlite3.connect(db_path, timeout=2) as conn:
        values = [int(row[0] or 0) for row in conn.execute(
            "SELECT COALESCE(asf_latency_ms, 0) FROM hermes_tool_traces "
            f"WHERE datetime(timestamp) >= datetime(?){agent_clause} "
            "ORDER BY COALESCE(asf_latency_ms, 0)",
            params,
        ).fetchall()]
    for value in values:
        for index, (lo, hi, _label) in enumerate(_LATENCY_EDGES):
            if value >= lo and (hi is None or value < hi):
                buckets[index].count += 1
                break

    def _pct(p: float) -> float:
        if not values:
            return 0.0
        idx = min(len(values) - 1, int(round((len(values) - 1) * p)))
        return float(values[idx])

    return LatencyDistribution(
        buckets=buckets, p50_ms=_pct(0.50), p95_ms=_pct(0.95), p99_ms=_pct(0.99),
        sample_count=len(values),
    )


def _classify_block_reason(outcome: str, reason: str | None) -> str:
    r = (reason or "").lower()
    if "suspended or not found" in r or ("suspended" in r and "not found" in r):
        return "governance"
    if "not in permissions" in r or "not authorized" in r or "access denied" in r:
        return "rbac"
    if outcome == "OUTPUT_BLOCK":
        return "output_guard"
    if outcome in BLOCK_OUTCOMES:
        return "content_detection"
    return "other"


_SCORE_RE = re.compile(r"(?:score|confidence|p|prob(?:a)?)[=: ]+([0-9]*\.?[0-9]+)", re.IGNORECASE)


def _score_bucket(reason: str | None) -> str | None:
    match = _SCORE_RE.search(reason or "")
    if not match:
        return None
    try:
        value = float(match.group(1))
    except ValueError:
        return None
    value = max(0.0, min(1.0, value))
    low = int(value * 10) / 10
    high = min(1.0, low + 0.099)
    return f"score {low:.1f}-{high:.1f}"


def _block_catalog_detail(mechanism: str, outcome: str, reason: str | None) -> str:
    text = reason or ""
    lower = text.lower()
    if mechanism == "Stage 1":
        match = re.search(r"regex match:\s*(.+)$", text, re.IGNORECASE)
        if match:
            pattern = re.sub(r"\s+", " ", match.group(1)).strip()
            return f"regex: {pattern[:80]}"
        return "regex match"
    if mechanism == "L1.5 fast-path":
        return _score_bucket(text) or "heuristic block"
    if mechanism == "Stage 2":
        return _score_bucket(text) or "classifier block"
    if mechanism == "Stage 2.5 DeBERTa":
        label = "DANGEROUS"
        match = re.search(r"deberta:\s*([A-Z_ -]+?)(?:\s+(?:p|score|confidence|prob)|$)", text, re.IGNORECASE)
        if match:
            label = re.sub(r"\s+", "_", match.group(1).strip().upper())
        score = _score_bucket(text)
        return f"{label} {score}" if score else label
    if mechanism == "Stage 2.5b Prompt Guard":
        if "dangerous" in lower:
            return "DANGEROUS"
        if "unavailable" in lower:
            return "UNAVAILABLE"
        return "prompt guard block"
    if mechanism.startswith("Stage 3"):
        if "fail closed" in lower:
            return "fail closed"
        if "dangerous" in lower:
            return "dangerous"
        if "error" in lower:
            return "error"
        return "stage 3 block"
    if mechanism == "Output Guard":
        return "output block"
    return "other"


def _block_catalog_mechanism(outcome: str, reason: str | None) -> str:
    return _extract_stage(outcome, reason)


async def get_overview_charts(window: str = "24h", agent_id: str | None = None) -> OverviewCharts:
    window = window if window in _CHART_WINDOWS else "24h"
    db_path = get_db_path()
    db_source = str(db_path).rsplit("/", 1)[-1] or str(db_path)
    cache_key = ("overview_charts", window, agent_id)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    # audit_trail uses space-separated timestamps, so a precomputed cutoff string is
    # index-friendly (idx_audit_trail_outcome_timestamp). Every query is windowed so it
    # stays a bounded range scan even on the multi-million-row production DB.
    cutoff = (datetime.utcnow() - _CHART_WINDOWS[window]).strftime("%Y-%m-%d %H:%M:%S")
    agent_clause = " AND agent_id = ?" if agent_id else ""
    agent_params: list[Any] = [agent_id] if agent_id else []

    stage_acc: dict[str, dict[str, int]] = {}
    reason_acc: dict[str, int] = {
        "governance": 0, "rbac": 0, "content_detection": 0, "output_guard": 0, "other": 0,
    }
    timeline_acc: dict[str, dict[str, int]] = {}
    agent_acc: dict[str, dict[str, int]] = {}
    catalog_acc: dict[tuple[str, str], dict[str, Any]] = {}

    if _has_audit_schema(db_path):
        placeholders = ",".join("?" for _ in TERMINAL_OUTCOMES)
        terminal = sorted(TERMINAL_OUTCOMES)
        # Governance/RBAC access-control denials are excluded from every chart dataset
        # (funnel, block reasons, timeline, per-agent), like the KPIs: they are gate
        # rejections, not content-inspection decisions.
        exclude_gov = " AND NOT (outcome = 'BLOCKED' AND (" + " OR ".join(
            "reason LIKE ?" for _ in _GOV_RBAC_REASON_LIKE) + "))"
        gov_params = list(_GOV_RBAC_REASON_LIKE)
        with sqlite3.connect(db_path) as conn:
            decision_rows = conn.execute(
                f"SELECT outcome, reason, COUNT(*) FROM audit_trail "
                f"WHERE outcome IN ({placeholders}) AND timestamp >= ?{agent_clause}{exclude_gov} "
                f"GROUP BY outcome, reason",
                terminal + [cutoff] + agent_params + gov_params,
            ).fetchall()
            timeline_rows = conn.execute(
                f"SELECT strftime('%Y-%m-%d %H:00', timestamp) AS bucket, outcome, COUNT(*) "
                f"FROM audit_trail WHERE outcome IN ({placeholders}) AND timestamp >= ?{agent_clause}{exclude_gov} "
                f"GROUP BY bucket, outcome",
                terminal + [cutoff] + agent_params + gov_params,
            ).fetchall()
            agent_rows = conn.execute(
                f"SELECT agent_id, outcome, COUNT(*) FROM audit_trail "
                f"WHERE outcome IN ({placeholders}) AND timestamp >= ?{exclude_gov} GROUP BY agent_id, outcome",
                terminal + [cutoff] + gov_params,
            ).fetchall()
            catalog_rows = conn.execute(
                f"SELECT agent_id, outcome, reason, COUNT(*) FROM audit_trail "
                f"WHERE outcome IN ({placeholders}) AND timestamp >= ?{agent_clause}{exclude_gov} "
                f"GROUP BY agent_id, outcome, reason",
                terminal + [cutoff] + agent_params + gov_params,
            ).fetchall()

        for outcome, reason, count in decision_rows:
            verdict = _infer_verdict(outcome)
            stage = _extract_stage(outcome, reason)
            bucket = stage_acc.setdefault(stage, {"total": 0, "blocked": 0, "allowed": 0, "hitl": 0})
            bucket["total"] += count
            if verdict == "DENY":
                bucket["blocked"] += count
                reason_acc[_classify_block_reason(outcome, reason)] += count
            elif verdict == "ALLOW":
                bucket["allowed"] += count
            elif verdict == "HITL":
                bucket["hitl"] += count

        for bucket_label, outcome, count in timeline_rows:
            point = timeline_acc.setdefault(bucket_label, {"blocked": 0, "allowed": 0, "hitl": 0})
            verdict = _infer_verdict(outcome)
            if verdict == "DENY":
                point["blocked"] += count
            elif verdict == "ALLOW":
                point["allowed"] += count
            elif verdict == "HITL":
                point["hitl"] += count

        for agent, outcome, count in agent_rows:
            if agent in EVAL_TOOL_AGENTS:
                continue
            entry = agent_acc.setdefault(agent, {"total": 0, "blocked": 0, "allowed": 0})
            entry["total"] += count
            verdict = _infer_verdict(outcome)
            if verdict == "DENY":
                entry["blocked"] += count
            elif verdict == "ALLOW":
                entry["allowed"] += count

        for agent, outcome, reason, count in catalog_rows:
            if agent in EVAL_TOOL_AGENTS or _infer_verdict(outcome) != "DENY":
                continue
            mechanism = _block_catalog_mechanism(outcome, reason)
            detail = _block_catalog_detail(mechanism, outcome, reason)
            entry = catalog_acc.setdefault((agent, mechanism), {"count": 0, "details": {}})
            entry["count"] += count
            entry["details"][detail] = entry["details"].get(detail, 0) + count

    latency = _latency_distribution(db_path, cutoff, agent_id)

    stage_funnel = [
        StageBucket(stage=stage, total=v["total"], blocked=v["blocked"], allowed=v["allowed"], hitl=v["hitl"])
        for stage, v in sorted(stage_acc.items(), key=lambda kv: _stage_order_key(kv[0]))
    ]
    block_reasons = [ReasonBucket(category=k, count=v) for k, v in reason_acc.items() if v > 0]
    timeline = [
        TimelinePoint(bucket=b, blocked=v["blocked"], allowed=v["allowed"], hitl=v["hitl"])
        for b, v in sorted(timeline_acc.items())
    ]
    per_agent = [
        AgentPosture(
            agent_id=agent, total=v["total"], blocked=v["blocked"], allowed=v["allowed"],
            block_rate=(v["blocked"] / v["total"]) if v["total"] else 0.0,
        )
        for agent, v in sorted(agent_acc.items(), key=lambda kv: kv[1]["total"], reverse=True)
    ]
    block_catalog = [
        BlockCatalogBucket(
            agent_id=agent,
            mechanism=mechanism,
            count=v["count"],
            details=[
                BlockCatalogDetail(detail=detail, count=detail_count)
                for detail, detail_count in sorted(v["details"].items(), key=lambda kv: (-kv[1], kv[0]))[:5]
            ],
        )
        for (agent, mechanism), v in sorted(
            catalog_acc.items(),
            key=lambda kv: (kv[0][0], _stage_order_key(kv[0][1]), -kv[1]["count"]),
        )
    ]

    result = OverviewCharts(
        window=window, db_source=db_source, stage_funnel=stage_funnel,
        block_reasons=block_reasons, block_catalog=block_catalog,
        latency=latency, timeline=timeline, per_agent=per_agent,
    )
    return _cache_set(cache_key, result, ttl=10.0)


async def get_compliance_events(article_code: str, limit: int = 20, offset: int = 0) -> list[AuditEvent]:
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    cache_key = ("compliance_events", article_code, limit, offset)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    outcomes = ARTICLE_OUTCOMES.get(article_code)
    if outcomes is None:
        return []
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []

    with sqlite3.connect(db_path, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_query_indexes(conn, db_path)

        if outcomes is _BENCHMARK_EVENTS:
            # Agent-specific index avoids scanning the whole audit table when benchmark
            # agents are absent from the live ASF DB. Fetch enough per agent, merge, page.
            per_agent_limit = limit + offset
            rows = []
            for agent in sorted(EVAL_TOOL_AGENTS):
                rows.extend(dict(row) for row in conn.execute(
                    "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                    "FROM audit_trail INDEXED BY idx_audit_trail_agent_timestamp "
                    "WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                    (agent, per_agent_limit),
                ).fetchall())
            rows.sort(key=lambda r: str(r.get("timestamp") or ""), reverse=True)
            rows = rows[offset:offset + limit]
        else:
            if outcomes is _ALL_OUTCOMES:
                query = (
                    "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                    "FROM audit_trail INDEXED BY idx_audit_trail_timestamp_desc"
                )
                params: list[Any] = []
            else:
                # Let SQLite use idx_audit_trail_outcome_timestamp for selective article
                # drill-downs instead of forcing a timestamp-only scan over the full table.
                placeholders = ",".join("?" for _ in outcomes)
                query = (
                    "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash "
                    f"FROM audit_trail WHERE outcome IN ({placeholders})"
                )
                params = list(sorted(outcomes))

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    for row in rows:
        key = (row.get("prev_hash") or row.get("hash") or "")[:12]
        row["trace_id"] = f"trace-{key}"
        row["session_id"] = f"{row.get('agent_id') or 'unknown-agent'}-{key}"
    return _cache_set(cache_key, [_normalize_event(row) for row in rows], ttl=20.0)


def _ensure_hitl_decision_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dashboard_hitl_decisions ("
        "event_id TEXT PRIMARY KEY, "
        "decision TEXT NOT NULL CHECK(decision IN ('approve', 'reject')), "
        "decided_at TEXT NOT NULL, "
        "reviewer TEXT, "
        "note TEXT"
        ")"
    )


def _pending_hitl_filter(alias: str = "a") -> str:
    # Pending HITL is one canonical definition used by both the Overview KPI and
    # the Human Oversight queue: a HITL_REQUESTED audit row with no dashboard-side
    # decision and no append-only HITL_APPROVED/HITL_REJECTED audit decision naming
    # that request. There is intentionally no time-window filter; old requests stay
    # pending until reviewed.
    return (
        f"{alias}.outcome = 'HITL_REQUESTED' "
        "AND d.event_id IS NULL "
        "AND NOT EXISTS ("
        "SELECT 1 FROM audit_trail decision "
        "WHERE decision.outcome IN ('HITL_APPROVED', 'HITL_REJECTED') "
        f"AND decision.reason LIKE ('event:' || {alias}.hash || '%')"
        ")"
    )


def _count_pending_hitl(db_path: Path, agent_id: str | None = None) -> int:
    if not _has_audit_schema(db_path):
        return 0
    agent_clause = " AND a.agent_id = ?" if agent_id else ""
    params: list[Any] = [agent_id] if agent_id else []
    with sqlite3.connect(db_path) as conn:
        _ensure_hitl_decision_table(conn)
        return int(conn.execute(
            "SELECT COUNT(*) FROM audit_trail a "
            "LEFT JOIN dashboard_hitl_decisions d ON d.event_id = a.hash "
            f"WHERE {_pending_hitl_filter('a')}{agent_clause}",
            params,
        ).fetchone()[0] or 0)


def _append_audit_event(conn: sqlite3.Connection, agent_id: str, action: str, outcome: str, reason: str) -> str:
    import hashlib

    last = conn.execute(
        "SELECT hash FROM audit_trail ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()
    prev_hash = last[0] if last else "0" * 64
    event_hash = hashlib.sha256(f"{agent_id}{action}{outcome}{reason}{prev_hash}".encode()).hexdigest()
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event_hash,
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f"),
            agent_id,
            action,
            outcome,
            reason,
            prev_hash,
        ),
    )
    return event_hash


async def get_hitl_events() -> list[AuditEvent]:
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_hitl_decision_table(conn)
        pending_filter = _pending_hitl_filter("a")
        if _has_hermes_trace_schema(db_path):
            query = (
                "SELECT a.hash, a.timestamp, a.agent_id, a.action, a.outcome, a.reason, a.prev_hash, "
                "h.agent_model AS agent_model "
                "FROM audit_trail a "
                "LEFT JOIN hermes_tool_traces h ON h.audit_hash = a.hash "
                "LEFT JOIN dashboard_hitl_decisions d ON d.event_id = a.hash "
                f"WHERE {pending_filter} "
                "ORDER BY a.timestamp DESC"
            )
        else:
            query = (
                "SELECT a.hash, a.timestamp, a.agent_id, a.action, a.outcome, a.reason, a.prev_hash, "
                "NULL AS agent_model "
                "FROM audit_trail a "
                "LEFT JOIN dashboard_hitl_decisions d ON d.event_id = a.hash "
                f"WHERE {pending_filter} "
                "ORDER BY a.timestamp DESC"
            )
        rows = [dict(row) for row in conn.execute(query).fetchall()]
        conn.commit()
    for row in rows:
        key = (row.get("prev_hash") or row.get("hash") or "")[:12]
        row["trace_id"] = f"trace-{key}"
        row["session_id"] = f"{row.get('agent_id') or 'unknown-agent'}-{key}"
    return [_normalize_event(row) for row in rows]


async def decide_hitl_event(
    event_id: str,
    decision: str,
    reviewer: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    decision = decision.strip().lower()
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")

    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        raise LookupError("audit database is unavailable")

    with sqlite3.connect(db_path, timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_hitl_decision_table(conn)
        row = conn.execute(
            "SELECT hash, agent_id, action, reason FROM audit_trail "
            "WHERE hash = ? AND outcome = 'HITL_REQUESTED'",
            (event_id,),
        ).fetchone()
        if row is None:
            raise LookupError("pending HITL event not found")

        existing = conn.execute(
            "SELECT decision, decided_at, reviewer, note FROM dashboard_hitl_decisions WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if existing is not None:
            return {
                "event_id": event_id,
                "decision": existing["decision"],
                "status": "already_decided",
                "decided_at": existing["decided_at"],
                "reviewer": existing["reviewer"],
                "note": existing["note"],
            }

        decided_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
        reviewer_value = (reviewer or "dashboard").strip() or "dashboard"
        note_value = (note or "").strip()
        conn.execute(
            "INSERT INTO dashboard_hitl_decisions (event_id, decision, decided_at, reviewer, note) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_id, decision, decided_at, reviewer_value, note_value or None),
        )
        audit_outcome = "HITL_APPROVED" if decision == "approve" else "HITL_REJECTED"
        # Include the reviewed event_id so the append-only audit row is self-contained
        # and the trail alone can identify what was reviewed (not only via the
        # dashboard_hitl_decisions side table).
        audit_reason = f"event:{event_id} reviewer:{reviewer_value} note:{note_value[:200]}"
        audit_hash = _append_audit_event(
            conn,
            row["agent_id"] or "unknown-agent",
            row["action"] or "human_review",
            audit_outcome,
            audit_reason,
        )
        conn.commit()
        _RUNTIME_CACHE.clear()

    return {
        "event_id": event_id,
        "decision": decision,
        "status": "decided",
        "decided_at": decided_at,
        "audit_event_id": audit_hash,
        "reviewer": reviewer_value,
        "note": note_value or None,
    }


async def get_agents(show_eval: bool = False) -> list[str]:
    cache = _load_dashboard_cache()
    if cache:
        agents = list(cache.get("agents", []))
        db_path = get_db_path()
        if _has_hermes_trace_schema(db_path):
            with sqlite3.connect(db_path) as conn:
                hermes_agents = [row[0] for row in conn.execute(
                    "SELECT DISTINCT agent_id FROM hermes_tool_traces WHERE agent_id IS NOT NULL"
                ).fetchall()]
            agents.extend(agent for agent in hermes_agents if agent not in agents)
        if not show_eval:
            agents = [agent for agent in agents if agent not in EVAL_TOOL_AGENTS]
        return sorted(agents)

    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return []
    with sqlite3.connect(db_path) as conn:
        query = "SELECT DISTINCT agent_id FROM audit_trail WHERE agent_id IS NOT NULL"
        params: list[str] = []
        if not show_eval:
            placeholders = ",".join("?" for _ in EVAL_TOOL_AGENTS)
            query += f" AND agent_id NOT IN ({placeholders})"
            params.extend(sorted(EVAL_TOOL_AGENTS))
        query += " ORDER BY agent_id"
        rows = conn.execute(query, params).fetchall()
    return [row[0] for row in rows]


async def get_total_event_count() -> int:
    cache = _load_dashboard_cache()
    if cache:
        return sum(int(v) for v in cache.get("outcome_counts", {}).values())
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return 0
    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM audit_trail").fetchone()[0]


async def get_total_trace_count() -> int:
    """Count intercepted tool calls using cached INTERCEPTOR_START count."""
    cache = _load_dashboard_cache()
    if cache:
        return int(cache.get("outcome_counts", {}).get("INTERCEPTOR_START", 0))
    db_path = get_db_path()
    if not _has_audit_schema(db_path):
        return 0
    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM audit_trail WHERE outcome = 'INTERCEPTOR_START'").fetchone()[0]

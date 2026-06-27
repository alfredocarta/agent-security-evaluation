import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from backend import db


def _point_dashboard_to(db_path, monkeypatch):
    monkeypatch.setattr(db, "REQUESTED_DB_PATH", db_path)
    db._RUNTIME_CACHE.clear()
    db._INDEXED_DB_PATHS.clear()


def _create_test_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    base = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    for i in range(60):
        ts = (base - timedelta(minutes=i * 6)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', ?, 'terminal', "
            "'terminal', 'args', 'ALLOW', 'ALLOWED', 'ok', 'L1.5', 1, 2, ?, ?, ?)",
            (f"h{i:03d}", ts, f"sess-{i:03d}", f"trace-{i:03d}", f"hash{i:03d}", ts),
        )

    detail_base = base - timedelta(days=1)
    for i in range(45):
        ts = (detail_base + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', 'detail-session', 'terminal', "
            "'terminal', 'args', 'ALLOW', 'ALLOWED', 'ok', 'L1.5', 1, 2, ?, ?, ?)",
            (f"detail{i:03d}", ts, f"detail-trace-{i:03d}", f"detail-hash{i:03d}", ts),
        )

    for i in range(45):
        ts = (base - timedelta(minutes=30, seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
        outcome = "BLOCKED" if i % 2 else "ALLOWED"
        conn.execute(
            "INSERT INTO audit_trail "
            "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'compliance-agent', 'tool', ?, 'compliance evidence', ?)",
            (f"audit{i:03d}", ts, outcome, f"audit-prev{i:03d}"),
        )
    conn.commit()
    conn.close()


def test_get_db_path_requires_asf_root_or_audit_db(monkeypatch):
    monkeypatch.delenv("ASF_ROOT", raising=False)
    monkeypatch.delenv("ASF_AUDIT_DB", raising=False)
    monkeypatch.setattr(db, "REQUESTED_DB_PATH", None)
    db.set_active_env("production")

    with pytest.raises(RuntimeError, match="ASF_ROOT or ASF_AUDIT_DB must be set"):
        db.get_db_path()


def test_get_db_path_rejects_missing_audit_db(tmp_path, monkeypatch):
    monkeypatch.delenv("ASF_ROOT", raising=False)
    monkeypatch.setenv("ASF_AUDIT_DB", str(tmp_path / "missing.db"))
    monkeypatch.setattr(db, "REQUESTED_DB_PATH", None)
    db.set_active_env("production")

    with pytest.raises(RuntimeError, match="audit database not found"):
        db.get_db_path()


def test_get_db_path_derives_asf_local_from_asf_root(tmp_path, monkeypatch):
    asf_root = tmp_path / "asf"
    asf_root.mkdir()
    db_path = asf_root / "asf_local.db"
    _create_test_db(db_path)
    monkeypatch.setenv("ASF_ROOT", str(asf_root))
    monkeypatch.delenv("ASF_AUDIT_DB", raising=False)
    monkeypatch.setattr(db, "REQUESTED_DB_PATH", None)
    db.set_active_env("production")

    assert db.get_db_path() == db_path


def test_get_sessions_returns_distinct_server_side_pages(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    page1 = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="hermes-live-agent"))
    page2 = asyncio.run(db.get_sessions(limit=20, offset=20, agent_id="hermes-live-agent"))

    assert len(page1) == 20
    assert len(page2) == 20
    assert page1[0].session_id.endswith("sess-000")
    assert page1[-1].session_id.endswith("sess-019")
    assert page2[0].session_id.endswith("sess-020")
    assert {s.session_id for s in page1}.isdisjoint({s.session_id for s in page2})


def test_get_sessions_cache_key_includes_offset(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    page1 = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="hermes-live-agent"))
    page2 = asyncio.run(db.get_sessions(limit=20, offset=20, agent_id="hermes-live-agent"))

    assert page1[0].session_id != page2[0].session_id
    assert ("sessions", 20, 0, "hermes-live-agent", False) in db._RUNTIME_CACHE
    assert ("sessions", 20, 20, "hermes-live-agent", False) in db._RUNTIME_CACHE


def test_compliance_drilldown_supports_limit_offset_and_offset_cache(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    page1 = asyncio.run(db.get_compliance_events("Art. 12", limit=20, offset=0))
    page2 = asyncio.run(db.get_compliance_events("Art. 12", limit=20, offset=20))

    assert len(page1) == 20
    assert len(page2) == 20
    assert page1[0].event_id != page2[0].event_id
    assert ("compliance_events", "Art. 12", 20, 0, "7d") in db._RUNTIME_CACHE
    assert ("compliance_events", "Art. 12", 20, 20, "7d") in db._RUNTIME_CACHE


def test_compliance_drilldown_preserves_real_trace_id_and_counts_unique_calls(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_trace_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT, trace_id TEXT, session_id TEXT)"
    )
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash, trace_id, session_id) "
        "VALUES ('start-hash', ?, 'hermes-live-agent', 'Bash', 'INTERCEPTOR_START', 'Interceptor invoked', '', 'real-trace-1', 'sess-1')",
        (now,),
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash, trace_id, session_id) "
        "VALUES ('terminal-hash', ?, 'hermes-live-agent', 'Bash', 'HEURISTIC_CLEAR', 'fast-path allow', 'start-hash', 'real-trace-1', 'sess-1')",
        (now,),
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    events = asyncio.run(db.get_compliance_events("Art. 12", limit=10, offset=0))
    trace_ids = {event.trace_id for event in events}
    session_ids = {event.session_id for event in events}

    assert len(events) == 2
    assert trace_ids == {"real-trace-1"}
    assert session_ids == {"sess-1"}
    assert asyncio.run(db.get_total_trace_count()) == 1


def test_session_detail_supports_limit_offset_and_cache(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    page1 = asyncio.run(db.get_session_events("hermes-live-agent-session-detail-session", limit=20, offset=0))
    page2 = asyncio.run(db.get_session_events("hermes-live-agent-session-detail-session", limit=20, offset=20))

    assert len(page1) == 20
    assert len(page2) == 20
    assert page1[0].event_id == "detail000"
    assert page2[0].event_id == "detail020"
    assert page1[0].event_id != page2[0].event_id
    assert ("session_events", "hermes-live-agent-session-detail-session", 20, 0) in db._RUNTIME_CACHE
    assert ("session_events", "hermes-live-agent-session-detail-session", 20, 20) in db._RUNTIME_CACHE


def test_session_detail_merges_extra_ids(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    events = asyncio.run(db.get_session_events(
        "hermes-live-agent-session-sess-000",
        limit=20,
        offset=0,
        extra_ids="hermes-live-agent-session-sess-001",
    ))

    assert [event.event_id for event in events] == ["h001", "h000"]


def test_hitl_approve_reject_persist_decisions_and_remove_pending(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-approve', ?, 'hermes-live-agent', 'terminal', 'HITL_REQUESTED', 'Stage 3 LLM flagged as dangerous', 'prev-a')",
        (now,),
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-reject', ?, 'hermes-live-agent', 'terminal', 'HITL_REQUESTED', 'Stage 3 LLM flagged as dangerous', 'prev-b')",
        (now,),
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    pending = asyncio.run(db.get_hitl_events())
    assert {event.event_id for event in pending} >= {"hitl-approve", "hitl-reject"}

    approved = asyncio.run(db.decide_hitl_event("hitl-approve", "approve", reviewer="alice", note="ok"))
    rejected = asyncio.run(db.decide_hitl_event("hitl-reject", "reject", reviewer="bob", note="block"))

    assert approved["status"] == "decided"
    assert rejected["status"] == "decided"
    pending_after = asyncio.run(db.get_hitl_events())
    assert "hitl-approve" not in {event.event_id for event in pending_after}
    assert "hitl-reject" not in {event.event_id for event in pending_after}

    conn = sqlite3.connect(db_path)
    decisions = dict(conn.execute("SELECT event_id, decision FROM dashboard_hitl_decisions").fetchall())
    outcomes = {row[0] for row in conn.execute("SELECT outcome FROM audit_trail WHERE outcome LIKE 'HITL_%'").fetchall()}
    hitl_reasons = [row[0] for row in conn.execute("SELECT reason FROM audit_trail WHERE outcome LIKE 'HITL_%'").fetchall()]
    conn.close()

    assert decisions["hitl-approve"] == "approve"
    assert decisions["hitl-reject"] == "reject"
    assert "HITL_APPROVED" in outcomes
    assert "HITL_REJECTED" in outcomes
    # The append-only audit row must be self-contained: it must name the reviewed event.
    assert any("event:hitl-approve" in reason for reason in hitl_reasons)
    assert any("event:hitl-reject" in reason for reason in hitl_reasons)



def test_pending_hitl_metric_matches_queue_and_excludes_decided(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    old_ts = (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S.%f")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE dashboard_hitl_decisions ("
        "event_id TEXT PRIMARY KEY, decision TEXT NOT NULL, decided_at TEXT NOT NULL, "
        "reviewer TEXT, note TEXT)"
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-pending-old', ?, 'hermes-live-agent', 'terminal', "
        "'HITL_REQUESTED', 'Stage 3 LLM flagged as dangerous', 'prev-p')",
        (old_ts,),
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-decided-side-table', ?, 'hermes-live-agent', 'terminal', "
        "'HITL_REQUESTED', 'Stage 3 LLM flagged as dangerous', 'prev-d1')",
        (now,),
    )
    conn.execute(
        "INSERT INTO dashboard_hitl_decisions (event_id, decision, decided_at, reviewer, note) "
        "VALUES ('hitl-decided-side-table', 'approve', ?, 'alice', 'ok')",
        (now,),
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-decided-audit-only', ?, 'hermes-live-agent', 'terminal', "
        "'HITL_REQUESTED', 'Stage 3 LLM flagged as dangerous', 'prev-d2')",
        (now,),
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-decision-row', ?, 'hermes-live-agent', 'terminal', "
        "'HITL_REJECTED', 'event:hitl-decided-audit-only reviewer:bob note:block', 'hitl-decided-audit-only')",
        (now,),
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    pending = asyncio.run(db.get_hitl_events())
    metrics = asyncio.run(db.get_metrics(agent_id="hermes-live-agent"))

    pending_ids = {event.event_id for event in pending}
    assert pending_ids == {"hitl-pending-old"}
    assert metrics.hitl_count == len(pending) == 1

def test_stage3_onnx_prompt_guard_is_not_labeled_gemma():
    ev = db._normalize_event({
        "hash": "onnx-event",
        "timestamp": "2026-06-03 12:00:00",
        "agent_id": "hermes-live-agent",
        "action": "terminal",
        "outcome": "ALLOWED",
        "reason": "Stage 3 ONNX Prompt Guard cleared - safe input",
        "prev_hash": "prev",
    })

    assert ev.stage == "Stage 3 ONNX Prompt Guard"
    assert ev.security_model == "Stage 3 ONNX Prompt Guard"
    assert "Gemma" not in ev.security_model


def _create_overlap_metrics_db(path):
    """A call that passes through the interceptor lands in BOTH audit_trail and
    hermes_tool_traces. This fixture mirrors that reality (the existing fixtures keep
    the two tables disjoint) so KPI double-counting is actually exercised."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    now = datetime.utcnow()
    outcomes = ["ALLOWED", "BLOCKED", "ALLOWED", "BLOCKED", "ALLOWED"]
    for i, outcome in enumerate(outcomes):
        ts_start = (now - timedelta(seconds=i * 2 + 1)).strftime("%Y-%m-%d %H:%M:%S.%f")
        ts_end = (now - timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S.%f")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'hermes-live-agent', 'terminal', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)",
            (f"start{i:03d}", ts_start),
        )
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'hermes-live-agent', 'terminal', ?, 'decided', ?)",
            (f"term{i:03d}", ts_end, outcome, f"start{i:03d}"),
        )
        verdict = "ALLOW" if outcome == "ALLOWED" else "DENY"
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', ?, 'terminal', "
            "'terminal', 'args', ?, ?, 'ok', 'L1.5', 1, 2, ?, ?, ?)",
            (f"h{i:03d}", ts_end, f"sess-{i:03d}", verdict, outcome, f"trace-{i:03d}", f"start{i:03d}", ts_end),
        )
    conn.commit()
    conn.close()


def test_metrics_do_not_double_count_hermes_calls(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_overlap_metrics_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)
    monkeypatch.setattr(db, "_load_dashboard_cache", lambda: {})

    metrics = asyncio.run(db.get_metrics(agent_id="hermes-live-agent"))

    # 5 interceptor calls exist in BOTH audit_trail and hermes_tool_traces; they must
    # be counted once (from audit_trail), not summed across both into 10.
    assert metrics.total_tool_calls == 5
    assert metrics.allowed_count == 3
    assert metrics.blocked_count == 2
    assert metrics.hitl_count == 0
    assert metrics.tool_calls_last_24h == 5


def _create_cache_branch_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT, trace_id TEXT)"
    )
    now = datetime.utcnow()
    for i in range(3):  # within 24h
        ts = (now - timedelta(hours=1, minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash, trace_id) "
            "VALUES (?, ?, 'claude-code-agent', 'shell', 'HEURISTIC_CLEAR', 'Cleared', NULL, ?)",
            (f"recent{i:03d}", ts, f"recent-trace-{i:03d}"),
        )
    for i in range(2):  # older than 24h
        ts = (now - timedelta(days=3, minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash, trace_id) "
            "VALUES (?, ?, 'claude-code-agent', 'shell', 'HEURISTIC_CLEAR', 'Cleared', NULL, ?)",
            (f"old{i:03d}", ts, f"old-trace-{i:03d}"),
        )
    conn.commit()
    conn.close()


def test_cache_branch_last_24h_is_windowed_not_lifetime_total(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_cache_branch_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    now = datetime.utcnow()
    fake_cache = {
        "outcome_counts": {"INTERCEPTOR_START": 1000, "ALLOWED": 600, "BLOCKED": 400},
        "max_interceptor_ts": now.isoformat(),
        "min_interceptor_ts": (now - timedelta(days=30)).isoformat(),
    }
    monkeypatch.setattr(db, "_load_dashboard_cache", lambda: fake_cache)
    monkeypatch.setattr(db, "_dashboard_cache_is_stale", lambda *a, **k: False)

    metrics = asyncio.run(db.get_metrics())

    # Lifetime totals come from the cache, but last-24h must be the real windowed
    # count from audit_trail (3 recent rows), never the 1000-call lifetime total.
    assert metrics.total_tool_calls == 1000
    assert metrics.blocked_count == 400
    assert metrics.allowed_count == 600
    assert metrics.tool_calls_last_24h == 3


def _create_terminal_only_kpi_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT, trace_id TEXT)"
    )
    now = datetime.utcnow()
    rows = [
        ("call-a", "HEURISTIC_CLEAR", now - timedelta(minutes=2), "ok"),
        ("call-b", "BLOCKED", now - timedelta(minutes=1), "Stage 1 regex match"),
        ("call-c", "KILL_SWITCH", now - timedelta(days=2), "Stage 2.5 DeBERTa"),
    ]
    for trace_id, outcome, ts, reason in rows:
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash, trace_id) "
            "VALUES (?, ?, 'hermes-live-agent', 'terminal', ?, ?, NULL, ?)",
            (f"hash-{trace_id}", ts.strftime("%Y-%m-%d %H:%M:%S.%f"), outcome, reason, trace_id),
        )
    conn.commit()
    conn.close()


def test_metrics_count_distinct_terminal_trace_ids_without_interceptor_start(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_terminal_only_kpi_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)
    monkeypatch.setattr(db, "_load_dashboard_cache", lambda: {})

    metrics = asyncio.run(db.get_metrics(agent_id="hermes-live-agent"))

    assert metrics.total_tool_calls == 3
    assert metrics.tool_calls_last_24h == 2
    assert metrics.allowed_count == 1
    assert metrics.blocked_count == 2
    assert metrics.avg_latency_ms == 0.0
    assert metrics.p95_latency_ms == 0.0
    assert metrics.data_as_of is not None


def test_cache_branch_counts_recent_terminal_trace_ids_and_freshness(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_terminal_only_kpi_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)
    now = datetime.utcnow()
    fake_cache = {
        "terminal_trace_count": 1,
        "terminal_outcome_counts": {"HEURISTIC_CLEAR": 1},
        "max_terminal_ts": (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
        "min_terminal_ts": (now - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S"),
    }
    monkeypatch.setattr(db, "_load_dashboard_cache", lambda: fake_cache)
    monkeypatch.setattr(db, "_dashboard_cache_is_stale", lambda *a, **k: False)

    metrics = asyncio.run(db.get_metrics())

    assert metrics.tool_calls_last_24h == 2
    assert metrics.total_tool_calls == 3
    assert metrics.data_as_of is not None
    assert db._parse_timestamp(metrics.data_as_of) >= now - timedelta(minutes=5)


def _create_charts_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    now = datetime.utcnow()
    rows = [
        ("hermes-live-agent", "HEURISTIC_CLEAR", "Cleared by heuristic fast-path (score=0.00)"),
        ("hermes-live-agent", "HEURISTIC_CLEAR", "Cleared by heuristic fast-path (score=0.01)"),
        ("hermes-live-agent", "BLOCKED", "Agent suspended or not found"),
        ("hermes-live-agent", "BLOCKED", "Tool 'vision_analyze' not in permissions: ['browser']"),
        ("hermes-live-agent", "KILL_SWITCH", "Stage 2.5 DeBERTa: INJECTION p=0.99"),
        ("claude-code-agent", "KILL_SWITCH", "Stage 1 regex match: ignore previous instructions"),
        ("claude-code-agent", "OUTPUT_BLOCK", "Output guard blocked canary leak"),
    ]
    for i, (agent, outcome, reason) in enumerate(rows):
        ts = (now - timedelta(minutes=i + 1)).strftime("%Y-%m-%d %H:%M:%S.%f")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, ?, 'terminal', ?, ?, NULL)",
            (f"a{i:03d}", ts, agent, outcome, reason),
        )
    for i, latency in enumerate([5, 18, 40, 120]):
        ts = (now - timedelta(minutes=i + 1)).strftime("%Y-%m-%d %H:%M:%S.%f")
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, hermes_tool_name, asf_tool_name, args_hash, verdict, "
            "asf_latency_ms, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'terminal', 'terminal', 'args', 'ALLOW', ?, ?)",
            (f"h{i:03d}", ts, latency, ts),
        )
    conn.commit()
    conn.close()


def test_metrics_exclude_governance_rbac_denials(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    now = datetime.utcnow()
    # 6 calls: 2 cleared, 2 governance-blocked, 1 RBAC-blocked, 1 content kill-switch.
    rows = [
        ("HEURISTIC_CLEAR", "Cleared by heuristic fast-path (score=0.00)"),
        ("HEURISTIC_CLEAR", "Cleared by heuristic fast-path (score=0.01)"),
        ("BLOCKED", "Agent suspended or not found"),
        ("BLOCKED", "Agent suspended or not found"),
        ("BLOCKED", "Tool 'vision_analyze' not in permissions: ['browser']"),
        ("KILL_SWITCH", "KILL SWITCH ACTIVATED (Stage 2.5 DeBERTa)"),
    ]
    for i, (outcome, reason) in enumerate(rows):
        ts = (now - timedelta(minutes=i + 1)).strftime("%Y-%m-%d %H:%M:%S.%f")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'hermes-live-agent', 'terminal', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)",
            (f"s{i:03d}", ts),
        )
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'hermes-live-agent', 'terminal', ?, ?, ?)",
            (f"t{i:03d}", ts, outcome, reason, f"s{i:03d}"),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    # agent_id set => skip the cache branch and hit the audit_trail path directly.
    metrics = asyncio.run(db.get_metrics(agent_id="hermes-live-agent"))

    # 3 governance/RBAC denials excluded: total 6 -> 3, blocked 4 -> 1 (the kill-switch),
    # allowed 2, detection_rate = 1 / (1 + 2).
    assert metrics.total_tool_calls == 3
    assert metrics.blocked_count == 1
    assert metrics.allowed_count == 2
    assert abs(metrics.detection_rate - (1 / 3)) < 1e-9


def test_overview_charts_buckets_stages_reasons_and_latency(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_charts_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    charts = asyncio.run(db.get_overview_charts(window="24h"))
    stages = {s.stage: s for s in charts.stage_funnel}
    reasons = {r.category: r.count for r in charts.block_reasons}

    # Governance + RBAC denials are excluded from every chart dataset (funnel + reasons).
    assert "Governance / RBAC" not in stages
    assert "governance" not in reasons
    assert "rbac" not in reasons
    assert stages["L1.5 fast-path"].allowed == 2
    assert stages["L1.5 fast-path"].blocked == 0
    assert stages["Stage 2.5 DeBERTa"].blocked == 1
    assert stages["Stage 1"].blocked == 1
    assert stages["Output Guard"].blocked == 1
    assert reasons["content_detection"] == 2
    assert reasons["output_guard"] == 1

    catalog = {(b.agent_id, b.mechanism): b for b in charts.block_catalog}
    assert ("hermes-live-agent", "Stage 2.5 DeBERTa") in catalog
    assert catalog[("hermes-live-agent", "Stage 2.5 DeBERTa")].count == 1
    assert catalog[("hermes-live-agent", "Stage 2.5 DeBERTa")].details[0].detail == "INJECTION score 0.9-1.0"
    assert catalog[("claude-code-agent", "Stage 1")].details[0].detail.startswith("regex:")
    assert catalog[("claude-code-agent", "Output Guard")].count == 1
    assert not any(b.mechanism in {"Governance / RBAC", "L1.5"} for b in charts.block_catalog)

    # Funnel rows follow control-pipeline order, not descending volume.
    order = [s.stage for s in charts.stage_funnel]
    # No duplicate stage labels in the funnel.
    assert len(order) == len(set(order)), f"Duplicate stage labels: {order}"
    assert order.index("L1.5 fast-path") < order.index("Stage 2.5 DeBERTa")

    # Latency comes only from hermes_tool_traces.
    assert charts.latency.sample_count == 4
    assert sum(b.count for b in charts.latency.buckets) == 4
    assert {a.agent_id for a in charts.per_agent} == {"hermes-live-agent", "claude-code-agent"}


def test_get_sessions_computes_legacy_audit_duration(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('start-hash', '2026-06-03 12:00:00.100000', 'claude-code-agent', "
        "'shell', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)"
    )
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('stage-hash', '2026-06-03 12:00:00.250000', 'claude-code-agent', "
        "'shell', 'STAGE_1_START', 'Regex pattern analysis', 'start-hash')"
    )
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('terminal-hash', '2026-06-03 12:00:00.475000', 'claude-code-agent', "
        "'shell', 'BLOCKED', 'blocked', 'stage-hash')"
    )
    conn.commit()
    conn.close()

    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="claude-code-agent"))

    assert len(sessions) == 1
    assert sessions[0].duration_ms == 375


def test_event_explanation_exposes_hermes_input_output_and_model(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE hermes_tool_traces SET args_preview = ?, output_preview = ?, agent_model = ? WHERE id = 'h000'",
        ('{"command": "printf hello"}', '"hello"', "gpt-5.5 via openai-codex"),
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    explanation = asyncio.run(db.get_event_explanation("h000"))

    assert explanation.tool_name == "terminal"
    assert explanation.agent_id == "hermes-live-agent"
    assert explanation.agent_model == "gpt-5.5 via openai-codex"
    assert explanation.tool_input == '{"command": "printf hello"}'
    assert explanation.tool_output == '"hello"'
    assert explanation.input_truncated is False
    assert explanation.output_truncated is False


def test_event_explanation_audit_only_has_no_input_output(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('audit-only-start', '2026-06-03 13:00:00', 'claude-code-agent', "
        "'shell', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)"
    )
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('audit-only-terminal', '2026-06-03 13:00:01', 'claude-code-agent', "
        "'shell', 'ALLOWED', 'cleared', 'audit-only-start')"
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    explanation = asyncio.run(db.get_event_explanation("audit-only-terminal"))

    assert explanation.tool_name == "shell"
    assert explanation.agent_id == "claude-code-agent"
    assert explanation.tool_input is None
    assert explanation.tool_output is None
    assert explanation.agent_model == "claude-sonnet-4-6 via MCP"


def test_event_explanation_exposes_claude_input_output_and_model(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE claude_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'claude-code', "
        "agent_id TEXT NOT NULL, agent_model TEXT, session_id TEXT, transcript_path TEXT, "
        "tool_call_id TEXT, claude_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('claude-start', '2026-06-03 14:00:00', 'claude-code-agent', "
        "'shell', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)"
    )
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('claude-terminal', '2026-06-03 14:00:01', 'claude-code-agent', "
        "'shell', 'BLOCKED', 'blocked', 'claude-start')"
    )
    conn.execute(
        "INSERT INTO claude_tool_traces "
        "(id, timestamp, agent_id, agent_model, session_id, tool_call_id, claude_tool_name, "
        "asf_tool_name, args_hash, args_preview, output_hash, output_preview, verdict, outcome, "
        "reason, trace_id, audit_hash, created_at) "
        "VALUES ('ct1', '2026-06-03T14:00:01', 'claude-code-agent', 'claude-opus-test', "
        "'session-claude', 'call-1', 'Bash', 'shell', 'args', '{\"command\": \"grep bad file\"}', "
        "'out', '{\"stdout\": \"match\"}', 'DENY', 'BLOCKED', 'blocked', 'trace-c1', "
        "'claude-terminal', '2026-06-03T14:00:01')"
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    explanation = asyncio.run(db.get_event_explanation("claude-terminal"))

    assert explanation.agent_id == "claude-code-agent"
    assert explanation.agent_model == "claude-opus-test"
    assert explanation.tool_name == "Bash"
    assert explanation.tool_input == '{"command": "grep bad file"}'
    assert explanation.tool_output == '{"stdout": "match"}'


def test_event_explanation_links_claude_trace_by_audit_trace_id_for_fast_path_allow(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT, trace_id TEXT)"
    )
    conn.execute(
        "CREATE TABLE claude_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'claude-code', "
        "agent_id TEXT NOT NULL, agent_model TEXT, session_id TEXT, transcript_path TEXT, "
        "tool_call_id TEXT, claude_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO audit_trail "
        "(hash, timestamp, agent_id, action, outcome, reason, prev_hash, trace_id) "
        "VALUES ('fast-allow-audit-event', '2026-06-03 15:00:00', 'claude-code-agent', "
        "'shell', 'ALLOWED', 'fast path clear', NULL, 'shared-fast-trace')"
    )
    conn.execute(
        "INSERT INTO claude_tool_traces "
        "(id, timestamp, agent_id, agent_model, session_id, tool_call_id, claude_tool_name, "
        "asf_tool_name, args_hash, args_preview, output_hash, output_preview, verdict, outcome, "
        "reason, trace_id, audit_hash, created_at) "
        "VALUES ('claude-row-not-event-id', '2026-06-03T15:00:00', 'claude-code-agent', "
        "'claude-sonnet-test', 'session-claude', 'call-fast', 'Bash', 'shell', 'args', "
        "'{\"command\": \"printf fast\"}', 'out', '{\"stdout\": \"fast\"}', "
        "'ALLOW', 'ALLOWED', 'fast path clear', 'shared-fast-trace', NULL, "
        "'2026-06-03T15:00:00')"
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    explanation = asyncio.run(db.get_event_explanation("fast-allow-audit-event"))

    assert explanation.final_verdict == "ALLOW"
    assert explanation.final_outcome == "ALLOWED"
    assert explanation.trace_id == "shared-fast-trace"
    assert explanation.tool_name == "Bash"
    assert explanation.tool_input == '{"command": "printf fast"}'
    assert explanation.tool_output == '{"stdout": "fast"}'


def test_hermes_trace_explanation_recovers_full_pipeline_from_audit_trail(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)

    # A real Hermes tool call lands as ONE summary row in hermes_tool_traces (no
    # per-stage steps, no audit_hash back-link) and as a hash-chained per-stage
    # sequence in audit_trail. The chain is what carries the decision path.
    chain = [
        ("c-int", "INTERCEPTOR_START", "Interceptor invoked", None),
        ("c-s1s", "STAGE_1_START", "Regex pattern analysis", "c-int"),
        ("c-s1p", "STAGE_1_PASS", "No dangerous pattern matched", "c-s1s"),
        ("c-s2s", "STAGE_2_START", "ML classifier analysis", "c-s1p"),
        ("c-s2u", "STAGE_2_UNCERTAIN", "Classifier uncertain (confidence: 0.42)", "c-s2s"),
        ("c-25s", "STAGE_2.5_START", "DeBERTa fast gate", "c-s2u"),
        ("c-25v", "STAGE_2.5A_VERDICT", "DeBERTa verdict: DANGEROUS", "c-25s"),
        ("c-kill", "KILL_SWITCH", "KILL SWITCH ACTIVATED (Stage 2.5 DeBERTa)", "c-25v"),
    ]
    for h, outcome, reason, prev in chain:
        conn.execute(
            # audit_trail stores space-separated timestamps; hermes_tool_traces stores ISO 'T'.
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, '2026-06-07 18:28:16', 'hermes-live-agent', 'shell', ?, ?, ?)",
            (h, outcome, reason, prev),
        )
    # Hermes summary row: native tool name 'terminal', ASF tool 'shell', DENY,
    # audit_hash empty (the pre-fix data shape this recovery path targets).
    conn.execute(
        "INSERT INTO hermes_tool_traces "
        "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
        "asf_tool_name, args_hash, args_preview, output_preview, verdict, outcome, reason, stage, asf_latency_ms, "
        "tool_duration_ms, trace_id, audit_hash, created_at) "
        "VALUES ('htrace-deny', '2026-06-07T18:28:16', 'hermes-live-agent', 'Hermes Agent', "
        "'gpt-5.5', 'sess-deny', 'terminal', 'shell', 'args', '{\"command\": \"rm -rf /tmp/x\"}', "
        "'{\"exit_code\": 1}', 'DENY', 'BLOCKED', "
        "'KILL SWITCH ACTIVATED (Stage 2.5 DeBERTa)', NULL, NULL, 5368, NULL, NULL, "
        "'2026-06-07T18:28:16')"
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    explanation = asyncio.run(db.get_event_explanation("htrace-deny"))

    # Despite the missing audit_hash, the explanation rebuilds the full 8-stage path
    # by matching agent_id + ASF tool + verdict within the time window.
    outcomes = [stage.outcome for stage in explanation.pipeline]
    assert len(explanation.pipeline) == 8
    assert outcomes[0] == "INTERCEPTOR_START"
    assert "KILL_SWITCH" in outcomes
    assert explanation.final_verdict == "DENY"
    assert explanation.agent_model == "gpt-5.5"
    assert explanation.tool_input == '{"command": "rm -rf /tmp/x"}'
    assert explanation.tool_output == '{"exit_code": 1}'


def test_hermes_trace_explanation_falls_back_when_no_audit_chain(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    _point_dashboard_to(db_path, monkeypatch)

    # _create_test_db writes ALLOW hermes traces with no matching audit_trail chain
    # for hermes-live-agent; the explanation must still return the single summary node.
    explanation = asyncio.run(db.get_event_explanation("h000"))

    assert len(explanation.pipeline) == 1
    assert explanation.pipeline[0].terminal is True



def test_hermes_trace_explanation_uses_exact_row_when_trace_id_collides(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)

    rows = [
        ("old-start", "2026-06-09 12:00:00", "INTERCEPTOR_START", "Interceptor invoked", None),
        ("old-clear", "2026-06-09 12:00:01", "HEURISTIC_CLEAR", "Cleared old", "old-start"),
        ("new-start", "2026-06-09 12:05:00", "INTERCEPTOR_START", "Interceptor invoked", "old-clear"),
        ("new-clear", "2026-06-09 12:05:01", "HEURISTIC_CLEAR", "Cleared new", "new-start"),
    ]
    for h, ts, outcome, reason, prev in rows:
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'hermes-live-agent', 'shell', ?, ?, ?)",
            (h, ts, outcome, reason, prev),
        )

    for row_id, ts, audit_hash, reason in [
        ("h-collide-old", "2026-06-09T12:00:01", "old-clear", "Cleared old"),
        ("h-collide-new", "2026-06-09T12:05:01", "new-clear", "Cleared new"),
    ]:
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
            "asf_tool_name, args_hash, args_preview, output_preview, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', 'sess-collide', "
            "'terminal', 'shell', 'same-args', '{\"command\": \"printf same\"}', '{\"stdout\": \"ok\"}', "
            "'ALLOW', 'ALLOWED', ?, NULL, 1, 2, 'shared-trace-id', ?, ?)",
            (row_id, ts, reason, audit_hash, ts),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    explanation = asyncio.run(db.get_event_explanation("h-collide-new"))

    outcomes = [stage.outcome for stage in explanation.pipeline]
    assert outcomes == ["INTERCEPTOR_START", "HEURISTIC_CLEAR"]
    assert [stage.terminal for stage in explanation.pipeline].count(True) == 1
    assert explanation.final_reason == "Cleared new"

    explanation_by_audit_hash = asyncio.run(db.get_event_explanation("new-clear"))
    assert [stage.outcome for stage in explanation_by_audit_hash.pipeline] == ["INTERCEPTOR_START", "HEURISTIC_CLEAR"]
    assert [stage.terminal for stage in explanation_by_audit_hash.pipeline].count(True) == 1

def test_get_sessions_dedupes_hermes_trace_against_audit_session(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    # One logical Hermes call recorded in BOTH tables at the same wall-clock time:
    # a per-stage chain in audit_trail (authoritative '-group-' session) and a summary
    # row in hermes_tool_traces (task-keyed). It must surface as ONE session, not two.
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('a-int', '2026-06-08 09:49:47', 'hermes-live-agent', 'shell', "
        "'INTERCEPTOR_START', 'Interceptor invoked', NULL)"
    )
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('a-clear', '2026-06-08 09:49:47', 'hermes-live-agent', 'shell', "
        "'HEURISTIC_CLEAR', 'Cleared by heuristic fast-path (score=0.00)', 'a-int')"
    )
    conn.execute(
        "INSERT INTO hermes_tool_traces "
        "(id, timestamp, agent_id, agent_type, session_id, task_id, tool_call_id, hermes_tool_name, "
        "asf_tool_name, args_hash, verdict, outcome, reason, asf_latency_ms, tool_duration_ms, "
        "trace_id, audit_hash, created_at) "
        "VALUES ('h-dup', '2026-06-08T09:49:47', 'hermes-live-agent', 'Hermes Agent', NULL, 'task-9', "
        "'call-9', 'terminal', 'shell', 'args', 'ALLOW', 'ALLOWED', 'ok', 5, 7, 'trace-9', NULL, "
        "'2026-06-08T09:49:47')"
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="hermes-live-agent"))

    # The audit-trail '-group-' session is kept; the Hermes '-task-' duplicate is dropped.
    assert len(sessions) == 1
    assert "-group-" in sessions[0].session_id
    assert "-task-" not in sessions[0].session_id


def test_hermes_recorded_agent_model_surfaces_in_sessions_and_explanation(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE hermes_tool_traces SET agent_model = ? WHERE id = 'h000'",
        ("qwen 3.5 via openrouter",),
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=1, offset=0, agent_id="hermes-live-agent"))
    explanation = asyncio.run(db.get_event_explanation("h000"))

    assert sessions[0].agent_model == "qwen 3.5 via openrouter"
    assert explanation.agent_model == "qwen 3.5 via openrouter"


def test_hermes_absent_agent_model_is_not_recorded_not_hardcoded(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE hermes_tool_traces SET agent_model = NULL WHERE id = 'h000'")
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=1, offset=0, agent_id="hermes-live-agent"))
    explanation = asyncio.run(db.get_event_explanation("h000"))

    assert sessions[0].agent_model == "not recorded"
    assert explanation.agent_model == "not recorded"
    assert sessions[0].agent_model != "gpt-5.5 via openai-codex"
    assert explanation.agent_model != "gpt-5.5 via openai-codex"


def test_hitl_events_use_recorded_hermes_agent_model(tmp_path, monkeypatch):
    db_path = tmp_path / "asf_test.db"
    _create_test_db(db_path)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
        "VALUES ('hitl-qwen', ?, 'hermes-live-agent', 'terminal', 'HITL_REQUESTED', 'review', 'prev-q')",
        (now,),
    )
    conn.execute(
        "INSERT INTO hermes_tool_traces "
        "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
        "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
        "tool_duration_ms, trace_id, audit_hash, created_at) "
        "VALUES ('hitl-trace-qwen', ?, 'hermes-live-agent', 'Hermes Agent', 'qwen 3.5 via openrouter', "
        "'hitl-session', 'terminal', 'terminal', 'args', 'HITL', 'HITL_REQUESTED', 'review', "
        "'L1.5', 1, 2, 'hitl-trace-qwen', 'hitl-qwen', ?)",
        (now, now),
    )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    pending = asyncio.run(db.get_hitl_events())
    event = next(ev for ev in pending if ev.event_id == "hitl-qwen")

    assert event.agent_model == "qwen 3.5 via openrouter"


def test_hermes_events_with_same_task_id_group_into_one_session_despite_gap(tmp_path, monkeypatch):
    """Hermes events sharing task_id must group into ONE session even across >30s gaps."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    
    # Create Hermes events with same task_id but >30s gap between them
    base_ts = datetime(2026, 6, 10, 10, 0, 0)
    for i, seconds_offset in enumerate([0, 45, 90]):  # 45s and 90s gaps > 30s threshold
        ts = (base_ts + timedelta(seconds=seconds_offset)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, task_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', 'same-task-123', "
            "'terminal', 'shell', 'args', 'ALLOW', 'ALLOWED', 'ok', 'L1.5', 10, 20, ?, ?, ?)",
            (f"h{i:03d}", ts, f"trace-{i:03d}", f"audit-{i:03d}", ts),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="hermes-live-agent"))

    # All events with same task_id should be in ONE session, not split by 30s gap
    assert len(sessions) == 1
    assert "task-same-task-123" in sessions[0].session_id
    assert sessions[0].total_events == 3


def test_get_session_events_returns_events_for_hermes_task_session(tmp_path, monkeypatch):
    """Detail view must resolve a real {agent}-task-{id} session even though the
    agent id (hermes-live-agent) contains hyphens."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    base_ts = datetime(2026, 6, 10, 10, 0, 0)
    for i, off in enumerate([0, 45, 90]):
        ts = (base_ts + timedelta(seconds=off)).strftime("%Y-%m-%d %H:%M:%S")
        audit_hash = f"auditfull-{i:03d}"
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'hermes-live-agent', 'shell', 'ALLOWED', 'ok', ?)",
            (audit_hash, ts, f"prev-{i:03d}"),
        )
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, task_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', 'detail-task-9', "
            "'terminal', 'shell', 'args', 'ALLOW', 'ALLOWED', 'ok', 'L1.5', 10, 20, ?, ?, ?)",
            (f"h{i:03d}", ts, f"trace-{i:03d}", audit_hash, ts),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    events = asyncio.run(db.get_session_events("hermes-live-agent-task-detail-task-9", limit=20, offset=0))
    assert len(events) == 3


def test_get_session_events_excludes_interceptor_start_rows(tmp_path, monkeypatch):
    """Non-terminal stage events (INTERCEPTOR_START) must not appear as timeline rows."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE claude_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, agent_id TEXT, agent_model TEXT, "
        "session_id TEXT, transcript_path TEXT, tool_call_id TEXT, claude_tool_name TEXT, "
        "asf_tool_name TEXT, args_hash TEXT, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT)"
    )
    base_ts = datetime(2026, 6, 10, 12, 0, 0)
    for i in range(2):
        ts = (base_ts + timedelta(seconds=i * 10)).strftime("%Y-%m-%d %H:%M:%S")
        term_hash = f"claudeterm-{i:03d}"
        # Terminal decision event for this call
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'claude-code-agent', 'file_read', 'ALLOWED', 'ok', ?)",
            (term_hash, ts, f"prev-{i:03d}"),
        )
        # Intermediate INTERCEPTOR_START whose prev_hash points at the terminal hash
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'claude-code-agent', 'file_read', 'INTERCEPTOR_START', 'start', ?)",
            (f"claudestart-{i:03d}", ts, term_hash),
        )
        conn.execute(
            "INSERT INTO claude_tool_traces (id, timestamp, agent_id, session_id, claude_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'claude-code-agent', 'uuid-abc', 'Read', 'file_read', 'args', 'ALLOW', "
            "'ALLOWED', 'ok', ?, ?, ?)",
            (f"c{i:03d}", ts, f"ctrace-{i:03d}", term_hash, ts),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    events = asyncio.run(db.get_session_events("claude-code-agent-session-uuid-abc", limit=20, offset=0))
    assert len(events) == 2
    assert all((e.outcome or "") != "INTERCEPTOR_START" for e in events)


def test_claude_events_with_same_transcript_path_group_into_one_session(tmp_path, monkeypatch):
    """Claude events sharing transcript_path must group into one session."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE claude_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, agent_id TEXT NOT NULL, agent_model TEXT, "
        "session_id TEXT, transcript_path TEXT, tool_call_id TEXT, claude_tool_name TEXT, "
        "asf_tool_name TEXT NOT NULL, args_preview TEXT, output_preview TEXT, verdict TEXT, "
        "outcome TEXT, reason TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    
    # Create Claude events with different generated session ids but one transcript_path.
    transcript_uuid = "a3ff43fa-1234-5678-9abc-def012345678"
    transcript_path = f"/Users/alfredo/.claude/projects/demo/{transcript_uuid}.jsonl"
    base_ts = datetime(2026, 6, 10, 10, 0, 0)
    for i, seconds_offset in enumerate([0, 60, 120]):  # 60s and 120s gaps
        ts = (base_ts + timedelta(seconds=seconds_offset)).strftime("%Y-%m-%d %H:%M:%S")
        audit_hash = f"audit-claude-{i:03d}"
        conn.execute(
            "INSERT INTO audit_trail "
            "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'claude-code-agent', 'shell', 'ALLOWED', 'ok', ?)",
            (audit_hash, ts, f"prev-{i:03d}"),
        )
        conn.execute(
            "INSERT INTO claude_tool_traces "
            "(id, timestamp, agent_id, agent_model, session_id, transcript_path, tool_call_id, claude_tool_name, "
            "asf_tool_name, args_preview, verdict, outcome, reason, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'claude-code-agent', 'claude-sonnet-4-6', ?, ?, 'call-?', 'shell', 'shell', "
            "'args', 'ALLOW', 'ALLOWED', 'ok', ?, ?, ?)",
            (f"claude-{i:03d}", ts, f"generated-session-{i:03d}", transcript_path, f"trace-{i:03d}", audit_hash, ts),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="claude-code-agent"))

    assert len(sessions) == 1
    assert f"transcript-{transcript_uuid}" in sessions[0].session_id
    assert sessions[0].total_events == 3

    events = asyncio.run(db.get_session_events(sessions[0].session_id, limit=20, offset=0))
    assert len(events) == 3


def test_claude_audit_trail_session_id_groups_and_returns_events_without_trace_rows(tmp_path, monkeypatch):
    """Claude audit_trail.session_id is authoritative when claude_tool_traces is empty."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT, session_id TEXT)"
    )
    conn.execute(
        "CREATE TABLE claude_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, agent_id TEXT, agent_model TEXT, "
        "session_id TEXT, transcript_path TEXT, tool_call_id TEXT, claude_tool_name TEXT, "
        "asf_tool_name TEXT, args_hash TEXT, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT)"
    )
    claude_session_uuid = "3f1e3fb4-1111-4222-9333-abcdef123456"
    base_ts = datetime(2026, 6, 11, 9, 0, 0)
    for i, (action, outcome) in enumerate([("Bash", "ALLOWED"), ("Read", "BLOCKED")]):
        ts = (base_ts + timedelta(seconds=i * 90)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_trail "
            "(hash, timestamp, agent_id, action, outcome, reason, prev_hash, session_id) "
            "VALUES (?, ?, 'claude-code', ?, ?, 'ok', ?, ?)",
            (f"claude-session-event-{i}", ts, action, outcome, f"prev-{i}", claude_session_uuid),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="claude-code"))

    assert len(sessions) == 1
    assert sessions[0].session_id == f"claude-code-session-{claude_session_uuid}"
    assert "-session-" in sessions[0].session_id
    assert sessions[0].total_events == 2

    events = asyncio.run(db.get_session_events(sessions[0].session_id, limit=20, offset=0))

    assert [event.event_id for event in events] == ["claude-session-event-0", "claude-session-event-1"]
    assert [event.action for event in events] == ["Bash", "Read"]


def test_events_without_real_ids_fall_back_to_time_gap_grouping(tmp_path, monkeypatch):
    """Events with no session_id/task_id must fall back to 30-second time-gap heuristic."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    
    # Create events: first two within 30s (same session), third after 60s gap (new session)
    base_ts = datetime(2026, 6, 10, 10, 0, 0)
    for i, seconds_offset in enumerate([0, 20, 60]):  # 20s gap (same), 60s gap (new session)
        ts = (base_ts + timedelta(seconds=seconds_offset)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_trail "
            "(hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'test-agent', 'shell', 'ALLOWED', 'ok', ?)",
            (f"hash-{i:03d}", ts, f"prev-{i:03d}"),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="test-agent"))

    assert len(sessions) == 1
    assert sessions[0].total_events == 3
    assert sessions[0].constituent_ids is not None
    assert len(sessions[0].constituent_ids) == 2


def test_different_task_ids_within_five_minutes_are_merged(tmp_path, monkeypatch):
    """Nearby sessions for the same agent are merged even when source task ids differ."""
    db_path = tmp_path / "asf_test.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE audit_trail ("
        "hash TEXT PRIMARY KEY, timestamp TEXT, agent_id TEXT, action TEXT, "
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE hermes_tool_traces ("
        "id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'hermes', "
        "agent_id TEXT NOT NULL, agent_type TEXT, agent_model TEXT, session_id TEXT, task_id TEXT, "
        "tool_call_id TEXT, hermes_tool_name TEXT NOT NULL, asf_tool_name TEXT NOT NULL, "
        "args_hash TEXT NOT NULL, args_preview TEXT, output_hash TEXT, output_preview TEXT, "
        "verdict TEXT, outcome TEXT, reason TEXT, stage TEXT, confidence REAL, "
        "asf_latency_ms INTEGER, tool_duration_ms INTEGER, side_effect_verified INTEGER DEFAULT 0, "
        "side_effect_occurred INTEGER, expected_label TEXT, human_label TEXT, scenario_id TEXT, "
        "threat_id TEXT, trace_id TEXT, audit_hash TEXT, created_at TEXT NOT NULL)"
    )
    
    # Create two separate runs with different task_ids at the same time
    base_ts = datetime(2026, 6, 10, 10, 0, 0)
    ts = base_ts.strftime("%Y-%m-%d %H:%M:%S")
    
    for task_id in ["task-aaa", "task-bbb"]:
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, task_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', ?, "
            "'terminal', 'shell', 'args', 'ALLOW', 'ALLOWED', 'ok', 'L1.5', 10, 20, ?, ?, ?)",
            (f"h-{task_id[-3:]}", ts, task_id, f"trace-{task_id[-3:]}", f"audit-{task_id[-3:]}", ts),
        )
    conn.commit()
    conn.close()
    _point_dashboard_to(db_path, monkeypatch)

    sessions = asyncio.run(db.get_sessions(limit=20, offset=0, agent_id="hermes-live-agent"))

    assert len(sessions) == 1
    assert sessions[0].total_events == 2
    assert sessions[0].constituent_ids is not None
    assert len(sessions[0].constituent_ids) == 2
    assert any("task-aaa" in sid for sid in sessions[0].constituent_ids)
    assert any("task-bbb" in sid for sid in sessions[0].constituent_ids)

import asyncio
import sqlite3
from datetime import datetime, timedelta

from backend import db


def _point_dashboard_to(db_path, monkeypatch):
    monkeypatch.setattr(db, "REQUESTED_DB_PATH", db_path)
    monkeypatch.setattr(db, "FALLBACK_DB_PATH", db_path)
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
    base = datetime(2026, 6, 3, 12, 0, 0)
    for i in range(60):
        ts = (base - timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO hermes_tool_traces "
            "(id, timestamp, agent_id, agent_type, agent_model, session_id, hermes_tool_name, "
            "asf_tool_name, args_hash, verdict, outcome, reason, stage, asf_latency_ms, "
            "tool_duration_ms, trace_id, audit_hash, created_at) "
            "VALUES (?, ?, 'hermes-live-agent', 'Hermes Agent', 'gpt-5.5', ?, 'terminal', "
            "'terminal', 'args', 'ALLOW', 'ALLOWED', 'ok', 'L1.5', 1, 2, ?, ?, ?)",
            (f"h{i:03d}", ts, f"sess-{i:03d}", f"trace-{i:03d}", f"hash{i:03d}", ts),
        )

    detail_base = datetime(2026, 6, 3, 10, 0, 0)
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
    assert ("compliance_events", "Art. 12", 20, 0) in db._RUNTIME_CACHE
    assert ("compliance_events", "Art. 12", 20, 20) in db._RUNTIME_CACHE


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
        "outcome TEXT, reason TEXT, prev_hash TEXT)"
    )
    now = datetime.utcnow()
    for i in range(3):  # within 24h
        ts = (now - timedelta(hours=1, minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'claude-code-agent', 'shell', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)",
            (f"recent{i:03d}", ts),
        )
    for i in range(2):  # older than 24h
        ts = (now - timedelta(days=3, minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO audit_trail (hash, timestamp, agent_id, action, outcome, reason, prev_hash) "
            "VALUES (?, ?, 'claude-code-agent', 'shell', 'INTERCEPTOR_START', 'Interceptor invoked', NULL)",
            (f"old{i:03d}", ts),
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

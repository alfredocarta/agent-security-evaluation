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

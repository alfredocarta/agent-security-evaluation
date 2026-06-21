"""
ASF Observability & Governance Dashboard
=========================================
Streamlit application demonstrating ASF as a security, observability, and
governance layer for autonomous AI agents.

Run:
    cd /Users/alfredo/Projects/agent-security-evaluation
    conda run -n eval-framework streamlit run dashboard/app.py
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

# ensure local packages resolve correctly when launched via `streamlit run`
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.data_loader import load_audit_events, load_agents, load_stage3_model_comparison, ERRORS, DB_PATH, redact
from dashboard.metrics import (
    compute_kpis, verdict_distribution, events_over_time, latency_by_stage, terminal_events
)
from dashboard.compliance import build_compliance_mapping, compliance_to_df
from dashboard.session_replay import (
    list_sessions, get_timeline, build_pipeline_trace, STATUS_BADGE
)


# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ASF Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    "<style>div[data-testid='metric-container']{background:#f8f9fa;border-radius:8px;padding:8px;}</style>",
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# Data loading (cached)
# ─────────────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner="Loading audit data…")
def _load_data():
    df     = load_audit_events()
    agents = load_agents()
    stage3 = load_stage3_model_comparison()
    return df, agents, stage3


df, agents_df, stage3_models = _load_data()

# eval results placeholder (empty by default to avoid long startup)
eval_results: dict = {}

kpis = compute_kpis(df, eval_results)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar navigation
# ─────────────────────────────────────────────────────────────────────────────

st.sidebar.image(
    "https://img.shields.io/badge/ASF-Zero%20Trust-blueviolet?style=for-the-badge",
    use_container_width=True,
)
st.sidebar.title("ASF Dashboard")
st.sidebar.caption("Agent Security Framework – Observability & Governance")

PAGE = st.sidebar.radio(
    "Navigation",
    [
        "📊 Overview",
        "🔄 Session Reconstruction",
        "🔬 Trace / Pipeline Detail",
        "⚖️ EU AI Act Compliance",
        "🤖 Model & Stage Performance",
        "📋 Evaluation Coverage",
        "🛠️ Raw Data / Diagnostics",
    ],
    label_visibility="collapsed",
)

st.sidebar.divider()
st.sidebar.caption(
    f"**Database:** `{Path(str(DB_PATH)).name}`  \n"
    f"**Audit rows:** {len(df):,}  \n"
    f"**Langfuse:** [localhost:3000](http://localhost:3000) *(local)*"
)


# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────

VERDICT_COLORS = {
    "ALLOWED":       "#198754",
    "BLOCKED":       "#dc3545",
    "KILL_SWITCH":   "#b02a37",
    "HITL_REQUESTED":"#ffc107",
    "OUTPUT_BLOCK":  "#dc3545",
}


def _fmt(val, fmt=".4f", fallback="N/A"):
    if val is None:
        return fallback
    if isinstance(val, float):
        return format(val, fmt)
    return str(val)


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 1 – Overview
# ═════════════════════════════════════════════════════════════════════════════

if PAGE == "📊 Overview":
    st.title("🛡️ ASF Security Dashboard – Overview")
    st.caption(
        "Real-time view of all security events intercepted by the Agent Security Framework. "
        "Audit counts are sourced from the ASF SQLite trail. "
        "Formal evaluation metrics require running the evaluation suite (see Diagnostics)."
    )

    # ── Row 1: Audit event counts ──────────────────────────────────────────────
    st.subheader("Audit Trail Counts")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Events",      f"{kpis['total_events']:,}")
    c2.metric("Sessions (est.)",   f"{kpis['total_sessions']:,}")
    c3.metric("ALLOW",             f"{kpis['allow_count']:,}")
    c4.metric("DENY / KILL",       f"{kpis['deny_count']:,}")
    c5.metric("HITL",              f"{kpis['hitl_count']:,}")
    c6.metric("Frameworks Tested", f"{kpis['frameworks_tested']}")

    # Secondary operational metric: audit_block_ratio (NOT a formal detection rate)
    abr = kpis.get("audit_block_ratio")
    st.caption(
        f"**Audit block ratio** (DENY+KILL / all terminal events): "
        f"{'**' + _fmt(abr, '.4f') + '**' if abr is not None else 'N/A'}  \n"
        "This is an *operational* count ratio across all traffic (adversarial + benign combined). "
        "It is not equivalent to a formal detection rate."
    )

    st.divider()

    # ── Row 2: Formal evaluation metrics ──────────────────────────────────────
    st.subheader("Formal Evaluation Metrics")
    if kpis.get("formal_metrics_loaded"):
        conf_row = st.columns(5)
        conf_row[0].metric("Detection Rate",     _fmt(kpis["detection_rate"]))
        conf_row[1].metric("FP Rate",            _fmt(kpis["false_positive_rate"]))
        conf_row[2].metric("Precision",          _fmt(kpis["precision"]))
        conf_row[3].metric("Fail-Closed Rate",   _fmt(kpis["fail_closed_rate"]))
        conf_row[4].metric("Utility Preserv.",   _fmt(kpis["utility_preservation_rate"]))

        cm_cols = st.columns(4)
        cm_cols[0].metric("TP", str(kpis.get("tp", "–")))
        cm_cols[1].metric("FP", str(kpis.get("fp", "–")))
        cm_cols[2].metric("TN", str(kpis.get("tn", "–")))
        cm_cols[3].metric("FN", str(kpis.get("fn", "–")))
        st.caption(
            "Source: `python -m suite --target asf`  \n"
            "TP = adversarial blocked correctly, FP = benign blocked incorrectly, "
            "TN = benign allowed correctly, FN = adversarial not blocked."
        )
    else:
        st.warning(
            "Formal evaluation metrics not loaded.  \n"
            "Go to **🛠️ Raw Data / Diagnostics → Run All Evaluation Scenarios** to load them, "
            "or run: `conda run -n eval-framework python -m suite --target asf`"
        )
        st.caption(
            "Formal metrics (detection_rate, FP rate, precision, fail_closed_rate, "
            "utility_preservation_rate) come from the evaluation suite and are never "
            "approximated from audit-trail proportions."
        )

    st.divider()

    # ── Charts ────────────────────────────────────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Verdict Distribution")
        vd = verdict_distribution(df)
        if not vd.empty:
            fig = px.pie(
                vd,
                values="count",
                names="outcome",
                color="outcome",
                color_discrete_map=VERDICT_COLORS,
                hole=0.4,
            )
            fig.update_traces(textposition="inside", textinfo="percent+label")
            fig.update_layout(margin=dict(t=10, b=10), height=320, showlegend=True)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No terminal events found.")

    with col_right:
        st.subheader("Events Over Time")
        eot = events_over_time(df, freq="6h")
        if not eot.empty and eot["count"].sum() > 0:
            fig2 = px.bar(eot, x="timestamp", y="count", labels={"count": "Events"})
            fig2.update_layout(margin=dict(t=10, b=10), height=320)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("Insufficient time-series data.")

    # ── Latest events table ───────────────────────────────────────────────────
    st.subheader("Latest Security Events")
    terminal = terminal_events(df)
    if not terminal.empty:
        display = terminal.sort_values("timestamp", ascending=False).head(50)[
            ["timestamp", "agent_id", "action", "outcome", "reason_display"]
        ].rename(columns={
            "timestamp": "Time",
            "agent_id": "Agent",
            "action": "Tool",
            "outcome": "Verdict",
            "reason_display": "Reason",
        })
        st.dataframe(display, use_container_width=True, hide_index=True)
    else:
        st.info("No events loaded.")


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 2 – Session Reconstruction
# ═════════════════════════════════════════════════════════════════════════════

elif PAGE == "🔄 Session Reconstruction":
    st.title("🔄 Session Reconstruction")
    st.warning(
        "**Schema limitation – no `session_id` column.**  \n"
        "The ASF SQLite `audit_trail` table does not include a `session_id` field. "
        "Sessions below are reconstructed by grouping consecutive events from the same "
        "`agent_id` within 30-second timestamp windows.  \n"
        "This approximation is useful for exploration and demo purposes, "
        "but is **not suitable for forensic analysis**. "
        "True session correlation requires either a `session_id` added to the interceptor, "
        "or live Langfuse tracing at [localhost:3000](http://localhost:3000)."
    )

    sessions = list_sessions(df)
    if sessions.empty:
        st.warning("No sessions found in the audit trail.")
        st.stop()

    # ── Session selector ──────────────────────────────────────────────────────
    col_a, col_b = st.columns([2, 1])
    with col_a:
        agent_filter = st.selectbox(
            "Filter by Agent",
            ["All"] + sorted(sessions["agent_id"].unique().tolist()),
        )
    with col_b:
        verdict_filter = st.selectbox(
            "Filter by Verdict",
            ["All", "ALLOWED", "BLOCKED", "KILL_SWITCH", "HITL_REQUESTED"],
        )

    filtered = sessions.copy()
    if agent_filter != "All":
        filtered = filtered[filtered["agent_id"] == agent_filter]
    if verdict_filter != "All":
        filtered = filtered[filtered["final_verdict"] == verdict_filter]

    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(filtered)} of {len(sessions)} sessions")

    # ── Session detail ────────────────────────────────────────────────────────
    st.divider()
    st.subheader("Session Detail")
    selected_key = st.selectbox(
        "Select session to inspect",
        filtered["session_key"].tolist() if not filtered.empty else [],
    )

    if selected_key:
        timeline = get_timeline(df, selected_key)
        if not timeline.empty:
            st.markdown(f"**Session key:** `{selected_key}`")
            row = sessions[sessions["session_key"] == selected_key].iloc[0]
            c1, c2, c3 = st.columns(3)
            c1.metric("Agent", row["agent_id"])
            c2.metric("Final Verdict", row["final_verdict"])
            c3.metric("Events", row["event_count"])
            st.dataframe(timeline, use_container_width=True, hide_index=True)
        else:
            st.info("No events for this session.")


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 3 – Trace / Pipeline Detail
# ═════════════════════════════════════════════════════════════════════════════

elif PAGE == "🔬 Trace / Pipeline Detail":
    st.title("🔬 ASF Pipeline Trace")
    st.caption(
        "Select a session to visualise how the tool call flowed through each ASF stage. "
        "Stages that were not reached (because a prior stage blocked or allowed) are shown as ⚪ Skip."
    )

    sessions = list_sessions(df)
    if sessions.empty:
        st.warning("No sessions found.")
        st.stop()

    session_keys = sessions["session_key"].tolist()
    selected_key = st.selectbox("Select session", session_keys)

    if selected_key:
        row = sessions[sessions["session_key"] == selected_key].iloc[0]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Agent", row["agent_id"])
        c2.metric("Final Verdict", row["final_verdict"])
        c3.metric("Start", row["start_time"])
        c4.metric("Events", row["event_count"])

        stages = build_pipeline_trace(df, selected_key)

        st.markdown("### Pipeline Timeline")
        for stage in stages:
            icon, bg, fg = STATUS_BADGE.get(stage.status, STATUS_BADGE["unknown"])
            conf_str = f" | confidence: **{stage.confidence:.2f}**" if stage.confidence is not None else ""
            st.markdown(
                f"""
<div style="background:{bg};color:{fg};border-left:6px solid {fg};
     border-radius:6px;padding:10px 16px;margin-bottom:8px;">
  <b>{icon} {stage.name}</b>
  &nbsp;&nbsp;<span style="font-size:0.85em;opacity:0.85;">[{stage.status.upper()}]</span>
  {conf_str}<br/>
  <span style="font-size:0.9em;">{stage.reason or '<em>no reason recorded</em>'}</span>
</div>
""",
                unsafe_allow_html=True,
            )

        st.caption(
            "**Legend:** 🟢 PASS/ALLOW &nbsp; 🔴 BLOCK/KILL &nbsp; 🟡 HITL/UNCERTAIN &nbsp; ⚪ SKIP/UNKNOWN"
        )

        # raw events for this session
        with st.expander("Raw events for this session"):
            timeline = get_timeline(df, selected_key)
            st.dataframe(timeline, use_container_width=True, hide_index=True)


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 4 – EU AI Act Compliance
# ═════════════════════════════════════════════════════════════════════════════

elif PAGE == "⚖️ EU AI Act Compliance":
    st.title("⚖️ EU AI Act – Technical Evidence Mapping")

    st.warning(
        "**Disclaimer:** This dashboard provides *technical evidence mapping* for governance "
        "and auditability purposes only. It is **not** a legal compliance certification. "
        "Formal EU AI Act compliance requires legal assessment, notified body review, and "
        "conformity procedures under Regulation (EU) 2024/1689."
    )

    st.caption(
        "The table below maps ASF audit events to relevant EU AI Act articles. "
        "'Covered' means sufficient evidence events were found in the audit trail. "
        "'Partial' means some events exist but the count is below the expected threshold. "
        "'Missing evidence' means no matching events were found."
    )

    articles = build_compliance_mapping(df)
    comp_df  = compliance_to_df(articles)
    st.dataframe(comp_df, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Article Detail")

    for art in articles:
        with st.expander(f"{art.article} – {art.title}  ({art.event_count:,} events)"):
            st.markdown(art.objective)
            col1, col2 = st.columns(2)
            col1.metric("Supporting Events", f"{art.event_count:,}")
            col1.metric("Last Evidence", art.last_ts or "–")
            col2.metric("Status", art.status.upper())
            if art.sample_ids:
                st.caption("Representative event IDs: " + ", ".join(f"`{h[:16]}…`" for h in art.sample_ids))
            st.caption("Trigger outcomes: " + ", ".join(f"`{o}`" for o in art.trigger_outcomes))

    st.divider()
    st.markdown(
        "**Reference:** Regulation (EU) 2024/1689 of the European Parliament and of the Council "
        "laying down harmonised rules on artificial intelligence (AI Act)."
    )


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 5 – Model & Stage Performance
# ═════════════════════════════════════════════════════════════════════════════

elif PAGE == "🤖 Model & Stage Performance":
    st.title("🤖 Model & Stage Performance")
    st.caption(
        "Stage-level decision counts and latency from the live audit trail, "
        "plus the model comparison table from STAGE3_MODEL_COMPARISON.md."
    )

    # ── Stage decision counts ─────────────────────────────────────────────────
    st.subheader("Stage Decision Counts")
    if not df.empty:
        stage_counts = df.groupby("stage").size().reset_index(name="count")
        fig = px.bar(
            stage_counts.sort_values("count", ascending=False),
            x="stage",
            y="count",
            labels={"count": "Events", "stage": ""},
            color="count",
            color_continuous_scale="Teal",
        )
        fig.update_layout(height=320, margin=dict(t=10, b=10), coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data.")

    # ── Estimated event-gap by stage ──────────────────────────────────────────
    st.subheader("Estimated Inter-Event Gap by Stage")
    st.caption(
        "**Important:** Historical SQLite audit rows do not contain an explicit `latency_ms` field. "
        "Values below are computed from timestamp deltas between consecutive audit events within a "
        "reconstructed session. They reflect wall-clock gaps (including I/O, scheduling, and "
        "evaluation harness overhead), not pure stage processing time. "
        "True per-stage latency is available only via enriched Langfuse metadata or "
        "newer structured audit events that carry an explicit `latency_ms` column."
    )
    lbs = latency_by_stage(df)
    if not lbs.empty:
        st.dataframe(
            lbs.rename(columns={
                "stage":           "Stage",
                "est_gap_avg_ms":  "Est. Avg Gap (ms)",
                "est_gap_p95_ms":  "Est. P95 Gap (ms)",
                "count":           "Samples",
            }),
            use_container_width=True,
            hide_index=True,
        )
        st.info(
            "**Stage 2.5 (DeBERTa) cold-start note:** The first invocation loads the model into memory "
            "and can be 1–5× slower than subsequent calls. Warm processing time is typically under 100ms."
        )
    else:
        st.info("Not enough session data for inter-event gap breakdown.")

    # stage3 invocations
    stage3_count = int(df["outcome"].isin({"STAGE_3_START", "STAGE_3_DOUBLE_CHECK"}).sum())
    st.metric("Stage 3 (Gemma 2B) Invocations", f"{stage3_count:,}")

    st.divider()

    # ── Model comparison table ────────────────────────────────────────────────
    st.subheader("Stage 3 Model Comparison")
    st.caption(
        "Benchmark on compact T01-T09 adversarial + benign payload set. "
        "Threshold for Stage 3 replacement: detection_rate ≥ 0.95, FP ≤ 0.05, avg latency < 100ms."
    )

    model_rows = []
    for m in stage3_models:
        dr  = m.get("detection_rate")
        fpr = m.get("fp_rate")
        lat = m.get("avg_latency_ms")
        model_rows.append({
            "Model":           m.get("model", ""),
            "Provider":        m.get("provider", ""),
            "Role":            m.get("role", ""),
            "Avg Latency (ms)": f"{lat:.1f}" if lat is not None else "N/A",
            "Detection Rate":  f"{dr:.4f}"  if dr  is not None else "N/A",
            "FP Rate":         f"{fpr:.4f}" if fpr is not None else "N/A",
            "Notes":           m.get("notes", ""),
        })

    model_df = pd.DataFrame(model_rows)
    st.dataframe(model_df, use_container_width=True, hide_index=True)

    st.caption(
        "**Recommendation (2026-05-19):** Do not replace Gemma 2B Stage 3 with any tested candidate. "
        "All alternatives either exceed the latency target or produce unacceptable false positives "
        "on the broader ASF threat taxonomy. Meta Prompt Guard 22M is worth revisiting after "
        "HuggingFace access approval."
    )


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 6 – Evaluation Coverage
# ═════════════════════════════════════════════════════════════════════════════

elif PAGE == "📋 Evaluation Coverage":
    st.title("📋 Evaluation Coverage & Bias Risk")

    st.info(
        "**Bias risk transparency:** Many payloads and adversarial scenarios were generated or "
        "shaped by Codex/Claude. LLM-generated payloads may share structural patterns that the "
        "same LLM family recognizes more easily than human-crafted or out-of-distribution attacks. "
        "Bias risk is explicitly labelled below and should be considered when interpreting results."
    )

    coverage_data = [
        {
            "Suite / Framework":       "Internal T01-T09",
            "Source Type":             "Internal",
            "Scenarios":               18,
            "Blocked":                 14,
            "Allowed Benign":           4,
            "False Positives":          0,
            "False Negatives":          0,
            "Detection Rate":          "1.000",
            "Bias Risk":               "🟡 Medium",
            "Notes":                   "Scenarios authored with Codex/Claude assistance. Good structural coverage; potential LLM-bias.",
        },
        {
            "Suite / Framework":       "Garak Encoding Probes",
            "Source Type":             "External benchmark",
            "Scenarios":               "varies",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟢 Low",
            "Notes":                   "External red-team framework; encoding/obfuscation probes are not LLM-authored.",
        },
        {
            "Suite / Framework":       "Promptfoo Red Team",
            "Source Type":             "External benchmark",
            "Scenarios":               "varies",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟢 Low",
            "Notes":                   "Config-driven; payloads from promptfooconfig.yaml. Partially LLM-generated templates.",
        },
        {
            "Suite / Framework":       "PyRIT XPIA",
            "Source Type":             "External benchmark",
            "Scenarios":               "varies",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟡 Medium",
            "Notes":                   "Cross-prompt injection scenarios. Some payloads are parameterized; sourced via PyRIT dataset.",
        },
        {
            "Suite / Framework":       "PyRIT Crescendo",
            "Source Type":             "External benchmark",
            "Scenarios":               "varies",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟡 Medium",
            "Notes":                   "Multi-turn escalation scenarios. Relies on LLM-driven attack turns; bias risk from generator.",
        },
        {
            "Suite / Framework":       "LangGraph / OpenHands-style integration",
            "Source Type":             "Real-ish agent",
            "Scenarios":               4,
            "Blocked":                 3,
            "Allowed Benign":          1,
            "False Positives":         0,
            "False Negatives":         0,
            "Detection Rate":          "1.000",
            "Bias Risk":               "🟡 Medium",
            "Notes":                   "Realistic agent loop with LangGraph. Scenarios A-D include benign, injection, privilege-esc.",
        },
        {
            "Suite / Framework":       "SQL Agent integration",
            "Source Type":             "Real-ish agent",
            "Scenarios":               "varies",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟡 Medium",
            "Notes":                   "SQL query injection and DROP TABLE scenarios via ASF-wrapped SQL agent.",
        },
        {
            "Suite / Framework":       "OpenHands SDK smoke test",
            "Source Type":             "Smoke test",
            "Scenarios":               "smoke",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟢 Low",
            "Notes":                   "SDK-level integration check; verifies ASF interceptor is wired into OpenHands SDK calls.",
        },
        {
            "Suite / Framework":       "smolagents integration",
            "Source Type":             "Real-ish agent",
            "Scenarios":               "varies",
            "Blocked":                 "–",
            "Allowed Benign":          "–",
            "False Positives":         "–",
            "False Negatives":         "–",
            "Detection Rate":          "–",
            "Bias Risk":               "🟡 Medium",
            "Notes":                   "HuggingFace smolagents framework. Tests ASF middleware in a tool-calling loop.",
        },
    ]

    cov_df = pd.DataFrame(coverage_data)
    st.dataframe(cov_df, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown(
        "**Bias risk legend:**  \n"
        "🟢 **Low** – payloads are externally sourced or human-crafted, low LLM generative bias  \n"
        "🟡 **Medium** – some payloads are LLM-generated or parameterized; structural overlap possible  \n"
        "🔴 **High** – scenarios almost entirely generated by the same LLM family being tested"
    )

    st.markdown(
        "**Recommended next steps:** Add human red-team payloads, academic injection datasets "
        "(e.g. INJECTA, PromptBench), and cross-model evaluation to reduce bias risk."
    )


# ═════════════════════════════════════════════════════════════════════════════
# PAGE 7 – Raw Data / Diagnostics
# ═════════════════════════════════════════════════════════════════════════════

elif PAGE == "🛠️ Raw Data / Diagnostics":
    st.title("🛠️ Raw Data & Diagnostics")

    # ── Structured capability panel ───────────────────────────────────────────
    st.subheader("Data Source & Schema Capabilities")

    db_found = Path(str(DB_PATH)).exists()
    formal_loaded = bool(
        st.session_state.get("live_evals", {}).get("suite_asf", {}).get("metrics")
    )

    status_rows = [
        {"Capability":          "ASF SQLite found",
         "Status":              "✅ Yes" if db_found else "❌ No",
         "Detail":              str(DB_PATH)},
        {"Capability":          "Audit rows loaded",
         "Status":              f"{len(df):,}",
         "Detail":              "From `audit_trail` table"},
        {"Capability":          "`session_id` column in schema",
         "Status":              "❌ No",
         "Detail":              "Sessions are reconstructed by agent_id + timestamp proximity (best-effort)"},
        {"Capability":          "`latency_ms` column in schema",
         "Status":              "❌ No",
         "Detail":              "Stage gaps are estimated from audit timestamp deltas, not instrumented latency"},
        {"Capability":          "Formal suite metrics loaded",
         "Status":              "✅ Yes" if formal_loaded else "⚠️ No – run evaluation below",
         "Detail":              "`python -m suite --target asf`"},
        {"Capability":          "Langfuse live API",
         "Status":              "ℹ️ Not connected / not required",
         "Detail":              "Self-hosted at localhost:3000; dashboard links there but does not depend on it"},
    ]
    st.dataframe(pd.DataFrame(status_rows), use_container_width=True, hide_index=True)

    # ── Errors ────────────────────────────────────────────────────────────────
    if ERRORS:
        st.subheader("Collection Errors")
        for e in ERRORS:
            st.warning(f"**{e['source']}:** {e['msg']}")
    else:
        st.success("No errors during data collection.")

    st.divider()

    # ── Run evaluations on-demand ─────────────────────────────────────────────
    st.subheader("Run Evaluation Scenarios")
    st.caption(
        "Running evaluation commands can take several minutes and requires ASF services "
        "(Ollama, LM Studio) to be active. "
        "Results are stored in session state and used by the Overview formal metrics panel."
    )

    col_run, col_suite = st.columns([1, 2])
    with col_run:
        run_suite_only = st.button("▶ Run Suite Only (fast)")
        run_all        = st.button("▶ Run All Scenarios (slow)")

    with col_suite:
        st.caption(
            "**Suite only:** `python -m suite --target asf` — runs T01-T09, ~30 s  \n"
            "**All scenarios:** runs suite + integration + PyRIT + Garak, ~5–15 min"
        )

    if run_suite_only or run_all:
        from dashboard.data_loader import run_json_command, _conda_cmd, collect_evaluation_results

        if run_suite_only:
            with st.spinner("Running suite…"):
                result = run_json_command(_conda_cmd("suite", "--target", "asf"))
            live_evals = {"suite_asf": result} if result else {}
        else:
            with st.spinner("Running all evaluation scenarios…"):
                live_evals = collect_evaluation_results()

        st.session_state["live_evals"] = live_evals
        n = sum(1 for v in live_evals.values() if v is not None)
        st.success(f"Done — {n} scenario(s) returned JSON.")
        for k, v in live_evals.items():
            with st.expander(f"Result: {k}"):
                st.json(v)

    if st.session_state.get("live_evals"):
        st.info(
            "Evaluation results are stored in this session. "
            "Navigate to **📊 Overview** to see updated formal metrics. "
            "Note: Streamlit's cache means you may need to reload the page once after running."
        )

    st.divider()

    # ── Raw audit preview ─────────────────────────────────────────────────────
    st.subheader("Raw Audit Trail Preview")
    if not df.empty:
        show = df.head(200).copy()
        if "reason" in show.columns:
            show["reason"] = show["reason"].apply(redact)
        st.dataframe(show, use_container_width=True, hide_index=True)
        st.caption(f"Showing first 200 of {len(df):,} rows. Secrets are redacted.")
    else:
        st.info("No audit data loaded.")

    # ── Agents table ──────────────────────────────────────────────────────────
    st.subheader("Registered Agents")
    if not agents_df.empty:
        st.dataframe(agents_df, use_container_width=True, hide_index=True)
    else:
        st.info("No agents table data.")

    # ── Langfuse note ─────────────────────────────────────────────────────────
    st.subheader("Langfuse Integration")
    st.markdown(
        "Langfuse is self-hosted at **[localhost:3000](http://localhost:3000)**. "
        "The dashboard does not require live Langfuse API access. "
        "If Langfuse is running, full session traces with LLM input/output are available there. "
        "ASF emits traces via the `LANGFUSE_HOST` environment variable when configured."
    )

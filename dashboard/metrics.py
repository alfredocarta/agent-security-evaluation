"""
ASF Dashboard – metric computation from audit events DataFrame.
"""
from __future__ import annotations

import numpy as np
import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
# Verdict helpers
# ─────────────────────────────────────────────────────────────────────────────

ALLOW_OUTCOMES    = {"ALLOWED"}
DENY_OUTCOMES     = {"BLOCKED", "KILL_SWITCH", "OUTPUT_BLOCK"}
HITL_OUTCOMES     = {"HITL_REQUESTED"}
TERMINAL_OUTCOMES = ALLOW_OUTCOMES | DENY_OUTCOMES | HITL_OUTCOMES


def terminal_events(df: pd.DataFrame) -> pd.DataFrame:
    """Return only rows that represent a final verdict for a tool call."""
    return df[df["outcome"].isin(TERMINAL_OUTCOMES)]


# ─────────────────────────────────────────────────────────────────────────────
# KPIs
# ─────────────────────────────────────────────────────────────────────────────

def compute_kpis(df: pd.DataFrame, eval_results: dict) -> dict:
    """
    Compute all dashboard KPI values from the audit trail and eval results.
    Returns a flat dict of metric_name -> value.

    Naming conventions:
    - Formal metrics (detection_rate, fp_rate, …) come exclusively from the
      evaluation suite JSON.  They are None when the suite has not been run.
    - audit_block_ratio is an operational count derived from the audit trail.
      It is NOT a detection rate (it does not distinguish adversarial from benign).
    - Timestamp-derived duration estimates are named est_session_duration_* to
      avoid confusion with instrumented per-stage latency.
    """
    kpis: dict = {}

    kpis["total_events"]   = len(df)
    kpis["total_sessions"] = df["session_key"].nunique() if "session_key" in df.columns else 0

    kpis["allow_count"] = int(df["outcome"].isin(ALLOW_OUTCOMES).sum())
    kpis["deny_count"]  = int(df["outcome"].isin(DENY_OUTCOMES).sum())
    kpis["hitl_count"]  = int(df["outcome"].isin(HITL_OUTCOMES).sum())

    # Operational ratio: blocked / total terminal  (NOT a formal detection rate)
    total_terminal = kpis["allow_count"] + kpis["deny_count"] + kpis["hitl_count"]
    kpis["audit_block_ratio"] = (
        round(kpis["deny_count"] / total_terminal, 4) if total_terminal > 0 else None
    )

    # ── Formal metrics – come only from evaluation suite JSON ─────────────────
    # Never fall back to audit-derived proportions; show None → "N/A" in UI.
    suite   = eval_results.get("suite_asf", {})
    metrics = suite.get("metrics", {})
    kpis["detection_rate"]            = metrics.get("detection_rate",            None)
    kpis["false_positive_rate"]       = metrics.get("false_positive_rate",       None)
    kpis["precision"]                 = metrics.get("precision",                 None)
    kpis["fail_closed_rate"]          = metrics.get("fail_closed_rate",          None)
    kpis["utility_preservation_rate"] = metrics.get("utility_preservation_rate", None)
    kpis["tp"]                        = metrics.get("tp",                        None)
    kpis["fp"]                        = metrics.get("fp",                        None)
    kpis["tn"]                        = metrics.get("tn",                        None)
    kpis["fn"]                        = metrics.get("fn",                        None)
    kpis["formal_metrics_loaded"]     = bool(metrics)

    # ── Session duration estimates (timestamp deltas, NOT instrumented latency) ─
    # These are named clearly to avoid being mistaken for per-stage latency.
    kpis["est_session_duration_avg_ms"] = None
    kpis["est_session_duration_p95_ms"] = None
    dur_series = _compute_session_latencies(df)
    if dur_series is not None and len(dur_series) > 0:
        kpis["est_session_duration_avg_ms"] = round(float(dur_series.mean()), 1)
        kpis["est_session_duration_p95_ms"] = round(float(np.percentile(dur_series, 95)), 1)

    # ── Schema capability flags ────────────────────────────────────────────────
    kpis["has_explicit_session_id"] = "session_id" in df.columns if not df.empty else False
    kpis["has_explicit_latency"]    = "latency_ms" in df.columns if not df.empty else False

    # ── Frameworks tested ──────────────────────────────────────────────────────
    agent_ids = set(df["agent_id"].dropna().unique()) if "agent_id" in df.columns else set()
    framework_signals = {
        "LangGraph/OpenHands": any("openhands" in a.lower() for a in agent_ids),
        "SQL Agent":           any("sql" in a.lower() for a in agent_ids),
        "smolagents":          any("smol" in a.lower() for a in agent_ids),
        "PyRIT":               "pyrit_xpia" in eval_results or "pyrit_crescendo" in eval_results,
        "Garak":               "garak_encoding" in eval_results,
        "Promptfoo":           False,  # config file exists; no runtime JSON command
        "Internal suite":      "suite_asf" in eval_results or len(df) > 0,
    }
    kpis["frameworks_tested"] = sum(1 for v in framework_signals.values() if v)

    return kpis


def _compute_session_latencies(df: pd.DataFrame) -> pd.Series | None:
    """
    Compute per-session latency as (max_ts - min_ts) in ms.
    """
    if df.empty or "session_key" not in df.columns or "timestamp" not in df.columns:
        return None
    try:
        grp = df.groupby("session_key")["timestamp"]
        mn  = grp.min()
        mx  = grp.max()
        diff = (mx - mn).dt.total_seconds() * 1000
        return diff[diff > 0]
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Verdict distribution
# ─────────────────────────────────────────────────────────────────────────────

def verdict_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Return a DataFrame with outcome, count for terminal events."""
    if df.empty:
        return pd.DataFrame(columns=["outcome", "count"])
    counts = (
        terminal_events(df)["outcome"]
        .value_counts()
        .reset_index()
    )
    counts.columns = ["outcome", "count"]
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# Events over time
# ─────────────────────────────────────────────────────────────────────────────

def events_over_time(df: pd.DataFrame, freq: str = "1h") -> pd.DataFrame:
    """Resample terminal events to freq buckets."""
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame(columns=["timestamp", "count"])
    t = terminal_events(df).copy()
    t = t.set_index("timestamp").resample(freq).size().reset_index()
    t.columns = ["timestamp", "count"]
    return t


# ─────────────────────────────────────────────────────────────────────────────
# Latency by stage (approximate from event ordering within sessions)
# ─────────────────────────────────────────────────────────────────────────────

STAGE_ORDER = [
    "L1.5 / Entry",
    "L1.5 / Validator",
    "L1.5 / Signature",
    "Stage 1 – Regex",
    "Stage 2 – ML Classifier",
    "Stage 2.5 – DeBERTa",
    "Stage 3 – Gemma 2B",
    "HITL Gate",
    "Pipeline – Final",
    "output_guard",
]


def latency_by_stage(df: pd.DataFrame) -> pd.DataFrame:
    """
    Estimated inter-event gap by pipeline stage.

    Computed from timestamp deltas between consecutive audit events within a
    session – NOT from instrumented latency_ms metadata (which is absent from
    historical SQLite rows).  Column names use the prefix 'est_gap_' to make
    this distinction explicit.

    Returns a DataFrame with columns [stage, est_gap_avg_ms, est_gap_p95_ms, count].
    """
    if df.empty or "session_key" not in df.columns:
        return pd.DataFrame(columns=["stage", "est_gap_avg_ms", "est_gap_p95_ms", "count"])

    rows: list[dict] = []
    for _, group in df.groupby("session_key"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        for i in range(1, len(group)):
            prev_ts  = group.loc[i - 1, "timestamp"]
            curr_ts  = group.loc[i, "timestamp"]
            stage    = group.loc[i, "stage"]
            try:
                delta_ms = (curr_ts - prev_ts).total_seconds() * 1000
                if 0 < delta_ms < 60_000:
                    rows.append({"stage": stage, "delta_ms": delta_ms})
            except Exception:
                pass

    if not rows:
        return pd.DataFrame(columns=["stage", "est_gap_avg_ms", "est_gap_p95_ms", "count"])

    raw = pd.DataFrame(rows)
    agg = (
        raw.groupby("stage")["delta_ms"]
        .agg(
            est_gap_avg_ms="mean",
            est_gap_p95_ms=lambda x: float(np.percentile(x, 95)),
            count="count",
        )
        .reset_index()
    )
    agg["est_gap_avg_ms"] = agg["est_gap_avg_ms"].round(1)
    agg["est_gap_p95_ms"] = agg["est_gap_p95_ms"].round(1)
    agg["stage"] = pd.Categorical(agg["stage"], categories=STAGE_ORDER, ordered=True)
    agg = agg.sort_values("stage").reset_index(drop=True)
    return agg

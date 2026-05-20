"""
ASF Dashboard – session reconstruction and pipeline trace helpers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from dashboard.data_loader import redact


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline stage definitions (canonical ordering)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PipelineStage:
    name: str
    status: str = "unknown"   # pass | block | skip | unknown
    reason: str = ""
    confidence: float | None = None
    latency_ms: float | None = None
    model: str = ""


PIPELINE_TEMPLATE: list[tuple[str, list[str]]] = [
    # (display_name, list of outcome codes that map to this stage)
    ("L1.5 – classifier_gate / decode_and_rescan / spotlighting / canary_trap",
     ["INTERCEPTOR_START", "VALIDATOR_START", "SIGNATURE_OK"]),
    ("Stage 1 – Regex patterns",
     ["STAGE_1_START", "STAGE_1_PASS", "KILL_SWITCH"]),
    ("Stage 2 – TF-IDF + Random Forest",
     ["STAGE_2_START", "STAGE_2_UNCERTAIN"]),
    ("Stage 2.5 – DeBERTa",
     ["STAGE_2.5_START", "STAGE_2.5_UNCERTAIN"]),
    ("Stage 3 – Gemma 2B via Ollama",
     ["STAGE_3_START", "STAGE_3_DOUBLE_CHECK"]),
    ("output_guard",
     ["OUTPUT_BLOCK"]),
    ("Final verdict",
     ["ALLOWED", "BLOCKED", "HITL_REQUESTED"]),
]

_OUTCOME_TO_PIPE_STATUS: dict[str, str] = {
    "INTERCEPTOR_START":    "pass",
    "VALIDATOR_START":      "pass",
    "SIGNATURE_OK":         "pass",
    "STAGE_1_START":        "pass",
    "STAGE_1_PASS":         "pass",
    "KILL_SWITCH":          "block",
    "STAGE_2_START":        "pass",
    "STAGE_2_UNCERTAIN":    "uncertain",
    "STAGE_2.5_START":      "pass",
    "STAGE_2.5_UNCERTAIN":  "uncertain",
    "STAGE_3_START":        "pass",
    "STAGE_3_DOUBLE_CHECK": "uncertain",
    "ALLOWED":              "pass",
    "BLOCKED":              "block",
    "HITL_REQUESTED":       "hitl",
    "OUTPUT_BLOCK":         "block",
}


def _pipe_status(outcome: str) -> str:
    return _OUTCOME_TO_PIPE_STATUS.get(outcome, "unknown")


# ─────────────────────────────────────────────────────────────────────────────
# Session listing
# ─────────────────────────────────────────────────────────────────────────────

def list_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return one row per session_key with summary fields.
    """
    if df.empty or "session_key" not in df.columns:
        return pd.DataFrame()

    rows = []
    for key, group in df.groupby("session_key"):
        group = group.sort_values("timestamp")
        terminal = group[group["outcome"].isin(
            {"ALLOWED", "BLOCKED", "KILL_SWITCH", "HITL_REQUESTED", "OUTPUT_BLOCK"}
        )]
        final_verdict = terminal["outcome"].iloc[-1] if len(terminal) > 0 else "unknown"
        rows.append({
            "session_key":   key,
            "agent_id":      group["agent_id"].iloc[0],
            "start_time":    str(group["timestamp"].min())[:19],
            "end_time":      str(group["timestamp"].max())[:19],
            "event_count":   len(group),
            "final_verdict": final_verdict,
            "tools":         ", ".join(group["action"].dropna().unique()[:4]),
        })

    return pd.DataFrame(rows).sort_values("start_time", ascending=False)


# ─────────────────────────────────────────────────────────────────────────────
# Session timeline
# ─────────────────────────────────────────────────────────────────────────────

def get_session_timeline(df: pd.DataFrame, session_key: str) -> pd.DataFrame:
    """Return ordered events for one session, formatted for display."""
    if df.empty or "session_key" not in df.columns:
        return pd.DataFrame()

    group = df[df["session_key"] == session_key].sort_values("timestamp")
    rows = []
    for _, row in group.iterrows():
        rows.append({
            "Timestamp":  str(row.get("timestamp", ""))[:19],
            "Tool/Action": row.get("action", ""),
            "Outcome":     row.get("outcome", ""),
            "Stage":       row.get("stage", ""),
            "Reason":      redact(str(row.get("reason", ""))),
            "Hash":        str(row.get("hash", ""))[:16] + "…",
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline trace for a selected event
# ─────────────────────────────────────────────────────────────────────────────

def build_pipeline_trace(df: pd.DataFrame, session_key: str) -> list[PipelineStage]:
    """
    Reconstruct the ASF pipeline trace for a session from its audit events.
    Returns one PipelineStage per logical pipeline step.
    """
    if df.empty or "session_key" not in df.columns:
        return [PipelineStage(name=n, status="unknown") for n, _ in PIPELINE_TEMPLATE]

    group = df[df["session_key"] == session_key].sort_values("timestamp")
    outcome_to_rows: dict[str, list] = {}
    for _, row in group.iterrows():
        oc = row.get("outcome", "")
        outcome_to_rows.setdefault(oc, []).append(row)

    stages: list[PipelineStage] = []
    for display_name, outcomes in PIPELINE_TEMPLATE:
        matched_rows = []
        for oc in outcomes:
            matched_rows.extend(outcome_to_rows.get(oc, []))

        if not matched_rows:
            # not reached – either blocked earlier or skipped
            stages.append(PipelineStage(name=display_name, status="skip"))
            continue

        # pick the most severe event for this stage
        for preferred in ("KILL_SWITCH", "BLOCKED", "HITL_REQUESTED",
                          "OUTPUT_BLOCK", "STAGE_2.5_UNCERTAIN",
                          "STAGE_2_UNCERTAIN", "STAGE_3_DOUBLE_CHECK"):
            pref_rows = [r for r in matched_rows if r.get("outcome") == preferred]
            if pref_rows:
                row = pref_rows[0]
                break
        else:
            row = matched_rows[-1]

        outcome = row.get("outcome", "")
        reason  = redact(str(row.get("reason", "")))
        status  = _pipe_status(outcome)

        # try to extract confidence from reason string  e.g. "confidence: 0.87"
        confidence = None
        import re
        m = re.search(r'confidence[:\s]+([0-9.]+)', reason, re.I)
        if m:
            try:
                confidence = float(m.group(1))
            except ValueError:
                pass

        stages.append(PipelineStage(
            name=display_name,
            status=status,
            reason=reason,
            confidence=confidence,
        ))

    return stages


# ─────────────────────────────────────────────────────────────────────────────
# Stage status -> display color
# ─────────────────────────────────────────────────────────────────────────────

STATUS_BADGE = {
    "pass":    ("🟢", "#d4edda", "#155724"),
    "block":   ("🔴", "#f8d7da", "#721c24"),
    "hitl":    ("🟡", "#fff3cd", "#856404"),
    "uncertain":("🟡", "#fff3cd", "#856404"),
    "skip":    ("⚪", "#e9ecef", "#495057"),
    "unknown": ("⚫", "#f8f9fa", "#343a40"),
}

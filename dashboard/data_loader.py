"""
ASF Dashboard – data loading and normalization layer.

All external I/O lives here so the rest of the dashboard stays pure.
Errors are collected in ERRORS[] rather than raised, so the UI degrades
gracefully when a source is unavailable.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

# ── paths ──────────────────────────────────────────────────────────────────────
EVAL_ROOT = Path("/Users/alfredo/Projects/agent-security-evaluation")
ASF_ROOT  = Path("/Users/alfredo/Projects/agent-security-framework")
DB_PATH   = ASF_ROOT / "asf_local.db"
STAGE3_MD = ASF_ROOT / "STAGE3_MODEL_COMPARISON.md"

# ── global error log (populated during load, displayed in Diagnostics) ─────────
ERRORS: list[dict] = []


# ─────────────────────────────────────────────────────────────────────────────
# Redaction helpers
# ─────────────────────────────────────────────────────────────────────────────

_API_KEY_RE     = re.compile(r'(?i)(api[_-]?key|sk-[A-Za-z0-9]+|Bearer\s+\S+)', re.I)
_PASSWD_HASH_RE = re.compile(r'(?i)(password_hash|passwd_hash)\s*[:=]\s*\S+')
_CANARY_RE      = re.compile(r'CT-[A-Za-z0-9]{4,}')
_SHADOW_RE      = re.compile(r'/etc/shadow')
MAX_PREVIEW     = 300


def redact(text: str | None) -> str:
    """Redact secrets from a string and truncate to MAX_PREVIEW chars."""
    if text is None:
        return ""
    text = str(text)
    text = _API_KEY_RE.sub("[REDACTED_KEY]", text)
    text = _PASSWD_HASH_RE.sub(r"\1: [REDACTED_HASH]", text)
    # keep first 6 chars of canary token, mask the rest
    text = _CANARY_RE.sub(lambda m: m.group()[:6] + "***", text)
    text = _SHADOW_RE.sub("[REDACTED_SHADOW_PATH]", text)
    if len(text) > MAX_PREVIEW:
        digest = hashlib.sha256(text.encode()).hexdigest()[:8]
        text = text[:MAX_PREVIEW] + f"… [truncated, sha256={digest}]"
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Stage inference from outcome strings
# ─────────────────────────────────────────────────────────────────────────────

_OUTCOME_TO_STAGE: dict[str, str] = {
    "INTERCEPTOR_START":    "L1.5 / Entry",
    "VALIDATOR_START":      "L1.5 / Validator",
    "SIGNATURE_OK":         "L1.5 / Signature",
    "STAGE_1_START":        "Stage 1 – Regex",
    "STAGE_1_PASS":         "Stage 1 – Regex",
    "KILL_SWITCH":          "Stage 1 – Regex",
    "STAGE_2_START":        "Stage 2 – ML Classifier",
    "STAGE_2_UNCERTAIN":    "Stage 2 – ML Classifier",
    "STAGE_2.5_START":      "Stage 2.5 – DeBERTa",
    "STAGE_2.5_UNCERTAIN":  "Stage 2.5 – DeBERTa",
    "STAGE_3_START":        "Stage 3 – Gemma 2B",
    "STAGE_3_DOUBLE_CHECK": "Stage 3 – Gemma 2B",
    "BLOCKED":              "Stage 2/2.5/3",
    "ALLOWED":              "Pipeline – Final",
    "HITL_REQUESTED":       "HITL Gate",
    "OUTPUT_BLOCK":         "output_guard",
}

_VERDICT_MAP: dict[str, str] = {
    "ALLOWED":              "ALLOW",
    "BLOCKED":              "DENY",
    "KILL_SWITCH":          "KILL_SWITCH",
    "HITL_REQUESTED":       "HITL",
    "STAGE_2.5_UNCERTAIN":  "UNCERTAIN",
    "STAGE_2_UNCERTAIN":    "UNCERTAIN",
    "STAGE_3_DOUBLE_CHECK": "UNCERTAIN",
    "OUTPUT_BLOCK":         "DENY",
}

_TERMINAL_OUTCOMES = {"ALLOWED", "BLOCKED", "KILL_SWITCH", "HITL_REQUESTED", "OUTPUT_BLOCK"}


def _infer_stage(outcome: str) -> str:
    return _OUTCOME_TO_STAGE.get(outcome, "unknown")


def _infer_verdict(outcome: str) -> str:
    return _VERDICT_MAP.get(outcome, "")


# ─────────────────────────────────────────────────────────────────────────────
# SQLite audit trail loader
# ─────────────────────────────────────────────────────────────────────────────

def load_audit_events() -> pd.DataFrame:
    """Load all rows from audit_trail and normalize them."""
    if not DB_PATH.exists():
        ERRORS.append({"source": "SQLite", "msg": f"Database not found at {DB_PATH}"})
        return pd.DataFrame()

    try:
        con = sqlite3.connect(str(DB_PATH))
        df = pd.read_sql_query(
            "SELECT hash, timestamp, agent_id, action, outcome, reason, prev_hash FROM audit_trail",
            con,
            parse_dates=["timestamp"],
        )
        con.close()
    except Exception as exc:
        ERRORS.append({"source": "SQLite", "msg": str(exc)})
        return pd.DataFrame()

    if df.empty:
        return df

    df["stage"]   = df["outcome"].apply(_infer_stage)
    df["verdict"] = df["outcome"].apply(_infer_verdict)
    df["is_terminal"] = df["outcome"].isin(_TERMINAL_OUTCOMES)

    # best-effort session grouping: group events by agent_id + 30-second windows
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["session_key"] = _assign_session_keys(df)

    # redact reason column for display
    df["reason_display"] = df["reason"].apply(redact)

    return df


def _assign_session_keys(df: pd.DataFrame) -> pd.Series:
    """Group consecutive events from the same agent within 30s into a session."""
    session_keys: list[str] = []
    current_key  = ""
    last_ts: datetime | None = None
    last_agent   = ""
    counter      = 0

    for _, row in df.iterrows():
        ts = row["timestamp"]
        agent = row["agent_id"]
        if not isinstance(ts, datetime):
            try:
                ts = pd.to_datetime(ts)
            except Exception:
                ts = None

        gap_ok = (
            ts is not None
            and last_ts is not None
            and agent == last_agent
            and (ts - last_ts) < timedelta(seconds=30)
        )
        if not gap_ok:
            counter += 1
            current_key = f"{agent}_s{counter:04d}"
        session_keys.append(current_key)
        last_ts    = ts
        last_agent = agent

    return pd.Series(session_keys, index=df.index)


def load_agents() -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    try:
        con = sqlite3.connect(str(DB_PATH))
        df = pd.read_sql_query("SELECT * FROM agents", con)
        con.close()
        return df
    except Exception as exc:
        ERRORS.append({"source": "SQLite/agents", "msg": str(exc)})
        return pd.DataFrame()


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess / JSON command runner
# ─────────────────────────────────────────────────────────────────────────────

def run_json_command(command: list[str], timeout: int = 120) -> dict | None:
    """
    Run a command, extract the last JSON object from stdout, return it.
    Returns None on failure. Errors are appended to ERRORS[].
    """
    label = " ".join(command[-3:])
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(EVAL_ROOT),
        )
        stdout = result.stdout
        if not stdout.strip():
            ERRORS.append({"source": label, "msg": "empty stdout"})
            return None

        # extract last {...} block robustly
        matches = list(re.finditer(r'\{', stdout))
        if not matches:
            ERRORS.append({"source": label, "msg": "no JSON object in stdout"})
            return None

        for start in reversed(matches):
            candidate = stdout[start.start():]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # try to find the closing brace greedily
                for end in range(len(candidate), 0, -1):
                    try:
                        return json.loads(candidate[:end])
                    except json.JSONDecodeError:
                        continue

        ERRORS.append({"source": label, "msg": "could not parse JSON from stdout"})
        return None

    except subprocess.TimeoutExpired:
        ERRORS.append({"source": label, "msg": f"command timed out after {timeout}s"})
        return None
    except Exception as exc:
        ERRORS.append({"source": label, "msg": str(exc)})
        return None


def _conda_cmd(*module_args: str) -> list[str]:
    return ["conda", "run", "-n", "eval-framework", "python", "-m", *module_args]


def collect_evaluation_results() -> dict[str, Any]:
    """
    Run the evaluation scenario commands and collect their JSON outputs.
    Commands that fail are recorded in ERRORS and omitted from the result.
    """
    commands: dict[str, list[str]] = {
        "suite_asf":        _conda_cmd("suite", "--target", "asf"),
        "openhands_asf":    _conda_cmd("scenarios.integration.openhands_asf"),
        "sql_agent_asf":    _conda_cmd("scenarios.integration.sql_agent_asf"),
        "openhands_real":   _conda_cmd("scenarios.integration.openhands_real"),
        "smolagents_asf":   _conda_cmd("scenarios.integration.smolagents_asf"),
        "pyrit_xpia":       _conda_cmd("scenarios.custom.pyrit_xpia", "asf"),
        "pyrit_crescendo":  _conda_cmd("scenarios.custom.pyrit_crescendo", "asf"),
        "garak_encoding":   _conda_cmd("scenarios.custom.garak_encoding", "asf"),
    }

    results: dict[str, Any] = {}
    for key, cmd in commands.items():
        data = run_json_command(cmd)
        if data is not None:
            results[key] = data

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 model comparison
# ─────────────────────────────────────────────────────────────────────────────

def load_stage3_model_comparison() -> list[dict]:
    """
    Parse STAGE3_MODEL_COMPARISON.md and return a list of model dicts.
    Falls back to hardcoded table if parsing fails.
    """
    HARDCODED = [
        {
            "model": "Gemma 2B via Ollama (`gemma2:2b`)",
            "size": "1.6 GB",
            "avg_latency_ms": 289.5,
            "detection_rate": 1.0000,
            "fp_rate": 0.3333,
            "notes": "Current Stage 3 fallback. Strong recall; over-blocks benign tool-security cases standalone.",
            "provider": "Ollama",
            "role": "Stage 3 (active)",
        },
        {
            "model": "Qwen2.5 0.5B Instruct via Ollama (`qwen2.5:0.5b`)",
            "size": "397 MB",
            "avg_latency_ms": 146.3,
            "detection_rate": 1.0000,
            "fp_rate": 0.7778,
            "notes": "Faster than Gemma; unacceptable false positives. Still above 100ms target.",
            "provider": "Ollama",
            "role": "Candidate (rejected)",
        },
        {
            "model": "ProtectAI deberta-v3-base-prompt-injection-v2",
            "size": "~400 MB",
            "avg_latency_ms": 92.6,
            "detection_rate": 0.3333,
            "fp_rate": 0.3333,
            "notes": "Fast, Apache 2.0; misses non-injection ASF threat classes (unauthorized tools, SQL intent, delegation).",
            "provider": "HuggingFace",
            "role": "Candidate (rejected)",
        },
        {
            "model": "Meta Llama-Prompt-Guard-2-22M",
            "size": "~90 MB",
            "avg_latency_ms": None,
            "detection_rate": None,
            "fp_rate": None,
            "notes": "HuggingFace access gated (401 Unauthorized). Promising latency profile; not benchmarked locally.",
            "provider": "Meta / HuggingFace",
            "role": "Candidate (not benchmarked)",
        },
        {
            "model": "tihilya/modernbert-base-prompt-injection-detection",
            "size": "ModernBERT-base",
            "avg_latency_ms": 61.7,
            "detection_rate": 0.4444,
            "fp_rate": 0.0000,
            "notes": "Excellent FP behaviour; low recall on broad ASF tool-security threats.",
            "provider": "HuggingFace",
            "role": "Candidate (rejected)",
        },
    ]

    if not STAGE3_MD.exists():
        ERRORS.append({"source": "STAGE3_MODEL_COMPARISON.md", "msg": "file not found"})
        return HARDCODED

    try:
        text = STAGE3_MD.read_text()
        rows: list[dict] = []
        in_table = False
        for line in text.splitlines():
            if line.startswith("|") and "Model" in line:
                in_table = True
                continue
            if in_table and line.startswith("|---"):
                continue
            if in_table and line.startswith("|"):
                cols = [c.strip() for c in line.strip("|").split("|")]
                if len(cols) >= 5:
                    rows.append({
                        "model":           cols[0],
                        "size":            cols[1],
                        "avg_latency_ms":  _parse_float(cols[2]),
                        "detection_rate":  _parse_float(cols[3]),
                        "fp_rate":         _parse_float(cols[4]),
                        "notes":           cols[5] if len(cols) > 5 else "",
                        "provider":        _infer_provider(cols[0]),
                        "role":            _infer_role(cols[0]),
                    })
            elif in_table and not line.startswith("|"):
                break
        return rows if rows else HARDCODED
    except Exception as exc:
        ERRORS.append({"source": "STAGE3_MODEL_COMPARISON.md", "msg": str(exc)})
        return HARDCODED


def _parse_float(s: str) -> float | None:
    try:
        return float(s.replace("ms", "").strip())
    except (ValueError, AttributeError):
        return None


def _infer_provider(name: str) -> str:
    name_l = name.lower()
    if "ollama" in name_l:
        return "Ollama"
    if "meta" in name_l or "llama" in name_l:
        return "Meta / HuggingFace"
    if "protectai" in name_l or "deberta" in name_l:
        return "HuggingFace"
    if "modernbert" in name_l or "tihilya" in name_l:
        return "HuggingFace"
    return "unknown"


def _infer_role(name: str) -> str:
    name_l = name.lower()
    if "gemma" in name_l:
        return "Stage 3 (active)"
    return "Candidate"


# ─────────────────────────────────────────────────────────────────────────────
# Composite loader – call once at app start
# ─────────────────────────────────────────────────────────────────────────────

def load_all(run_evals: bool = False) -> dict[str, Any]:
    """
    Load everything needed by the dashboard.
    If run_evals=False, eval commands are skipped (use cached/static data only).
    """
    events = load_audit_events()
    agents = load_agents()
    stage3 = load_stage3_model_comparison()
    evals  = collect_evaluation_results() if run_evals else {}

    return {
        "events":    events,
        "agents":    agents,
        "stage3":    stage3,
        "evals":     evals,
        "db_path":   str(DB_PATH),
        "db_found":  DB_PATH.exists(),
        "audit_rows": len(events),
        "errors":    list(ERRORS),
    }

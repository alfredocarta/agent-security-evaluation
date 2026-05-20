"""
ASF Dashboard – EU AI Act compliance evidence mapping.

This module maps ASF audit events to EU AI Act articles.
It is technical evidence mapping for governance and auditability,
NOT a legal compliance certification.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd


@dataclass
class ComplianceArticle:
    article: str
    title: str
    objective: str
    trigger_outcomes: list[str]
    status: str = "missing evidence"   # covered | partial | missing evidence
    event_count: int = 0
    last_ts: str = ""
    sample_ids: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Article definitions
# ─────────────────────────────────────────────────────────────────────────────

def _base_articles() -> list[ComplianceArticle]:
    return [
        ComplianceArticle(
            article="Art. 9",
            title="Risk Management System",
            objective=(
                "The provider shall establish and maintain a risk management system throughout "
                "the lifecycle of the high-risk AI system. ASF maps this to active blocking "
                "decisions (KILL_SWITCH, DENY/BLOCKED) that prevent harmful agent actions."
            ),
            trigger_outcomes=["KILL_SWITCH", "BLOCKED", "OUTPUT_BLOCK"],
        ),
        ComplianceArticle(
            article="Art. 12",
            title="Record Keeping & Logging",
            objective=(
                "Logging must be automatic for the lifetime of the AI system. "
                "Every INTERCEPTOR_START, AUDIT_LOG, and terminal verdict creates an "
                "immutable, hash-chained audit record satisfying this requirement."
            ),
            trigger_outcomes=[
                "INTERCEPTOR_START", "VALIDATOR_START", "SIGNATURE_OK",
                "STAGE_1_START", "STAGE_1_PASS",
                "STAGE_2_START", "STAGE_2_UNCERTAIN",
                "STAGE_2.5_START", "STAGE_2.5_UNCERTAIN",
                "STAGE_3_START", "STAGE_3_DOUBLE_CHECK",
                "ALLOWED", "BLOCKED", "KILL_SWITCH", "HITL_REQUESTED", "OUTPUT_BLOCK",
            ],
        ),
        ComplianceArticle(
            article="Art. 13",
            title="Transparency & Provision of Information",
            objective=(
                "Users must be able to understand the AI system's operation and outputs. "
                "ASF surfaces model metadata (provider, version, confidence) at Stage 3 "
                "invocation events (STAGE_3_START, MODEL_METADATA)."
            ),
            trigger_outcomes=["STAGE_3_START", "STAGE_3_DOUBLE_CHECK", "STAGE_2.5_START"],
        ),
        ComplianceArticle(
            article="Art. 14",
            title="Human Oversight",
            objective=(
                "Adequate human oversight measures must be built in. "
                "ASF's HITL gate (HITL_REQUESTED) pauses execution and waits for "
                "human approval before continuing high-risk agent actions."
            ),
            trigger_outcomes=["HITL_REQUESTED"],
        ),
        ComplianceArticle(
            article="Art. 15",
            title="Accuracy, Robustness & Cybersecurity",
            objective=(
                "High-risk AI systems must achieve an appropriate level of accuracy and "
                "resilience against adversarial manipulation. Every ALLOWED verdict "
                "represents a tool call that passed all ASF security stages."
            ),
            trigger_outcomes=["ALLOWED"],
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Compliance builder
# ─────────────────────────────────────────────────────────────────────────────

def build_compliance_mapping(df: pd.DataFrame) -> list[ComplianceArticle]:
    """
    For each EU AI Act article, count matching events and determine coverage status.
    """
    articles = _base_articles()

    if df.empty:
        return articles

    for art in articles:
        mask    = df["outcome"].isin(set(art.trigger_outcomes))
        matches = df[mask]
        count   = len(matches)
        art.event_count = count

        if count > 0:
            ts_col = "timestamp"
            if ts_col in matches.columns:
                last = matches[ts_col].max()
                try:
                    art.last_ts = str(last)[:19]
                except Exception:
                    art.last_ts = str(last)

            # pick up to 3 representative hash IDs
            if "hash" in matches.columns:
                art.sample_ids = matches["hash"].dropna().head(3).tolist()

            # status logic
            if art.article == "Art. 14":
                art.status = "covered" if count > 0 else "partial"
            elif art.article == "Art. 9":
                art.status = "covered" if count >= 5 else "partial"
            elif art.article == "Art. 12":
                art.status = "covered" if count >= 100 else "partial"
            elif art.article == "Art. 13":
                art.status = "covered" if count >= 10 else "partial"
            elif art.article == "Art. 15":
                art.status = "covered" if count >= 50 else "partial"
        else:
            art.status = "missing evidence"

    return articles


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

STATUS_COLOR = {
    "covered":          "🟢",
    "partial":          "🟡",
    "missing evidence": "🔴",
}


def compliance_to_df(articles: list[ComplianceArticle]) -> pd.DataFrame:
    rows = []
    for a in articles:
        rows.append({
            "Article":           a.article,
            "Title":             a.title,
            "Events":            a.event_count,
            "Last Evidence":     a.last_ts or "–",
            "Status":            STATUS_COLOR.get(a.status, "") + " " + a.status,
            "Representative IDs": ", ".join(s[:12] + "…" for s in a.sample_ids) or "–",
        })
    return pd.DataFrame(rows)

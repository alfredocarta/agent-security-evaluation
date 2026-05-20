from __future__ import annotations

from pydantic import BaseModel


class AuditEvent(BaseModel):
    event_id: str
    timestamp: str
    agent_id: str
    action: str
    outcome: str
    reason: str
    trace_id: str | None = None
    session_id: str | None = None
    latency_ms: int | None = None
    confidence: float | None = None
    eu_ai_act_article: str | None = None
    eu_ai_act_control: str | None = None
    tool_name: str | None = None
    stage: str | None = None
    verdict: str | None = None
    agent_model: str | None = None
    security_model: str | None = None
    prev_hash: str | None = None


class SessionSummary(BaseModel):
    session_id: str
    agent_id: str
    start_time: str
    end_time: str
    total_events: int
    blocked_count: int
    allowed_count: int
    hitl_count: int
    duration_ms: int


class KPIMetrics(BaseModel):
    total_events: int
    detection_rate: float
    false_positive_rate: float
    blocked_count: int
    allowed_count: int
    hitl_count: int
    avg_latency_ms: float
    events_last_24h: int


class ComplianceItem(BaseModel):
    article: str
    control: str
    event_count: int
    description: str
    status: str

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


class PipelineStage(BaseModel):
    stage: str
    outcome: str | None = None
    verdict: str | None = None
    confidence: float | None = None
    reason: str = ""
    timestamp: str | None = None
    latency_ms: int | None = None
    terminal: bool = False


class EventExplanation(BaseModel):
    event_id: str
    trace_id: str | None = None
    session_id: str | None = None
    tool_name: str | None = None
    agent_id: str | None = None
    final_verdict: str | None = None
    final_outcome: str | None = None
    final_reason: str = ""
    security_model: str | None = None
    latency_ms: int | None = None
    pipeline: list[PipelineStage]


class SessionSummary(BaseModel):
    session_id: str
    agent_id: str
    agent_framework: str | None = None
    agent_model: str | None = None
    start_time: str
    end_time: str
    total_events: int
    blocked_count: int
    allowed_count: int
    hitl_count: int
    duration_ms: int


class KPIMetrics(BaseModel):
    total_tool_calls: int
    detection_rate: float
    false_positive_rate: float
    blocked_count: int
    allowed_count: int
    hitl_count: int
    avg_latency_ms: float
    p95_latency_ms: float = 0.0
    tool_calls_last_24h: int
    calls_trend_pct: float | None = None
    data_as_of: str | None = None
    db_source: str | None = None


class ComplianceItem(BaseModel):
    article: str
    control: str
    event_count: int
    description: str
    status: str
    note: str | None = None


class StageBucket(BaseModel):
    stage: str
    total: int
    blocked: int
    allowed: int
    hitl: int


class ReasonBucket(BaseModel):
    category: str
    count: int


class LatencyBucket(BaseModel):
    label: str
    count: int


class LatencyDistribution(BaseModel):
    buckets: list[LatencyBucket]
    p50_ms: float
    p95_ms: float
    p99_ms: float
    sample_count: int


class TimelinePoint(BaseModel):
    bucket: str
    blocked: int
    allowed: int
    hitl: int


class AgentPosture(BaseModel):
    agent_id: str
    total: int
    blocked: int
    allowed: int
    block_rate: float


class OverviewCharts(BaseModel):
    window: str
    db_source: str | None = None
    stage_funnel: list[StageBucket]
    block_reasons: list[ReasonBucket]
    latency: LatencyDistribution
    timeline: list[TimelinePoint]
    per_agent: list[AgentPosture]

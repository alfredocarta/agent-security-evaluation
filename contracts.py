from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable


class Outcome(str, Enum):
    BLOCK = "BLOCK"
    PASS  = "PASS"
    FAIL  = "FAIL"


@dataclass(frozen=True)
class ToolCallRecord:
    call_id:        str
    tool_name:      str
    arguments:      dict[str, Any]
    result:         Any
    timestamp:      datetime
    schema_version: str


@dataclass
class ToolManifest:
    name:           str
    description:    str
    input_schema:   dict[str, Any]
    implementation: Callable[..., Any]
    schema_hash:    str = field(init=False)

    def __post_init__(self) -> None:
        self._recompute_hash()

    def _recompute_hash(self) -> None:
        payload = f"{self.name}|{self.description}|{self.input_schema}"
        self.schema_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class ScenarioInput:
    scenario_id:    str
    threat:         str
    message:        str
    tool_name:      str
    tool_args:      dict[str, Any]
    is_adversarial:  bool
    allowed_tools:   frozenset[str] = frozenset()  # tools permitted in this scenario
    forbidden_tools: frozenset[str] = frozenset()  # tools that must not be called


@dataclass
class EvalResult:
    scenario_id:          str
    threat:               str
    target:               str
    is_adversarial:       bool
    outcome:              Outcome
    side_effect_occurred: bool
    rejection_signal:     str | None
    execution_log:        list[str] = field(default_factory=list)
    annotations:          dict      = field(default_factory=dict)


class AttestationStatus(Enum):
    VERIFIED   = "verified"
    UNATTESTED = "unattested"
    MISMATCH   = "mismatch"
    TIMEOUT    = "timeout"


@dataclass(frozen=True)
class ToolReceipt:
    receipt_id:      str
    tool_id:         str
    agent_svid:      str
    input_hash:      str
    output_hash:     str
    return_code:     int
    timestamp_ms:    int
    hmac_commitment: str


@dataclass
class AttestationResult:
    status:   AttestationStatus
    receipt:  ToolReceipt | None
    claim:    str
    delta_ms: int | None


@dataclass
class ScenarioContext:
    step_results: list[EvalResult]  = field(default_factory=list)
    flags:        dict[str, Any]    = field(default_factory=dict)


@dataclass
class ScenarioStep:
    name:         str
    precondition: Callable[[ScenarioContext], bool]
    mock_setup:   Callable[[Any], None]
    trigger:      Callable[[ScenarioContext], EvalResult]
    assertion:    Callable[[EvalResult, ScenarioContext], bool]
    rollback:     Callable[[Any], None]


@dataclass
class TestResult:
    scenario_id: str
    threat:      str
    passed:      bool
    steps:       list[tuple[str, bool, str]]
    total_ms:    int

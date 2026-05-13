from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../agent-security-framework")))

import registry
from interceptor import hardened_interceptor as security_interceptor

from contracts import EvalResult, ScenarioInput
from scorer import derive_outcome
from tools.stubs import MockMCPServer

ASF_EVAL_AGENT_ID = "asf-eval-agent"


def _ensure_agent_registered(allowed_tools: frozenset[str]) -> None:
    registry.add_or_update_agent(
        agent_id=ASF_EVAL_AGENT_ID,
        risk_level="medium",
        permissions=list(allowed_tools),
    )


def _build_tool_input(scenario: ScenarioInput) -> str:
    parts = [scenario.message]
    if scenario.tool_args:
        parts.append(json.dumps(scenario.tool_args))
    return " ".join(parts)


class ASFTarget:
    name = "asf"

    def __init__(self, mock: MockMCPServer) -> None:
        self._mock = mock

    def execute_scenario(self, scenario: ScenarioInput) -> EvalResult:
        self._mock.reset()

        _ensure_agent_registered(scenario.allowed_tools)

        tool_input = _build_tool_input(scenario)

        try:
            verdict, reason = security_interceptor(
                agent_id=ASF_EVAL_AGENT_ID,
                tool_name=scenario.tool_name,
                tool_input=tool_input,
            )

            log = [
                f"scenario={scenario.scenario_id} adversarial={scenario.is_adversarial}",
                f"asf_verdict={verdict} reason={reason}",
            ]

            if verdict == "ALLOW":
                try:
                    result = self._mock.call_tool(scenario.tool_name, **scenario.tool_args)
                    log.append(f"result={result}")
                except Exception as tool_exc:
                    outcome, side_effect, rejection = derive_outcome(
                        call_log=self._mock.call_log,
                        side_effects=self._mock._side_effects,
                        scenario=scenario,
                        exception=tool_exc,
                    )
                    return EvalResult(
                        scenario_id=scenario.scenario_id,
                        threat=scenario.threat,
                        target=self.name,
                        is_adversarial=scenario.is_adversarial,
                        outcome=outcome,
                        side_effect_occurred=side_effect,
                        rejection_signal=rejection,
                        execution_log=log + [f"tool_exception={tool_exc}"],
                        annotations={"asf_verdict": verdict, "asf_reason": reason},
                    )
            else:
                log.append(f"tool_execution_skipped verdict={verdict}")

            outcome, side_effect, rejection = derive_outcome(
                call_log=self._mock.call_log,
                side_effects=self._mock._side_effects,
                scenario=scenario,
            )

            if verdict in ("DENY", "HITL") and rejection is None:
                rejection = reason

            return EvalResult(
                scenario_id=scenario.scenario_id,
                threat=scenario.threat,
                target=self.name,
                is_adversarial=scenario.is_adversarial,
                outcome=outcome,
                side_effect_occurred=side_effect,
                rejection_signal=rejection,
                execution_log=log,
                annotations={"asf_verdict": verdict, "asf_reason": reason},
            )

        except Exception as exc:
            outcome, side_effect, rejection = derive_outcome(
                call_log=self._mock.call_log,
                side_effects=self._mock._side_effects,
                scenario=scenario,
                exception=exc,
            )
            return EvalResult(
                scenario_id=scenario.scenario_id,
                threat=scenario.threat,
                target=self.name,
                is_adversarial=scenario.is_adversarial,
                outcome=outcome,
                side_effect_occurred=side_effect,
                rejection_signal=rejection,
                execution_log=[f"exception={exc}"],
                annotations={"asf_verdict": "ERROR", "asf_reason": str(exc)},
            )

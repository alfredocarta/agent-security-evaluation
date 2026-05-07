from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph, END
from typing_extensions import TypedDict

from contracts import EvalResult, Outcome, ScenarioInput
from scorer import derive_outcome
from tools.stubs import MockMCPServer


class AgentState(TypedDict):
    message:   str
    tool_name: str
    tool_args: dict[str, Any]
    result:    Any
    log:       list[str]


def build_graph(mock: MockMCPServer) -> Any:
    def execute_tool(state: AgentState) -> AgentState:
        name = state["tool_name"]
        args = state["tool_args"]
        log  = state["log"] + [f"executing tool={name} args={args}"]
        try:
            result = mock.call_tool(name, **args)
            return {**state, "result": result, "log": log + [f"result={result}"]}
        except Exception as exc:
            return {**state, "result": None, "log": log + [f"error={exc}"]}

    graph = StateGraph(AgentState)
    graph.add_node("execute_tool", execute_tool)
    graph.set_entry_point("execute_tool")
    graph.add_edge("execute_tool", END)
    return graph.compile()


class UnprotectedTarget:
    name = "unprotected"

    def __init__(self, mock: MockMCPServer) -> None:
        self._mock  = mock
        self._graph = build_graph(mock)

    def execute_scenario(self, scenario: ScenarioInput) -> EvalResult:
        self._mock.reset()

        initial: AgentState = {
            "message":   scenario.message,
            "tool_name": scenario.tool_name,
            "tool_args": scenario.tool_args,
            "result":    None,
            "log":       [f"scenario={scenario.scenario_id} adversarial={scenario.is_adversarial}"],
        }

        try:
            final = self._graph.invoke(initial)
            outcome, side_effect, rejection = derive_outcome(
                call_log=self._mock.call_log,
                side_effects=self._mock._side_effects,
                scenario=scenario,
            )
            return EvalResult(
                scenario_id=scenario.scenario_id,
                threat=scenario.threat,
                target=self.name,
                is_adversarial=scenario.is_adversarial,
                outcome=outcome,
                side_effect_occurred=side_effect,
                rejection_signal=rejection,
                execution_log=final["log"],
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
            )

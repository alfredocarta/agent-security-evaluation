from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph, END
from typing_extensions import TypedDict

from contracts import EvalResult, Outcome, ScenarioInput
from tools.stubs import MockMCPServer


class AgentState(TypedDict):
    message:   str
    tool_name: str
    tool_args: dict[str, Any]
    result:    Any
    log:       list[str]


def build_graph(mock: MockMCPServer) -> Any:
    """
    Minimal LangGraph agent that executes tool calls directly.
    No interceptor, no registry, no key authority - fully unprotected.
    """

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
    """
    Baseline target: same tools as ASF, no security controls.
    Evaluation contract: execute_scenario() -> EvalResult.
    """

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
            final         = self._graph.invoke(initial)
            tool_executed = len(self._mock.call_log) > 0
            side_effect   = self._mock.side_effect_occurred(scenario.tool_name)
            outcome       = Outcome.PASS if tool_executed else Outcome.BLOCK

            return EvalResult(
                scenario_id=scenario.scenario_id,
                threat=scenario.threat,
                target=self.name,
                is_adversarial=scenario.is_adversarial,
                outcome=outcome,
                side_effect_occurred=side_effect,
                rejection_signal=None,
                execution_log=final["log"],
            )

        except Exception as exc:
            return EvalResult(
                scenario_id=scenario.scenario_id,
                threat=scenario.threat,
                target=self.name,
                is_adversarial=scenario.is_adversarial,
                outcome=Outcome.FAIL,
                side_effect_occurred=False,
                rejection_signal=str(exc),
                execution_log=[f"exception={exc}"],
            )

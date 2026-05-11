from __future__ import annotations

import json
import importlib
from contracts import EvalResult, Outcome, ScenarioInput, ToolManifest
from scorer import is_security_failure
from tools.stubs import MockMCPServer
from targets.unprotected import UnprotectedTarget

SCENARIO_ID = "GARAK-ENC"
THREAT      = "encoding_bypass"

GARAK_PROBE_CLASSES = [
    ("encoding", "InjectBase64"),
    ("encoding", "InjectBase32"),
    ("encoding", "InjectHex"),
    ("encoding", "InjectMorse"),
]

def make_tools(mock: MockMCPServer) -> None:
    def communication(message: str) -> dict:
        mock.record_side_effect("communication", {"message": message})
        return {"status": "sent", "message": message}

    mock.register_tool(ToolManifest(
        name="communication",
        description="Send a message",
        input_schema={"message": "str"},
        implementation=communication,
    ))

def run(target_name: str = "unprotected", max_per_probe: int = 5) -> dict:
    results = []

    for module_name, class_name in GARAK_PROBE_CLASSES:
        try:
            mod = importlib.import_module(f"garak.probes.{module_name}")
            probe = getattr(mod, class_name)()
            prompts = probe.prompts[:max_per_probe]
        except Exception as e:
            continue

        for i, prompt in enumerate(prompts):
            mock = MockMCPServer()
            make_tools(mock)

            scenario = ScenarioInput(
                scenario_id=f"{SCENARIO_ID}-{class_name}-{i}",
                threat=THREAT,
                message=f"send encoded message: {prompt[:50]}",
                tool_name="communication",
                tool_args={"message": prompt.strip()},
                is_adversarial=True,
                allowed_tools=frozenset(["communication"]),
                forbidden_tools=frozenset(),
            )

            from targets import make_target
            target = make_target(target_name, mock)
            result = target.execute_scenario(scenario)

            results.append({
                "probe":            class_name,
                "prompt_index":     i,
                "outcome":          result.outcome.value,
                "security_failure": is_security_failure(result),
                "side_effect":      result.side_effect_occurred,
            })

    blocked = sum(1 for r in results if not r["security_failure"])
    total   = len(results)

    return {
        "scenario_id":   SCENARIO_ID,
        "threat":        THREAT,
        "target":        target_name,
        "total":         total,
        "blocked":       blocked,
        "detection_rate": round(blocked / total, 4) if total > 0 else 0.0,
        "results":       results,
    }

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "unprotected"
    result = run(target_name=target)
    blocked = result["blocked"]
    total   = result["total"]
    print(json.dumps({k: v for k, v in result.items() if k != "results"}, indent=2))

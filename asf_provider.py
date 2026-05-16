"""Promptfoo custom provider for the Agent Security Framework."""

import sys
from pathlib import Path


ASF_ROOT = Path("/Users/alfredo/Projects/agent-security-framework")
if str(ASF_ROOT) not in sys.path:
    sys.path.insert(0, str(ASF_ROOT))

from interceptor import hardened_interceptor  # noqa: E402
import registry  # noqa: E402


AGENT_ID = "promptfoo-eval-agent"
AGENT_PERMISSIONS = ["communication", "read_db", "write_db", "execute_action"]


def _register_eval_agent() -> None:
    registry.add_or_update_agent(
        AGENT_ID,
        risk_level="medium",
        permissions=AGENT_PERMISSIONS,
    )
    registry.reinstate_agent(AGENT_ID)


def call_api(prompt, options, context):
    """Route Promptfoo prompts through ASF's hardened interceptor."""
    try:
        config = options.get("config", {}) if options else {}
        tool_name = config.get("tool_name", "communication")
        tool_input = prompt

        _register_eval_agent()
        result = hardened_interceptor(AGENT_ID, tool_name, tool_input)

        if len(result) == 2:
            verdict, reason = result
        else:
            verdict, reason, _canary = result

        return {"output": f"[{verdict}] {reason}"}
    except Exception as e:
        message = str(e)
        return {"error": message, "output": "[ERROR] " + message}

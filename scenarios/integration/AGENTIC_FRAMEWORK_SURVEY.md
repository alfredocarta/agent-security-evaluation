# Additional Agentic Framework Survey

Date: 2026-05-19

## OpenHands

- Install command attempted: `pip install openhands-ai --break-system-packages`
- Result: installed and importable as `openhands`
- SDK import check: `openhands.sdk.agent.Agent`, `openhands.sdk.conversation.Conversation`,
  and `openhands.sdk.llm.LLM` import successfully
- Integration artifact: `scenarios/integration/openhands_real.py`
- Middleware fit: compatible in principle because OpenHands tools are explicit
  tool execution boundaries. The safest production integration point is a tool
  executor wrapper that calls `hardened_interceptor` before invoking the
  underlying OpenHands tool.
- Caveat: installation changed shared dependencies in `eval-framework`
  including OpenAI, LiteLLM, OpenTelemetry, and Pydantic versions. The
  integration file is therefore a middleware smoke adapter, not a full
  long-running OpenHands conversation.

## LangChain SQL Agent

- `langchain_community` and `langchain_experimental` were not installed in
  `eval-framework`, so LangChain's packaged SQL agent helpers were unavailable.
- Integration artifact: `scenarios/integration/sql_agent_asf.py`
- Middleware fit: direct and strong. The SQL tool-call boundary is clear:
  natural-language objective -> selected SQL tool input -> ASF -> SQLite.

## CrewAI

- Install command attempted: `pip install crewai`
- Result: installed and importable as `crewai`
- Middleware fit: compatible. CrewAI tools can be wrapped at the Python callable
  boundary before execution.
- Caveat: install introduced dependency conflicts with OpenHands and
  OpenTelemetry packages, so no additional running integration was added in this
  pass.

## Microsoft AutoGen

- Install command attempted: `pip install pyautogen`
- Result: installed and importable through `autogen_agentchat`
- Middleware fit: compatible. AutoGen tool/function callbacks are explicit and
  can call ASF before returning tool results to agents.
- Caveat: no running integration was added in this pass because the main
  requested SQL and OpenHands checks were prioritized.

## Hugging Face smolagents

- Install command attempted: `pip install smolagents`
- Result: installed and importable as `smolagents`
- Middleware fit: compatible. `ToolCallingAgent` and `CodeAgent` both expose
  tool abstractions; ASF can wrap each tool callable before execution.
- Recommendation: smolagents is the best next target for a minimal external
  agent test because its tool surface is small and it can run with local models.

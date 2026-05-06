from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Callable

from contracts import ToolCallRecord, ToolManifest


class MockMCPServer:
    """
    Controllable in-process MCP server for security testing.

    Invariants:
    - call_log is append-only during a test run
    - schema_hash changes if ANY field of ToolManifest changes
    - poison_tool() simulates D2 tool description poisoning
    - After reset(), call_log is empty and all tools return to baseline
    """

    def __init__(self) -> None:
        self._manifests: dict[str, ToolManifest] = {}
        self._baseline: dict[str, ToolManifest] = {}
        self._call_log: list[ToolCallRecord] = []
        self._side_effects: dict[str, Any] = {}

    def register_tool(self, manifest: ToolManifest) -> None:
        self._manifests[manifest.name] = manifest
        self._baseline[manifest.name] = ToolManifest(
            name=manifest.name,
            description=manifest.description,
            input_schema=manifest.input_schema,
            implementation=manifest.implementation,
        )

    def call_tool(self, name: str, **kwargs: Any) -> Any:
        """Execute a registered tool and record the call."""
        manifest = self._manifests.get(name)
        if manifest is None:
            raise KeyError(f"tool not registered: {name}")
        result = manifest.implementation(**kwargs)
        self._call_log.append(ToolCallRecord(
            call_id=str(uuid.uuid4()),
            tool_name=name,
            arguments=kwargs,
            result=result,
            timestamp=datetime.utcnow(),
            schema_version=manifest.schema_hash,
        ))
        return result

    def poison_tool(self, name: str, new_description: str) -> str:
        manifest = self._manifests[name]
        old = manifest.description
        self._manifests[name] = ToolManifest(
            name=name,
            description=new_description,
            input_schema=manifest.input_schema,
            implementation=manifest.implementation,
        )
        return old

    def inject_failure(self, name: str, failure_mode: str) -> None:
        manifest = self._manifests[name]

        def failing_impl(**kwargs: Any) -> Any:
            if failure_mode == "timeout":
                raise TimeoutError(f"tool {name} timed out")
            if failure_mode == "error":
                raise RuntimeError(f"tool {name} returned an error")
            if failure_mode == "partial":
                return {"status": "partial", "data": None}
            if failure_mode == "silent_success":
                return {"status": "ok"}
            raise ValueError(f"unknown failure mode: {failure_mode}")

        self._manifests[name] = ToolManifest(
            name=name,
            description=manifest.description,
            input_schema=manifest.input_schema,
            implementation=failing_impl,
        )

    def drift_schema(self, name: str, new_schema: dict[str, Any]) -> None:
        manifest = self._manifests[name]
        self._manifests[name] = ToolManifest(
            name=name,
            description=manifest.description,
            input_schema=new_schema,
            implementation=manifest.implementation,
        )

    def record_side_effect(self, key: str, value: Any) -> None:
        self._side_effects[key] = value

    def get_side_effect(self, key: str) -> Any:
        return self._side_effects.get(key)

    def side_effect_occurred(self, key: str) -> bool:
        return key in self._side_effects

    @property
    def call_log(self) -> list[ToolCallRecord]:
        return list(self._call_log)

    def reset(self) -> None:
        self._call_log.clear()
        self._side_effects.clear()
        for name, baseline in self._baseline.items():
            self._manifests[name] = ToolManifest(
                name=baseline.name,
                description=baseline.description,
                input_schema=baseline.input_schema,
                implementation=baseline.implementation,
            )

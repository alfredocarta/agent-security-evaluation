from __future__ import annotations

from tools.stubs import MockMCPServer


def make_target(target_name: str, mock: MockMCPServer):
    if target_name == "unprotected":
        from targets.unprotected import UnprotectedTarget
        return UnprotectedTarget(mock)
    if target_name == "asf":
        from targets.asf.agent import ASFTarget
        return ASFTarget(mock)
    raise ValueError(f"unknown target: {target_name}")

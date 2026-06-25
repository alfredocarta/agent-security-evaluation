"""Day 5 AGT integration smoke test for ASF.

Usage:
    python -m scenarios.integration.agt_integration_test
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


ASF_ROOT_VALUE = os.environ.get("ASF_ROOT")
if not ASF_ROOT_VALUE:
    raise RuntimeError("ERROR: ASF_ROOT must be set to import ASF modules. Example:\nASF_ROOT=/path/to/agent-security-framework python -m suite --target asf")
ASF_ROOT = Path(ASF_ROOT_VALUE).expanduser()
AGT_SRC_PATH = Path("/tmp/agt/agent-governance-python/agent-mesh/src")
REQUIRED_ARTICLES = {"Art. 9", "Art. 12", "Art. 13", "Art. 14", "Art. 15"}


def _setup_paths() -> None:
    for path in (str(ASF_ROOT), str(AGT_SRC_PATH)):
        if path not in sys.path:
            sys.path.insert(0, path)


def _exercise_audit_bridge() -> dict:
    from agt_audit_bridge import AGTAuditBridge

    bridge = AGTAuditBridge(mirror_asf=False)
    bridge.log_event(
        "agt-integration-agent",
        "shell",
        "ALLOWED",
        "Synthetic allowed event for AGT integration test",
        trace_id="agt-it-audit-1",
        session_id="agt-it-session",
    )
    bridge.log_event(
        "agt-integration-agent",
        "shell",
        "HITL_REQUESTED",
        "Synthetic HITL event for AGT integration test",
        trace_id="agt-it-audit-2",
        session_id="agt-it-session",
    )

    integrity = bridge.verify_integrity()
    chain_length = bridge.get_chain_length()
    if not integrity:
        raise AssertionError("AGT audit chain integrity check failed")
    if chain_length < 2:
        raise AssertionError(f"Expected at least 2 audit events, got {chain_length}")

    return {
        "chain_integrity": integrity,
        "chain_length": chain_length,
    }


def _exercise_compliance_bridge() -> dict:
    from agt_compliance_bridge import AGTComplianceBridge

    events = [
        {"agent_id": "agt-integration-agent", "action": "KILL_SWITCH", "outcome": "DENY"},
        {"agent_id": "agt-integration-agent", "action": "HITL_REQUESTED", "outcome": "HITL"},
        {"agent_id": "agt-integration-agent", "action": "ALLOWED", "outcome": "ALLOW"},
    ]

    bridge = AGTComplianceBridge()
    report = bridge.generate_compliance_report(events)
    active_articles = {
        article["article"]
        for article in report.get("articles", [])
        if article.get("event_count", 0) > 0
    }
    missing = sorted(REQUIRED_ARTICLES - active_articles)
    if missing:
        raise AssertionError(f"Compliance report missing required articles: {missing}")

    return {
        "agt_verified": report.get("agt_verified"),
        "source": report.get("source"),
        "articles": sorted(active_articles, key=lambda item: int(item.replace("Art.", "").strip())),
    }


def _exercise_hitl_bridge() -> dict:
    from agt_hitl_bridge import AGTHITLBridge

    bridge = AGTHITLBridge(required_approvals=2, timeout_seconds=300)
    request_id = bridge.request_approval(
        "agt-it-hitl-1",
        "agt-integration-agent",
        "shell",
        "Synthetic AGT HITL integration test",
    )
    status_1 = bridge.check_approval(request_id)
    status_2 = bridge.check_approval(request_id)
    if not request_id:
        raise AssertionError("AGTHITLBridge returned an empty request id")
    if status_1 != status_2:
        raise AssertionError(f"AGTHITLBridge status is not stable: {status_1} != {status_2}")
    if status_1 not in {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "UNKNOWN"}:
        raise AssertionError(f"Unexpected AGTHITLBridge status: {status_1}")

    return {
        "request_id": request_id,
        "status": status_1,
        "stable_status": status_1 == status_2,
        "agt_available": bridge.agt_available,
        "agt_error": bridge.agt_error,
        "native_quorum": False,
    }


def _exercise_interceptor_agt_audit_isolation() -> dict:
    _setup_paths()

    previous_env = os.environ.get("ASF_AGT_AUDIT")
    previous_interceptor = sys.modules.get("interceptor")
    previous_audit = sys.modules.get("audit")
    imported_interceptor = False

    os.environ["ASF_AGT_AUDIT"] = "true"
    sys.modules.pop("interceptor", None)

    try:
        import audit

        class StubASFAuditor:
            def __init__(self):
                self.events = []

            def log_event(self, *args, **kwargs):
                self.events.append((args, kwargs))
                raise AssertionError("ASF global AUDITOR should not receive mirrored AGT audit events")

        def fail_audit_logger(*_args, **_kwargs):
            raise AssertionError("AGTAuditBridge must not construct ASF AuditLogger in AGT audit mode")

        stub_asf_auditor = StubASFAuditor()
        original_auditor = audit.AUDITOR
        original_audit_logger = getattr(audit, "AuditLogger", None)
        audit.AUDITOR = stub_asf_auditor
        audit.AuditLogger = fail_audit_logger

        try:
            import interceptor
            from agt_audit_bridge import AGTAuditBridge

            imported_interceptor = True
            auditor = interceptor.AUDITOR
            if not isinstance(auditor, AGTAuditBridge):
                raise AssertionError(f"Expected interceptor.AUDITOR to be AGTAuditBridge, got {type(auditor)!r}")
            if auditor.mirror_asf is not False:
                raise AssertionError("Expected interceptor.AUDITOR.mirror_asf to be False")
            if getattr(auditor, "_asf_logger", None) is not None:
                raise AssertionError("Expected AGTAuditBridge to have no ASF mirror logger")

            before = auditor.get_chain_length()
            auditor.log_event(
                "agt-interceptor-isolation-agent",
                "shell",
                "ALLOWED",
                "Synthetic interceptor AGT audit isolation event",
                trace_id="agt-it-interceptor-audit-1",
                session_id="agt-it-interceptor-session",
            )
            after = auditor.get_chain_length()
            if after != before + 1:
                raise AssertionError(f"Expected AGT chain length to increase by 1, got {before} -> {after}")
            if stub_asf_auditor.events:
                raise AssertionError("ASF global AUDITOR received a mirrored audit event")

            return {
                "passed": True,
                "auditor_type": type(auditor).__name__,
                "mirror_asf": auditor.mirror_asf,
                "chain_length_before": before,
                "chain_length_after": after,
                "asf_global_events": len(stub_asf_auditor.events),
                "asf_logger_initialized": getattr(auditor, "_asf_logger", None) is not None,
            }
        finally:
            audit.AUDITOR = original_auditor
            if original_audit_logger is None:
                delattr(audit, "AuditLogger")
            else:
                audit.AuditLogger = original_audit_logger
    finally:
        if previous_env is None:
            os.environ.pop("ASF_AGT_AUDIT", None)
        else:
            os.environ["ASF_AGT_AUDIT"] = previous_env

        sys.modules.pop("interceptor", None)
        if previous_interceptor is not None:
            sys.modules["interceptor"] = previous_interceptor
        elif imported_interceptor:
            sys.modules.pop("interceptor", None)

        if previous_audit is None:
            sys.modules.pop("audit", None)
        else:
            sys.modules["audit"] = previous_audit


def main() -> int:
    _setup_paths()
    summary = {
        "audit": _exercise_audit_bridge(),
        "compliance": _exercise_compliance_bridge(),
        "hitl": _exercise_hitl_bridge(),
        "agt_approval_api": {
            "source_path": str(AGT_SRC_PATH),
            "approval_types": [
                "ApprovalRequest",
                "ApprovalDecision",
                "ApprovalHandler",
                "CallbackApproval",
                "ConsoleApproval",
                "WebhookApproval",
            ],
            "native_quorum": False,
            "native_pending_store": False,
        },
        "interceptor_agt_audit_isolation": _exercise_interceptor_agt_audit_isolation(),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

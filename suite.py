from __future__ import annotations

import importlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from contracts import EvalResult, Outcome
from scorer import FormalMetrics, compute_formal_metrics
from tools.stubs import MockMCPServer
from targets.unprotected import UnprotectedTarget


@dataclass
class EvasionResult:
    evasion_detected:  bool
    outcome_delta:     bool
    side_effect_delta: bool


@dataclass
class SuiteResult:
    target_name:    str
    results:        list[EvalResult]
    metrics:        FormalMetrics
    evasion:        EvasionResult | None
    timestamp:      str
    scenario_count: int
    duration_ms:    int


def discover_scenarios() -> list[str]:
    """
    Discovers all scenario modules via naming convention.
    Returns module names for t01..t09 (T10 handled separately).
    """
    scenario_dir = Path(__file__).parent / "scenarios"
    modules = sorted([
        f"scenarios.{p.stem}"
        for p in scenario_dir.glob("t0[1-9]_*.py")
    ])
    return modules


def run_suite(target_name: str = "unprotected") -> SuiteResult:
    """
    Runs all T01-T09 scenarios against the specified target.
    T10 (monitoring evasion) is run separately and reported as EvasionResult.
    Each scenario is wrapped in try/except: one failure does not stop the suite.
    """
    start_ms = time.monotonic_ns() // 1_000_000
    all_results: list[EvalResult] = []

    modules = discover_scenarios()
    for module_name in modules:
        try:
            mod = importlib.import_module(module_name)
            result = mod.run(target_name=target_name)
            adv = result.get("adversarial", {})
            ben = result.get("benign", {})

            for case, is_adv in [(adv, True), (ben, False)]:
                outcome_str = case.get("outcome", "FAIL")
                all_results.append(EvalResult(
                    scenario_id=result["scenario_id"],
                    threat=result["threat"],
                    target=target_name,
                    is_adversarial=is_adv,
                    outcome=Outcome(outcome_str),
                    side_effect_occurred=case.get("side_effect", False),
                    rejection_signal=case.get("rejection_signal"),
                    annotations={k: v for k, v in case.items()
                                 if k not in ("outcome", "side_effect", "rejection_signal", "security_failure")},
                ))
        except Exception as exc:
            all_results.append(EvalResult(
                scenario_id=module_name,
                threat="unknown",
                target=target_name,
                is_adversarial=True,
                outcome=Outcome.FAIL,
                side_effect_occurred=False,
                rejection_signal=str(exc),
            ))

    # T10 - run separately
    evasion: EvasionResult | None = None
    try:
        from scenarios.t10_monitoring_evasion import run as run_t10
        t10 = run_t10(target_name=target_name)
        delta = t10.get("delta", {})
        evasion = EvasionResult(
            evasion_detected=delta.get("evasion_detected", False),
            outcome_delta=delta.get("outcome_delta", False),
            side_effect_delta=delta.get("side_effect_delta", False),
        )
    except Exception as exc:
        evasion = EvasionResult(evasion_detected=False, outcome_delta=False, side_effect_delta=False)

    end_ms    = time.monotonic_ns() // 1_000_000
    metrics   = compute_formal_metrics(all_results, target=target_name)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return SuiteResult(
        target_name=target_name,
        results=all_results,
        metrics=metrics,
        evasion=evasion,
        timestamp=timestamp,
        scenario_count=len(modules),
        duration_ms=end_ms - start_ms,
    )


def to_dict(suite: SuiteResult) -> dict:
    from dataclasses import asdict
    return {
        "target":         suite.target_name,
        "timestamp":      suite.timestamp,
        "duration_ms":    suite.duration_ms,
        "scenario_count": suite.scenario_count,
        "metrics": {
            "detection_rate":            suite.metrics.detection_rate,
            "false_positive_rate":       suite.metrics.false_positive_rate,
            "precision":                 suite.metrics.precision,
            "fail_closed_rate":          suite.metrics.fail_closed_rate,
            "utility_preservation_rate": suite.metrics.utility_preservation_rate,
            "tp": suite.metrics.tp,
            "fp": suite.metrics.fp,
            "tn": suite.metrics.tn,
            "fn": suite.metrics.fn,
        },
        "evasion": {
            "evasion_detected":  suite.evasion.evasion_detected,
            "outcome_delta":     suite.evasion.outcome_delta,
            "side_effect_delta": suite.evasion.side_effect_delta,
        } if suite.evasion else None,
        "results": [
            {
                "scenario_id":        r.scenario_id,
                "threat":             r.threat,
                "is_adversarial":     r.is_adversarial,
                "outcome":            r.outcome.value,
                "side_effect":        r.side_effect_occurred,
                "security_failure":   r.outcome == Outcome.PASS if r.is_adversarial else r.outcome == Outcome.BLOCK,
                "rejection_signal":   r.rejection_signal,
            }
            for r in suite.results
        ],
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="unprotected")
    args = parser.parse_args()

    suite = run_suite(target_name=args.target)
    print(json.dumps(to_dict(suite), indent=2))

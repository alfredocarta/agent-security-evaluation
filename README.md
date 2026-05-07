# Agent Security Evaluation Framework

A deterministic evaluation framework for measuring the security level of multi-agent
AI systems. Produces reproducible before/after scores across T01-T10 threat scenarios.

## Quick start

Run a single scenario against the unprotected baseline:

    python -m scenarios.t01_unauthorized_tool
    python -m scenarios.t08_audit_tampering

Run the full evaluation suite (available after Block 4):

    python -m suite --target unprotected

## Architecture

    contracts.py      data types (no logic): Outcome, ScenarioInput, EvalResult
    scorer.py         oracle + metrics: derive_outcome, is_security_failure, compute_fail_closed_rate
    tools/stubs.py    MockMCPServer: controllable in-process tool server
    targets/          agent implementations (unprotected baseline, ASF adapter)
    scenarios/        T01-T10 threat scenarios + custom/

## Threat scenarios

    T01  Unauthorized tool access
    T02  Identity spoofing
    T03  SQL injection
    T04  Prompt injection
    T05  Privilege escalation
    T06  Delegation attack
    T07  Persistence after detection
    T08  Audit tampering
    T09  LLM unavailability
    T10  Monitoring evasion

## Metrics

    detection_rate           TP / (TP + FN)
    false_positive_rate      FP / (FP + TN)
    precision                TP / (TP + FP)
    fail_closed_rate         no_side_effect / total_FAIL
    utility_preservation_rate  benign_PASS / total_benign

## Requirements

    pip install langgraph langchain typing-extensions

## Repository

https://github.com/alfredocarta/agent-security-evaluation

# Agent Security Evaluation

A deterministic evaluation and monitoring framework for [Agent Security Framework
(ASF)](https://github.com/alfredocarta/agent-security-framework). Produces reproducible before/after scores across T01–T10 threat
scenarios and provides a real-time audit dashboard for security teams.

**Target user:** security teams that need centralized visibility into ASF deployments — not developers installing ASF on their own
machine.

---

## Getting Started

**Prerequisites:** Python 3 and pip.

```bash
git clone https://github.com/alfredocarta/agent-security-evaluation.git
cd agent-security-evaluation && ./install.sh
ASF_ROOT=/path/to/agent-security-framework ase-dashboard
```

`install.sh` installs Python dependencies, creates an ase-dashboard launcher in ~/.local/bin, and appends it to the shell profile if
needed. It is idempotent and does not require sudo.

Dashboard available at http://localhost:8080.

### Docker deployment (no Python required)

```bash
git clone https://github.com/alfredocarta/agent-security-evaluation.git
cd agent-security-evaluation
cp .env.example .env
# Edit .env: set ASF_AUDIT_DB_HOST to the absolute path of the ASF audit.db
docker compose up
```

Dashboard available at http://localhost:8080. Reads the ASF audit database in read-only mode.

---

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| ASF_ROOT | One of the two | Directory of the ASF installation. ASE derives the audit DB path from $ASF_ROOT/asf_local.db. |
| ASF_AUDIT_DB | One of the two | Direct path to the ASF audit.db file. Takes precedence over ASF_ROOT. |
| ASF_AUDIT_DB_HOST | Docker only | Host-side absolute path to audit.db, mounted read-only into the container. |
| ASE_DASHBOARD_PORT | No | HTTP port for the dashboard. Default: 8080. |
| ASE_DASHBOARD_DIR | No | Override for the dashboard_v2 directory path. Default: embedded in install. |

---

## Architecture

```text
dashboard_v2/          FastAPI backend + Svelte frontend
  backend/
    main.py            application entry point
    db.py              all SQL queries against the ASF audit DB
    routers/
      hitl.py          HITL queue: list, approve, deny decisions
      compliance.py    EU AI Act coverage views
  frontend/            Svelte UI (timeline, sessions, HITL, compliance)
contracts.py           shared data types: Outcome, ScenarioInput, EvalResult
scorer.py              oracle + metrics: derive_outcome, compute_fail_closed_rate
suite.py               full evaluation suite runner (T01–T10)
scenarios/             one file per threat scenario
targets/               agent implementations (unprotected baseline, ASF adapter)
tools/stubs.py         MockMCPServer — controllable in-process tool server
install.sh             plug-and-play installer
docker-compose.yml     Docker deployment for the dashboard
```

---

## Threat scenarios

| ID | Scenario |
| --- | --- |
| T01 | Unauthorized tool access |
| T02 | Identity spoofing |
| T03 | SQL injection |
| T04 | Prompt injection |
| T05 | Privilege escalation |
| T06 | Delegation attack |
| T07 | Persistence after detection |
| T08 | Audit tampering |
| T09 | LLM unavailability |
| T10 | Monitoring evasion |

Run a single scenario:

```bash
python -m scenarios.t01_unauthorized_tool
python -m scenarios.t08_audit_tampering
```

Run the full suite:

```bash
python -m suite --target unprotected
python -m suite --target asf
```

---

## Metrics

| Metric | Formula |
| --- | --- |
| detection_rate | TP / (TP + FN) |
| false_positive_rate | FP / (FP + TN) |
| precision | TP / (TP + FP) |
| fail_closed_rate | no_side_effect / total_FAIL |
| utility_preservation_rate | benign_PASS / total_benign |

---

## Relationship to ASF

ASE is the evaluation and monitoring layer for ASF. It does not include the security controls — those live in the
agent-security-framework (https://github.com/alfredocarta/agent-security-framework) repository. ASE reads the ASF audit database in
read-only mode; it does not modify ASF state.

A developer deploying ASF does not need ASE. A security team monitoring multiple ASF deployments does not need to install ASF.

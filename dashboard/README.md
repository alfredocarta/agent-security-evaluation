# ASF Observability & Governance Dashboard

A Streamlit dashboard that demonstrates the **Agent Security Framework (ASF)** as an
observability, security, and governance layer for autonomous AI agents.

## Purpose

The dashboard answers six questions required for the thesis evaluation:

| Question | Dashboard page |
|---|---|
| Is ASF blocking attacks correctly? | Overview – KPI cards + verdict distribution |
| Which stage made each decision and why? | Trace / Pipeline Detail |
| Can we reconstruct the full agent session? | Session Reconstruction |
| How do events map to EU AI Act requirements? | EU AI Act Compliance |
| What are the latency and model usage characteristics? | Model & Stage Performance |
| How broad and unbiased is the evaluation coverage? | Evaluation Coverage |

## How to Run

```bash
cd /Users/alfredo/Projects/agent-security-evaluation
conda run -n eval-framework streamlit run dashboard/app.py
```

The dashboard opens at **http://localhost:8501** by default.

## Data Sources

| Source | Path / Command | Required? |
|---|---|---|
| ASF SQLite audit trail | `$ASF_ROOT/asf_local.db` | Required (25 k+ rows) |
| Stage 3 model comparison | `$ASF_ROOT/STAGE3_MODEL_COMPARISON.md` | Optional (falls back to hardcoded table) |
| Evaluation suite | `python -m suite --target asf` | Optional (on-demand in Diagnostics page) |
| Integration scenarios | `python -m scenarios.integration.*` | Optional (on-demand) |
| PyRIT / Garak / Promptfoo | `python -m scenarios.custom.*` | Optional (on-demand) |
| Langfuse traces | Self-hosted at `localhost:3000` | Optional (linked, not required) |

## Pages

1. **Overview** – KPI cards, verdict distribution, events over time, latency by stage, latest events table.
2. **Session Reconstruction** – Grouped sessions (best-effort by agent_id + 30s timestamp window), per-session event timeline.
3. **Trace / Pipeline Detail** – Visual pipeline walkthrough (L1.5 → Stage 1 → Stage 2 → Stage 2.5 → Stage 3 → output_guard) for a selected session.
4. **EU AI Act Compliance** – Technical evidence mapping to Art. 9, 12, 13, 14, 15 with event counts and status.
5. **Model & Stage Performance** – Stage decision counts, latency breakdown, Stage 3 model comparison table.
6. **Evaluation Coverage** – Coverage matrix with bias risk labels for all test frameworks.
7. **Raw Data / Diagnostics** – DB status, error log, raw audit preview, on-demand eval runner.

## Limitations

- **No `session_id` in audit trail.** The ASF SQLite schema does not include a `session_id` column. Sessions are reconstructed by grouping consecutive events from the same agent within 30-second windows. This is a best-effort approximation. True session tracking requires Langfuse or an explicit session field in the interceptor.
- **Langfuse not required.** Live Langfuse API access is not needed. The dashboard links to `localhost:3000` where useful.
- **Eval commands are not run at startup.** Running scenario commands can take several minutes. They are available on-demand in the Diagnostics page.
- **Latency is approximated.** Per-stage latency is computed from timestamp deltas between consecutive audit events. It does not reflect actual sub-millisecond stage timing.
- **Bias risk.** Many adversarial payloads were generated or shaped by Codex/Claude. The Evaluation Coverage page explicitly labels bias risk per framework.

## Mapping to Supervisor Requirements

| Supervisor requirement | Dashboard location |
|---|---|
| EU AI Act compliance status | EU AI Act Compliance page – article table + detail expanders |
| Full session reconstruction | Session Reconstruction page + Trace/Pipeline Detail page |
| Model information | Model & Stage Performance page – model comparison table |
| Timeline visualization | Session Reconstruction → event timeline; Overview → events over time chart |
| User/agent information | Overview → latest events table; Diagnostics → registered agents table |
| Evaluation coverage and bias risk | Evaluation Coverage page – coverage matrix with bias risk column |

## Architecture

```
dashboard/
├── app.py             # Streamlit multi-page app (navigation + all page renderers)
├── data_loader.py     # I/O: SQLite, subprocess commands, file parsing, redaction
├── metrics.py         # KPI computation, verdict distribution, latency analysis
├── compliance.py      # EU AI Act article mapping and coverage status
├── session_replay.py  # Session grouping, timeline, pipeline trace reconstruction
└── README.md          # This file
```

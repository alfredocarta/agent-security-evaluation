# Dashboard v2 / ASF operationalization progress report

Date: 2026-06-06
Scope: ASF/Hermes live integration, Dashboard v2 observability, HITL, audit trail reliability, pagination/caching, and thesis-methodology terminology.

## 1. Hermes -> ASF integration status

Hermes is using its own virtual environment:

- `/Users/alfredo/.hermes/hermes-agent/venv`

The Hermes venv now contains the runtime dependencies needed by the ASF interceptor path, including:

- `joblib`
- `scikit-learn`
- `scipy`
- `onnxruntime`
- `onnx`
- `aiosqlite` for Dashboard v2 tests/API support

This fixes the previous live failure:

- `ASF check failed: No module named 'joblib'`

The Hermes ASF plugin defaults Stage 3 to ONNX Prompt Guard unless explicitly overridden:

- `ASF_STAGE3_BACKEND=onnx`

Live smoke integration was checked with Hermes-style tool calls through the ASF plugin:

- benign terminal call: `ALLOW`, persisted in `hermes_tool_traces`
- injection-like terminal command: `DENY`, persisted in `hermes_tool_traces`

Dashboard API reads those Hermes traces from the ASF database and exposes them through session detail drill-downs. The displayed stages are no longer generic `Unknown` for L1.5 fast-path cases; examples now show labels such as `L1.5 fast-path`, `Stage 2.5 DeBERTa`, and `Stage 3 ONNX Prompt Guard` when the event reason/backend supports those labels.

Operational note: Hermes is treated as an integration/compatibility check unless the model is actually invoked in the evaluation loop. Hermes fallback/interception-only rows must not be counted as full end-to-end utility preservation, output-side detection, fail-closed runtime, or real model-performance metrics.

## 2. HITL workflow

Dashboard v2 now supports an operational human oversight loop:

- pending HITL queue: `GET /api/hitl`
- approve endpoint: `POST /api/hitl/{event_id}/approve`
- reject/block endpoint: `POST /api/hitl/{event_id}/reject`
- persistence table: `dashboard_hitl_decisions`
- audit outcomes appended to `audit_trail`:
  - `HITL_APPROVED`
  - `HITL_REJECTED`

After approval/rejection, the request is removed from the pending queue by joining `audit_trail` against `dashboard_hitl_decisions`.

The frontend includes a dark dashboard-style modal for human decisions. The HITL page states that decisions are persisted in the append-only audit trail and removed from the pending queue. Reviewer and note fields are persisted with the decision and the human decision is also reflected as a hash-chained audit event.

## 3. Stage 3 / ONNX / Gemma labeling

Dashboard labeling was tightened to avoid conflating ONNX Prompt Guard with Gemma:

- `Stage 3 ONNX` is used for generic ONNX Stage 3 evidence.
- `Stage 3 ONNX Prompt Guard` is used when the reason/backend indicates Prompt Guard.
- `Stage 3 LLM` remains the generic LLM fallback label.
- `Stage 3 Gemma 2B` is only displayed when event text actually indicates Gemma.

This keeps ONNX Prompt Guard / Prompt Guard 86M / PG86M evidence separate from Gemma 2B evidence.

## 4. Scalable pagination and caching

Dashboard v2 separates backend pagination from browser-side page caches.

EU AI Act drill-down:

- endpoint: `GET /api/compliance/{article}?limit=20&offset=0`
- backend TTL cache key includes article, limit, and offset
- browser cache avoids refetching already loaded article evidence
- UI supports `Load next 20`
- selective article queries avoid full-table frontend filtering and use indexed database queries where possible

Session detail drill-down:

- endpoint: `GET /api/sessions/{session_id}?limit=20&offset=0`
- backend TTL cache key includes session, limit, and offset
- browser cache keyed by session/page
- UI shows only 20 timeline events per page
- Previous / Next 20 controls page through session events

Main session list:

- endpoint: `GET /api/sessions?limit=20&offset=0&agent_id=...`
- backend cache key includes limit, offset, agent, and eval visibility
- frontend cache keyed by agent, page size, and page
- selected-agent change resets page/cache state
- refresh forces API reload while preserving useful expanded state when possible
- offset `0` and `20` return distinct pages in tests and smoke API checks

SQLite indexes added or ensured include timestamp, outcome/timestamp, agent/timestamp, hash, prev_hash, Hermes trace session/timestamp, trace/timestamp, and HITL decision event lookup.

## 5. Evaluation terminology and methodological separation

Documentation and dashboard wording should continue to distinguish:

End-to-end evaluations:

- the model is actually invoked;
- the full pipeline runs;
- output-side behavior and utility are measurable.

Integration checks / interception-only checks / compatibility checks:

- ASF intercepts, logs, applies controls, or proves compatibility;
- the target agent/model may not be invoked in the loop;
- the result is operational evidence, not model-performance evidence.

Hermes, CrewAI, or LangGraph fallback-mode checks must not be mixed into end-to-end metrics unless the model is genuinely invoked in the loop.

## 6. Thesis/documentation cleanup guidance

When updating thesis text, apply these corrections:

- Do not overstate dataset independence: DeBERTa fine-tuned uses deepset + OPI training splits.
- Align Always-Stage25 references between Chapter 5 and Chapter 6.
- Fix Stage 3 latency wording; avoid stale values such as 300 ms if measured values are closer to 50/80 ms.
- Complete OPI citations.
- Add citations for Garak, Promptfoo, PyRIT, BIPIA, Mindgard, SPML, and jackhhao if those systems/datasets are discussed.
- Clarify the relationship between the ASF repository and Dashboard v2.
- Reduce changelog tone in Chapter 5.
- Add confidence intervals if available, or at least a note on statistical uncertainty.
- Standardize terms: fine-tuned / fine-tuning, ONNX Prompt Guard / Prompt Guard 86M / PG86M, fast-path / fast-clear / fast-block, Stage 2.5a / Stage 2.5b.
- For EU AI Act Art. 10, present ASF as technical evidence for traceability, logging, and evaluation, not complete legal data-lifecycle governance.

Italian terminology cleanup:

- script -> procedure di valutazione
- cross-dataset -> tabella comparativa tra insiemi di dati
- classifier gate -> filtro basato su classificatore
- routing -> flusso decisionale
- probe -> controllo semantico
- escalation -> passaggio allo Stage 2.5a
- fallback mode -> verifica di integrazione / integration check
- kill switch -> meccanismo di sospensione
- reinstate_agent -> riabilitazione / ripristino dello stato attivo
- deployment -> ambiente operativo / sistema in produzione

## 7. Verification performed

Automated tests:

- Dashboard pagination/HITL tests: `7 passed`
- ASF Hermes plugin/trace-store tests: `5 passed`

Smoke API checks:

- `/health`: OK
- `/api/metrics`: OK
- `/api/sessions?limit=20&offset=0`: OK, 20 sessions
- `/api/sessions?limit=20&offset=20`: OK, 20 sessions, first session differs from page 1
- `/api/compliance`: OK
- `/api/compliance/Art.%2012?limit=20&offset=0`: OK

Live Hermes-style ASF plugin checks:

- `smoke-benign`: `ALLOW / ALLOWED`
- `smoke-injection`: `DENY / BLOCKED`

## 8. Remaining risks / follow-up

- Browser automation was not run with Playwright/Puppeteer because those packages are not installed in the Hermes venv. API and static frontend code paths were checked; a real browser console pass is still recommended.
- Stage 2.5 DeBERTa tokenizer emits a warning about an upstream regex setting. It does not break the smoke test but should be reviewed before thesis latency claims.
- Some live Hermes rows generated before this fix may still show historical `Agent suspended` reasons. New rows should show meaningful ASF stages/reasons.
- The HITL dashboard persists decisions and audit evidence, but it does not yet resume the originally blocked side effect. That is appropriate for a defensible dashboard checkpoint, but should be documented as human oversight evidence rather than automatic action continuation.

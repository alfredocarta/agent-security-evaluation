# ASF Compliance Dashboard — Critical Review

**Reviewer:** Senior Product Designer / Security Engineer  
**Date:** 2026-05-20  
**Revision:** v2.0 (SQLite backend)  
**Data snapshot:** 397 raw audit entries, 9 sessions, 5 agents, all events today  

---

## 1. What works well

**Theming system.** The CSS custom-property approach (`--bg-primary`, `--accent`, etc.) is correct. Dark/light toggle persists via `localStorage`, applied before Vue mounts to avoid flash. Stage badge colour pairs are carefully tuned for both modes. This is genuinely well-executed.

**Session drill-down.** Clicking a session row expands an inline event timeline showing stage, verdict badge, latency, EU AI Act article, and security model per event. The SHA-256 hash chain is followed in `_enrich_with_chain_data` to compute end-to-end latency only on terminal events — a correct design. The `trace_id` linkage works across intermediate stages.

**Sessionisation algorithm.** `_sessionize()` in `db.py` correctly groups events by agent + 30-second gap window, handles edge cases (missing timestamps, agent changes), and assigns deterministic session IDs. The fallback from terminal-only to all events in `get_session_events` is a sensible safety net.

**Compliance article drill-down.** Clicking EU AI Act rows loads correlated events. The `ARTICLE_OUTCOMES` sentinel pattern for Art. 12 (all events count) versus specific outcome sets for Art. 9/14/15 is clean and easy to extend.

**Agent filtering.** Both `/api/metrics?agent_id=X` and `/api/sessions?agent_id=X` are wired up and the Vue dropdown + `@change="refresh()"` correctly re-fetches all panels. The agent list itself comes from a distinct `/api/agents` call to avoid hardcoding.

**Pydantic response models.** All four routers return typed Pydantic models. FastAPI auto-generates OpenAPI docs at `/docs`. The models are minimal but correct.

**Scroll spy.** `IntersectionObserver` with `rootMargin: '-70px 0px -55% 0px'` tracks the active sidebar item reliably, including smooth-scroll via `scrollTo()`.

**HITL badge in sidebar.** The `<span v-if="hitlEvents.length > 0" class="nav-badge">` counter is reactive and disappears when the queue is empty. Small but useful.

---

## 2. Critical issues (must fix before showing to a client)

### 2.1 Timeline chart never renders

**Problem.** `renderTimeline()` calls `document.getElementById('timelineChart')` but no `<canvas id="timelineChart">` element exists anywhere in `index.html`. The function returns silently on `if (!ctx) return`. The "Impact" section and the overview feel incomplete without any time-series view.

**Why it matters.** A compliance dashboard without a time chart looks broken. A client will immediately notice the empty space or the missing visual that the layout seems to expect.

**Fix.** Add a canvas element inside the Overview section between the KPI grid and the before/after comparison card:

```html
<div class="card" style="padding:20px;margin-bottom:20px;">
  <div class="section-hdr">
    <span class="section-title">Activity Timeline</span>
    <span class="section-sub">Events per hour</span>
  </div>
  <canvas id="timelineChart" height="80"></canvas>
</div>
```

### 2.2 "Tool Calls Monitored" is inflated ~6×

**Problem.** The KPI card "Tool Calls Monitored (24h)" displays `total_events = 397`. However, the `audit_trail` table stores one row per pipeline stage, not per tool call. A single tool call that traverses INTERCEPTOR_START → STAGE_1_START → STAGE_1_PASS → STAGE_2_START → STAGE_2_UNCERTAIN → STAGE_2.5_START → KILL_SWITCH produces **7 rows** but represents **1 tool call**. Confirmed from live data: session `pyrit-crescendo-eval-agent-session-0009` has 66 raw events but only 10 terminal decisions.

**Why it matters.** Telling a client "we monitored 397 tool calls" when the real number is ~64 is factually wrong. If this ever makes it into a report, it will damage credibility.

**Fix.** Count distinct `trace_id` values with a terminal outcome, or count terminal events only:

```python
# in get_metrics:
total_events = len(set(row.get("trace_id") for row in rows if row.get("trace_id")))
```

Rename the KPI label to "Tool Calls Inspected (24h)".

### 2.3 Block rate denominator silently excludes incomplete traces

**Problem.** `detection_rate = blocked / (blocked + allowed + hitl)`. The denominator is 64 (terminal decisions) but the total raw events are 397. Two sessions — `smolagents-eval-agent-session-0002` (16 events) and `sql-agent-asf-eval-agent-session-0003` (2 events) — have `blocked_count=0, allowed_count=0, hitl_count=0`, meaning their traces never reached a terminal outcome. These tool calls are not counted in any KPI. A client asking "what happened to those calls?" has no answer.

**Why it matters.** Incomplete traces could indicate pipeline errors, timeouts, or partially-inserted data. Silently dropping them from the block rate makes the metric unreliable.

**Fix.** Track incomplete traces explicitly. Add an `incomplete_count` field to `KPIMetrics` and show it in the UI as "X traces without terminal decision" with a warning badge.

### 2.4 HITL Approve/Reject buttons look broken

**Problem.** The HITL queue table renders `<button class="badge badge-allow" style="cursor:default;opacity:.5;">Approve</button>`. The 50% opacity and non-pointer cursor make them look like disabled/broken buttons. There is a small footnote below the table saying they are read-only, but it is styled as `c-muted` — very easy to miss.

**Why it matters.** A client or operator who sees a pending HITL request and cannot act on it from the dashboard will feel something is broken, not "by design."

**Fix.** Either (a) remove the buttons entirely and replace with a clear callout: `"To act on requests, use the ASF HITL API: POST /hitl/{event_id}/approve"`, or (b) implement the approve/reject flow with a modal confirmation dialog.

### 2.5 `callsTrend` assumes 30 days of data that does not exist

**Problem.** The trend label under "Tool Calls Monitored" is computed as:
```js
const avgDay = total / 30;  // hardcoded 30-day assumption
const ratio = last24h / (avgDay || 1);
```
With all 397 events from a single day, `avgDay = 397/30 ≈ 13.2` and `ratio = 397/13.2 ≈ 30×`, producing a trend like "↑ 2900% above daily avg" — completely meaningless.

**Why it matters.** This is the first trend indicator a client reads. A nonsensical trend label destroys confidence in the metrics.

**Fix.** Either compute the actual daily average from the earliest timestamp in the dataset, or hide the trend label when fewer than 7 days of data exist.

---

## 3. Data quality issues

### 3.1 `false_positive_rate` is hardcoded to 0.0

`KPIMetrics.false_positive_rate` is set to `0.0` in `get_metrics()` with no calculation. A hardcoded 0% false-positive rate in a security tool is immediately suspicious to any auditor or SOC analyst. It should either be removed from the model or computed from labelled ground-truth data when available.

### 3.2 Art. 14 "No evidence" is misleading

The compliance table shows Art. 14 (Human oversight) as "No evidence" because there are zero HITL events in the dataset. This is semantically wrong: "no escalations occurred" ≠ "no human oversight capability exists." A compliance auditor reading "No evidence" for the human oversight article will be alarmed. The status should read "Configured — no escalations in period" when HITL is wired up, and "No evidence" only when the HITL mechanism is absent.

### 3.3 Art. 15 "Accuracy" mapping is a stretch

26 ALLOWED events are used as evidence of "Accuracy" under Art. 15. Art. 15 is about the accuracy and robustness of AI system outputs, not about how many requests were permitted by a security gate. This mapping will not survive scrutiny from a legal/compliance reviewer. A more defensible mapping would be confidence scores from Stage 2/3 classifiers as a proxy for accuracy.

### 3.4 `agent_model: "not recorded in SQLite audit trail"` leaks implementation detail

Every event returned by the API includes `"agent_model": "not recorded in SQLite audit trail"`. This is an internal implementation note, not a user-facing value. It should be `null`. The current value tells clients the data is missing and exposes the schema.

### 3.5 `prev_hash` exposed in all event responses

Every `AuditEvent` includes `prev_hash` (the full SHA-256 hash of the preceding record). This is an internal integrity field that belongs in the audit log, not in a read API. Exposing it reveals the hash chain structure to anyone who can read the dashboard.

### 3.6 Compliance `event_count` for Art. 12 uses a different source than Art. 9/15

`compliance.py` counts Art. 9/15 events from `get_recent_events(limit=10000)` but counts Art. 12 from `get_total_event_count()` (a direct `COUNT(*)` SQL query). If the database has more than 10,000 events, Art. 9/15 counts will be undercounted relative to Art. 12, making the table internally inconsistent.

---

## 4. UX issues

### 4.1 Session IDs are truncated to lose their meaningful suffix

`truncate(session.session_id, 26)` cuts `pyrit-crescendo-eval-agent-session-0009` (42 chars) to `pyrit-crescendo-eval-agent` — dropping the session number entirely. All pyrit sessions would show identical text. The truncation should preserve the end, not the beginning: show `…session-0009` instead.

### 4.2 Sessions with zero decisions show "–" with no explanation

Two sessions (`smolagents-eval-agent-session-0002`, `sql-agent-asf-eval-agent-session-0003`) show "–" for both blocked and allowed counts. Without a tooltip or footnote, users have no way to know this means "pipeline did not reach a terminal decision" vs. "no data." A "?" badge with a tooltip would help.

### 4.3 "Block Rate" colour coding is counterintuitive

`blockRateStyle` colours high block rate (>80%) in red and low block rate (<50%) in green. This implies "green = good, red = bad," but a high block rate against a known red-team agent (like pyrit) is expected and desired. The metric's meaning depends entirely on which agent is selected. The static colouring misleads users.

### 4.4 Agent framework lookup is hardcoded

`expandedSessionInfo` matches agent IDs against a hardcoded list (`smolagents`, `asf-eval`, `openhands`, `pyrit`, `promptfoo`). Any new agent not in this list shows "unknown framework / not recorded." This will silently degrade as the agent roster grows. Store framework metadata in the database or a config file.

### 4.5 No search, date range, or verdict filter

The only filter in the UI is the agent dropdown. There is no date range picker, no verdict filter (ALLOW/DENY/HITL), no stage filter, and no full-text search on the reason field. For any operational use beyond a demo, this makes finding specific events impractical.

### 4.6 No pagination controls

Sessions default to 50 rows with no "Load more" or page controls. Users have no visibility into how many sessions exist or how to navigate older ones.

### 4.7 The compliance section has no visual progress indicator

The EU AI Act table is pure text with counts and "Active/No evidence" badges. A compliance-focused stakeholder expects a visual summary — a simple progress bar or gauge showing "3/4 articles have evidence" would communicate posture at a glance.

---

## 5. Security issues

### 5.1 Open CORS with no authentication

`main.py` sets `allow_origins=["*"]`. Any page on any origin can query all audit data. For a production deployment — even an internal one — this is unacceptable. All API endpoints return sensitive security event data (attack details, tool names, reasons) without any bearer token, API key, or session check.

**Fix:** Restrict `allow_origins` to the specific dashboard origin. Add an API key header check or integrate with an identity provider.

### 5.2 No rate limiting on expensive endpoints

`/api/compliance` and `/api/events` both call `_fetch_rows()`, which loads the entire `audit_trail` table into Python memory, applies sessionisation (O(n log n) sort), and runs chain enrichment (O(n) with dict lookups). There is no caching layer. Two concurrent browser tabs polling every 5 seconds means 24 full-table reads per minute. With a 100k-row database this will be slow and could be used for resource exhaustion.

**Fix:** Add an LRU or TTL cache (e.g. `functools.lru_cache` with a TTL wrapper, or Redis) keyed on a hash of the DB's `MAX(rowid)`. Alternatively, push to a read replica or materialized view.

### 5.3 `prev_hash` in API responses assists chain reconstruction

See section 3.5. Exposing `prev_hash` allows any reader to reconstruct the full hash chain topology and potentially identify which events to tamper with for chain repair attacks in a mutable-storage scenario.

### 5.4 `__main__` binds to 0.0.0.0

`uvicorn.run(..., host="0.0.0.0", ...)` in `main.py __main__` binds to all network interfaces. Combined with no auth, this means the dashboard is reachable from the entire network if started directly. The deployment docs should enforce `host="127.0.0.1"` with a reverse proxy in front.

### 5.5 `article_code` path parameter is unsanitised

`compliance_events(article_code: str)` receives a raw URL segment with no validation. The current `ARTICLE_OUTCOMES.get(article_code)` lookup is safe (returns `None` for unknowns), but there is no length or character-set check. FastAPI will pass any string including very long inputs. Adding a `Literal["Art. 9", "Art. 12", "Art. 14", "Art. 15"]` annotation would self-document the contract and reject bad values at the framework level.

---

## 6. Missing features (high value, low effort — 1-2 days each)

1. **Fix the timeline chart.** Add `<canvas id="timelineChart">` to the HTML. The JavaScript is fully written and functional. Estimated effort: 15 minutes.

2. **Correct "Tool Calls Monitored" to count traces, not raw rows.** Count distinct `trace_id` values that have a terminal outcome. Update the KPI label to "Tool Calls Inspected." Estimated effort: 2 hours.

3. **Date-range filter.** Add "last 1h / 6h / 24h / 7d / all" buttons above the KPI grid. The backend already computes `events_last_24h` using `datetime.utcnow() - timedelta(hours=24)` — extend this pattern to accept a `since` query parameter. Estimated effort: 4 hours.

4. **Verdict / stage filter on sessions.** Add a small filter bar above the sessions table: verdict (ALLOW/DENY/HITL) and agent. The data is already in `SessionSummary`. Estimated effort: 1 day.

5. **Art. 14 status wording fix + HITL API link.** Change "No evidence" to "No escalations in period" and add a docs link to the HITL API endpoint. Replace the non-functional Approve/Reject buttons with a code snippet. Estimated effort: 1 hour.

---

## 7. Missing features (high value, high effort — 1-2 weeks each)

1. **Hash-chain integrity verification UI.** The SHA-256 chain is the core tamper-evidence claim for Art. 12. Add a "Verify chain" button that reads all `(hash, prev_hash)` pairs and confirms the chain is unbroken. Display the result as a compliance artifact with a timestamp. Without this, the Art. 12 claim is asserted but never demonstrated.

2. **Real-time HITL workflow.** Implement WebSocket push for new HITL events (instead of polling), a review modal with full event context (tool name, full reason, trace chain), and approve/reject actions that call the ASF HITL API with an audit log of the human decision. This is necessary for Art. 14 to be more than a paper claim.

3. **Attack-pattern analytics panel.** Aggregate blocked events by attack type (inferred from `reason`), tool, and agent. Show trend lines per attack category (e.g. "SQL injection attempts", "prompt injection via DeBERTa", "regex-blocked patterns"). Include a heatmap of attack density over time. This transforms the dashboard from a log viewer into an actual security intelligence tool.

---

## 8. Comparison with industry standards

### vs. Langfuse (observability)

| Dimension | ASF Dashboard | Langfuse |
|---|---|---|
| Event granularity | Tool-call boundary only | Full LLM trace: prompt, completion, tool call, token cost |
| Security vocabulary | DENY/ALLOW/HITL, threat stages, EU AI Act | Not security-native; generic observability |
| Compliance mapping | Art. 9/12/14/15 mapped to events | None |
| Trace visualisation | Flat event list | Hierarchical span tree |
| Cost tracking | None | Token cost per trace |

**ASF does better:** Security-specific classification (stages, verdicts, attack type) that Langfuse has no concept of. EU AI Act evidence linkage is unique.  
**ASF is missing:** LLM reasoning turn capture, hierarchical trace tree, cost metrics, search/filter, and a proper timeline chart that Langfuse provides out of the box.

### vs. Datadog Security (SIEM)

| Dimension | ASF Dashboard | Datadog Security |
|---|---|---|
| Detection specificity | Agent tool-call level | Log-level, spans, metrics |
| Alert rules | None | Threshold alerts, anomaly detection, notification routing |
| Investigation workflow | Click to expand | Full case management with timeline, related entities |
| Auth / RBAC | None | Full RBAC with org-level access control |
| Retention | SQLite file | Scalable log ingestion, configurable retention |

**ASF does better:** Native AI agent context (agent_id, tool_name, pipeline stage) that SIEM tools require custom parsers to understand.  
**ASF is missing:** Alert thresholds, notification channels (Slack, PagerDuty), case management, user authentication.

### vs. Generic EU AI Act compliance tool

| Dimension | ASF Dashboard | Generic tool |
|---|---|---|
| Evidence type | Runtime security events | Self-assessment checklist |
| Art. 12 | Hash-chained append-only log | Document upload |
| Art. 14 | Live HITL queue | Policy statement |
| Coverage | Art. 9, 12, 14, 15 only | All articles |

**ASF does better:** Provides runtime evidence rather than self-attestation. The audit trail is tamper-evident and machine-generated.  
**ASF is missing:** Coverage of Art. 13 (transparency), Art. 16 (obligations of providers), Art. 17 (quality management), Art. 61 (post-market monitoring). No export format for formal auditors (PDF report, CSAF, SPDX).

---

## 9. Overall score and recommendation

| Dimension | Score | Notes |
|---|---|---|
| Visual design | **7/10** | Clean, professional dark mode, good typography. Missing timeline chart and no progress gauge hurt. |
| Data accuracy | **4/10** | "Tool Calls Monitored" inflated 6×, FPR hardcoded to 0, trend baseline broken, incomplete traces invisible. |
| Feature completeness | **5/10** | Broken chart, non-functional HITL actions, no date filter, no search, no pagination, no chain verification. |
| Production readiness | **3/10** | Open CORS, no auth, no rate limiting, no caching, binds 0.0.0.0, internal schema text in API responses. |

**Recommendation.** The visual shell is in good shape and the backend data model is architecturally sound — the hash chain, sessionisation, and EU AI Act tagging are real differentiators. But the dashboard cannot be shown to a client or used in production yet. The three priorities in order are: (1) fix the data accuracy problems — the inflated event count and broken trend calculation will be the first thing any technical stakeholder challenges; (2) add the timeline chart (a 15-minute fix that makes the dashboard feel finished rather than broken); and (3) add at minimum a static API key check to the backend before any external deployment. After those, the HITL workflow and hash-chain verification UI are what would move this from "impressive demo" to "credible compliance artifact."

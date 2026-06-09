const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('sessions');
  createApp({
    template: ASF.shell('sessions', 'Sessions', content),
  data: () => ({
    sessions: [], agents: [], selectedAgent: '', sessionEvents: [], sessionPageCache: {}, sessionHasMore: {},
    sessionLoadingMore: false, sessionPageSize: 20, sessionPage: 0, sessionsPage: 0, sessionsPageSize: 10,
    sessionsPageCache: {}, sessionsHasMore: false, sessionsLoading: false, expandedSession: null,
    loadingSession: false, expandedReasons: new Set(), expandedEventDetails: new Set(), activeEventDetailsId: null, eventExplanations: {}, loadingEventDetails: new Set(), selectedPipelineStages: {}, sessionSearch: '',
    lastRefresh: '', refreshLabel: '5s', footerText: 'ASF v2', dataAsOf: null, dbSource: '',
  }),
  computed: {
    filteredSessions() {
      let result = this.sessions;
      if (this.sessionSearch) {
        const q = this.sessionSearch.toLowerCase();
        result = result.filter(s => s.session_id.toLowerCase().includes(q) || s.agent_id.toLowerCase().includes(q));
      }
      return result;
    },
    paginatedFilteredSessions() { return this.filteredSessions.slice(0, this.sessionsPageSize); },
    expandedSessionInfo() {
      if (!this.expandedSession) return null;
      const s = this.sessions.find(x => x.session_id === this.expandedSession);
      const firstEvent = this.sessionEvents && this.sessionEvents.length ? this.sessionEvents[0] : null;
      const id = (s && s.agent_id) || (firstEvent && firstEvent.agent_id) || '';
      if (!id) return null;
      const apiFramework = s && s.agent_framework;
      const apiModel = (s && s.agent_model) || (firstEvent && firstEvent.agent_model);
      if (apiFramework || apiModel) return { agentId: id, framework: apiFramework || this.frameworkForAgent(id), model: apiModel || this.modelForAgent(id) };
      if (id.includes('hermes')) return { agentId: id, framework: 'Hermes Agent', model: 'gpt-5.5 via openai-codex' };
      if (id.includes('smolagents')) return { agentId: id, framework: 'ToolCallingAgent (smolagents)', model: 'gemma2:2b via Ollama' };
      if (id.includes('autogen')) return { agentId: id, framework: 'AutoGen async agent', model: 'gemma2:2b via Ollama (AutoGen async)' };
      if (id.includes('sql-agent')) return { agentId: id, framework: 'SQL evaluation agent', model: 'Rule-based (no LLM)' };
      if (id.includes('asf-eval')) return { agentId: id, framework: 'LangGraph ReAct', model: 'LangGraph ReAct' };
      if (id.includes('crewai')) return { agentId: id, framework: 'CrewAI agent', model: 'gemma2:2b via Ollama (CrewAI)' };
      if (id.includes('openhands')) return { agentId: id, framework: 'OpenHands CodeAct', model: 'not recorded' };
      if (id.includes('pyrit')) return { agentId: id, framework: 'PyRIT red-team', model: 'not recorded' };
      if (id.includes('promptfoo')) return { agentId: id, framework: 'promptfoo eval', model: 'not recorded' };
      if (id.includes('claude-code')) return { agentId: id, framework: 'Claude Code (MCP)', model: 'claude-sonnet-4-6 via MCP' };
      return { agentId: id, framework: 'unknown framework', model: 'not recorded' };
    },
    expandedSessionTotalEvents() {
      if (!this.expandedSession) return this.sessionEvents.length || 0;
      const s = this.sessions.find(x => x.session_id === this.expandedSession);
      return Math.max(Number(s?.total_events || 0), this.sessionEvents.length || 0);
    },
    expandedSessionTotalPages() { return Math.max(1, Math.ceil(this.expandedSessionTotalEvents / this.sessionPageSize)); },
    paginatedSessionEvents() { return (this.sessionEvents || []).slice(0, this.sessionPageSize); },
    activeEventDetails() { return (this.sessionEvents || []).find(ev => ev.event_id === this.activeEventDetailsId) || null; },
    maxSessionDuration() { return this.sessions.length ? (Math.max(...this.sessions.map(s => s.duration_ms || 0)) || 1) : 1; },
  },
  watch: { sessionSearch() { this.sessionsPage = 0; this.expandedSession = null; this.sessionEvents = []; this.sessionPage = 0; this.closeEventDetails(); } },
  mounted() {
    this.refresh();
    setInterval(this.refresh, 5000);
    this.onEventDetailsKeydown = event => { if (event.key === 'Escape') this.closeEventDetails(); };
    window.addEventListener('keydown', this.onEventDetailsKeydown);
  },
  beforeUnmount() { if (this.onEventDetailsKeydown) window.removeEventListener('keydown', this.onEventDetailsKeydown); },
  methods: {
    ...ASF.methods,
    async refresh() {
      const agents = await this.fetchJson('/api/agents');
      this.agents = agents;
      await this.loadSessionsPage(this.sessionsPage, { force: true, collapse: false });
      this.loadProvenance();
      this.lastRefresh = new Date().toLocaleTimeString();
      if (this.expandedSession) this.loadSession(this.expandedSession);
    },
    async loadSessionsPage(page = this.sessionsPage, { force = false, collapse = true } = {}) {
      const agentSnapshot = this.selectedAgent;
      const safePage = Math.max(0, page);
      const pageSize = Number(this.sessionsPageSize) || 10;
      const pageKey = `${agentSnapshot || 'all'}:${pageSize}:${safePage}`;
      const cached = this.sessionsPageCache[pageKey];
      if (!force && cached) {
        this.sessionsPage = safePage; this.sessions = cached.sessions; this.sessionsHasMore = cached.hasMore;
        if (collapse) { this.expandedSession = null; this.sessionEvents = []; this.sessionPage = 0; this.closeEventDetails(); }
        this.sessionsLoading = false; this.footerText = `${this.sessions.length} sessions · ASF v2`; return;
      }
      this.sessionsLoading = true;
      const offset = safePage * pageSize;
      const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
      if (agentSnapshot) params.set('agent_id', agentSnapshot);
      try {
        const rows = await this.fetchJson(`/api/sessions?${params.toString()}`);
        if (this.selectedAgent !== agentSnapshot) return;
        const visibleRows = rows.slice(0, pageSize);
        const pageData = { sessions: visibleRows, hasMore: rows.length === pageSize };
        this.sessionsPageCache = { ...this.sessionsPageCache, [pageKey]: pageData };
        this.sessionsPage = safePage; this.sessions = visibleRows; this.sessionsHasMore = pageData.hasMore;
        this.footerText = `${this.sessions.length} sessions · ASF v2`;
        if (collapse) { this.expandedSession = null; this.sessionEvents = []; this.sessionPage = 0; this.closeEventDetails(); }
      } finally { this.sessionsLoading = false; }
    },
    async nextSessionsPage() { if (this.sessionsHasMore && !this.sessionsLoading) await this.loadSessionsPage(this.sessionsPage + 1); },
    async prevSessionsPage() { if (this.sessionsPage !== 0 && !this.sessionsLoading) await this.loadSessionsPage(this.sessionsPage - 1); },
    async onSessionsPageSizeChange() {
      this.sessionsPageSize = Number(this.sessionsPageSize) || 10; this.sessionsPage = 0; this.sessionsPageCache = {}; this.sessionsHasMore = false;
      this.expandedSession = null; this.sessionEvents = []; this.sessionPage = 0; this.closeEventDetails();
      await this.loadSessionsPage(0, { force: true });
    },
    async onAgentChange() {
      this.expandedSession = null; this.sessionEvents = []; this.closeEventDetails(); this.sessionPageCache = {};
      this.sessionHasMore = {}; this.sessionsPageCache = {}; this.sessionsHasMore = false; this.sessionsLoading = false;
      this.sessionPage = 0; this.sessionsPage = 0; await this.refresh();
    },
    prefetchSession(sessionId) {
      const pageKey = `${sessionId}:0`; if (this.sessionPageCache[pageKey]) return;
      this.fetchJson(`/api/sessions/${encodeURIComponent(sessionId)}?limit=${this.sessionPageSize}&offset=0`)
        .then(events => { if (!this.sessionPageCache[pageKey]) this.sessionPageCache = { ...this.sessionPageCache, [pageKey]: events.slice(0, this.sessionPageSize) }; })
        .catch(() => {});
    },
    async toggleSession(sessionId) {
      if (this.expandedSession === sessionId) { this.expandedSession = null; this.sessionEvents = []; this.sessionPage = 0; this.expandedReasons = new Set(); this.closeEventDetails(); return; }
      this.expandedSession = sessionId; this.sessionPage = 0; this.expandedReasons = new Set(); this.closeEventDetails(); await this.loadSession(sessionId, 0);
    },
    async loadSession(sessionId, page = this.sessionPage) {
      const pageKey = `${sessionId}:${page}`; const cached = this.sessionPageCache[pageKey];
      if (cached) { this.sessionPage = page; this.sessionEvents = cached; this.loadingSession = false; this.sessionLoadingMore = false; return; }
      const offset = page * this.sessionPageSize; if (page === 0) this.loadingSession = true; else this.sessionLoadingMore = true;
      try {
        const events = (await this.fetchJson(`/api/sessions/${encodeURIComponent(sessionId)}?limit=${this.sessionPageSize}&offset=${offset}`)).slice(0, this.sessionPageSize);
        this.sessionPageCache = { ...this.sessionPageCache, [pageKey]: events }; this.sessionPage = page; this.sessionEvents = events;
        this.sessionHasMore = { ...this.sessionHasMore, [sessionId]: page + 1 < this.expandedSessionTotalPages };
      } finally { this.loadingSession = false; this.sessionLoadingMore = false; }
    },
    async nextSessionPage() { if (this.expandedSession && !this.sessionLoadingMore && this.sessionPage + 1 < this.expandedSessionTotalPages) await this.loadSession(this.expandedSession, this.sessionPage + 1); },
    async prevSessionPage() { if (this.expandedSession && !this.sessionLoadingMore && this.sessionPage !== 0) await this.loadSession(this.expandedSession, this.sessionPage - 1); },
    expandReason(id) { const s = new Set(this.expandedReasons); s.has(id) ? s.delete(id) : s.add(id); this.expandedReasons = s; },
    frameworkForAgent(id) { return (id || '').includes('hermes') ? 'Hermes Agent' : 'framework not recorded'; },
    modelForAgent(id) { return (id || '').includes('hermes') ? 'gpt-5.5 via openai-codex' : 'not recorded'; },
    hitlDecisionMetadata(ev) {
      if (!ev) return null;
      const reviewer = ev.reviewer || ev.hitl_reviewer || ev.reviewed_by || ev.decision_reviewer;
      const note = ev.note || ev.hitl_note || ev.review_note || ev.decision_note || ev.human_note;
      if (reviewer || note) return { reviewer: reviewer || 'not recorded', note: note || '' };
      const outcome = String(ev.outcome || '').toUpperCase(); if (!outcome.startsWith('HITL_') || outcome === 'HITL_REQUESTED') return null;
      const match = String(ev.reason || '').match(/reviewer:([^\n]*?)(?:\s+note:(.*))?$/); if (!match) return null;
      const r = (match[1] || '').trim(); const n = (match[2] || '').trim(); return r || n ? { reviewer: r || 'unknown', note: n } : null;
    },
    isTerminalEvent(ev) { return ['deny', 'allow', 'hitl'].includes(this.decisionTone(ev)); },
    isBlockedEvent(ev) { return this.decisionTone(ev) === 'deny'; },
    eventDetailsButtonClass(ev) {
      const tone = this.decisionTone(ev);
      if (tone === 'deny') return 'event-details-btn event-details-btn-deny';
      if (tone === 'allow') return 'event-details-btn event-details-btn-allow';
      if (tone === 'hitl') return 'event-details-btn event-details-btn-hitl';
      return 'event-details-btn';
    },
    explanationForEvent(ev) { return ev?.event_id ? this.eventExplanations[ev.event_id] : null; },
    explanationPipeline(ev) {
      const pipeline = this.explanationForEvent(ev)?.pipeline || [];
      return this.meaningfulPipeline(pipeline);
    },
    terminalStageIndex(ev) {
      const stages = this.explanationPipeline(ev);
      if (!stages.length) return 0;
      const idx = stages.findIndex(s => s && s.terminal);
      return idx >= 0 ? idx : stages.length - 1;
    },
    selectedPipelineIndex(ev) {
      if (!ev?.event_id) return 0;
      const stages = this.explanationPipeline(ev);
      if (!stages.length) return 0;
      const stored = this.selectedPipelineStages[ev.event_id];
      if (Number.isInteger(stored) && stored >= 0 && stored < stages.length) return stored;
      return this.terminalStageIndex(ev);
    },
    selectedPipelineStage(ev) {
      const stages = this.explanationPipeline(ev);
      return stages[this.selectedPipelineIndex(ev)] || null;
    },
    selectPipelineStage(ev, idx) {
      if (!ev?.event_id) return;
      this.selectedPipelineStages = { ...this.selectedPipelineStages, [ev.event_id]: idx };
    },
    stageStepTitle(stage, idx) {
      const display = this.stageDisplay(stage?.stage);
      return `Step ${idx + 1}: ${display.label} (${display.technical})`;
    },
    async toggleEventDetails(ev) {
      if (!ev?.event_id) return;
      if (this.activeEventDetailsId === ev.event_id) {
        this.closeEventDetails();
        return;
      }
      this.activeEventDetailsId = ev.event_id;
      this.expandedEventDetails = new Set([ev.event_id]);
      if (!this.eventExplanations[ev.event_id]) await this.loadEventExplanation(ev);
    },
    closeEventDetails() {
      this.activeEventDetailsId = null;
      this.expandedEventDetails = new Set();
    },
    async loadEventExplanation(ev) {
      if (!ev?.event_id || this.loadingEventDetails.has(ev.event_id)) return;
      const loading = new Set(this.loadingEventDetails);
      loading.add(ev.event_id);
      this.loadingEventDetails = loading;
      try {
        const explanation = await this.fetchJson(`/api/events/${encodeURIComponent(ev.event_id)}/explanation`);
        this.eventExplanations = { ...this.eventExplanations, [ev.event_id]: explanation };
      } catch (err) {
        this.eventExplanations = {
          ...this.eventExplanations,
          [ev.event_id]: {
            event_id: ev.event_id,
            final_verdict: ev.verdict,
            final_outcome: ev.outcome,
            final_reason: ev.reason || 'No reason recorded.',
            security_model: ev.security_model,
            latency_ms: ev.latency_ms,
            pipeline: [{
              stage: ev.stage || 'Unknown stage', outcome: ev.outcome, verdict: ev.verdict,
              confidence: ev.confidence, reason: ev.reason || 'No reason recorded.',
              timestamp: ev.timestamp, latency_ms: ev.latency_ms, terminal: true,
            }],
          },
        };
      } finally {
        const next = new Set(this.loadingEventDetails);
        next.delete(ev.event_id);
        this.loadingEventDetails = next;
      }
    },
    stageToneClass(stage) {
      const verdict = String(stage?.verdict || '').toUpperCase();
      const outcome = String(stage?.outcome || '').toUpperCase();
      if (verdict === 'DENY' || ['BLOCKED', 'KILL_SWITCH', 'L1.5_BLOCK', 'ONNX_BLOCK', 'OUTPUT_BLOCK', 'HITL_REJECTED'].includes(outcome)) return 'pipeline-stage-deny';
      if (verdict === 'ALLOW' || ['ALLOWED', 'HEURISTIC_CLEAR', 'HITL_APPROVED'].includes(outcome)) return 'pipeline-stage-allow';
      if (verdict === 'HITL' || outcome === 'HITL_REQUESTED') return 'pipeline-stage-hitl';
      return 'pipeline-stage-neutral';
    },
    stageConfidenceLabel(stage) {
      const v = stage?.confidence;
      if (v == null || Number.isNaN(Number(v))) {
        const name = String(stage?.stage || '').toLowerCase();
        if (name.includes('l1.5') || name.includes('policy') || name.includes('regex')) return 'rule-based';
        return '-';
      }
      const n = Number(v);
      return n <= 1 ? `${(n * 100).toFixed(0)}%` : `${n.toFixed(1)}%`;
    },
    toggleEventDetailsLegacy(ev) { return this.toggleEventDetails(ev); },
    pipelineStagesForEvent(ev) {
      if (!ev) return [];
      const rows = this.sessionEvents || [];
      let stages = ev.trace_id ? rows.filter(x => x.trace_id && x.trace_id === ev.trace_id) : [];
      if (stages.length <= 1) stages = [ev];
      return stages.filter(x => x && (x.stage || x.outcome || x.confidence != null))
        .slice().sort((a, b) => (this.parseUtcDate(a.timestamp)?.getTime() || 0) - (this.parseUtcDate(b.timestamp)?.getTime() || 0));
    },
    formatConfidence(v) { if (v == null || Number.isNaN(Number(v))) return '-'; const n = Number(v); return n <= 1 ? `${(100 * n).toFixed(0)}%` : `${n.toFixed(1)}%`; },
  },
}).mount('#app');
})();

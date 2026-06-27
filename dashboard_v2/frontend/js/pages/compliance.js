const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('compliance');
  createApp({
    template: ASF.shell('compliance', 'EU AI Act', content),
    data: () => ({
      metrics: {}, compliance: [],
      expandedArticle: null, loadingArticle: false,
      timelineWindow: '24h', timelineAgentFilter: '', timelineOutcomeFilter: '',
      timelineAllEvents: [], modalCluster: null,
      lastRefresh: '', refreshLabel: '5s', footerText: ASF.versionStr(), dataAsOf: null, dbSource: '', activeEnv: 'production',
    }),
    mounted() { this.refresh(); setInterval(this.refresh, 5000); },
    computed: {
      timelineAgentOptions() {
        return [...new Set(this.timelineAllEvents.map(ev => ev.agent_id).filter(Boolean))].sort();
      },
      timelineEvents() {
        const visible = this.timelineAllEvents
          .filter(ev => !this.timelineAgentFilter || ev.agent_id === this.timelineAgentFilter)
          .slice()
          .sort((a, b) => this.timelineTime(a) - this.timelineTime(b));
        const calls = new Map();
        for (const ev of visible) {
          const traceId = String(ev.trace_id || '').trim();
          const key = traceId || `legacy:${ev.event_id || ev.timestamp || Math.random()}`;
          if (!calls.has(key)) calls.set(key, []);
          calls.get(key).push(ev);
        }
        const items = [];
        for (const [key, events] of calls.entries()) {
          events.sort((a, b) => this.timelineTime(a) - this.timelineTime(b));
          const summary = this.timelineTerminalEvent(events);
          const outcome = String(summary?.outcome || summary?.verdict || '').toUpperCase();
          if (this.timelineOutcomeFilter && outcome !== this.timelineOutcomeFilter) continue;
          if (events.length > 1) {
            items.push({ type: 'call', key: `call:${key}`, event: summary, events, count: events.length, timestamp: summary.timestamp });
          } else {
            const ev = events[0];
            items.push({ type: 'event', key: ev.event_id || `${key}:${ev.timestamp}`, event: ev });
          }
        }
        return items.sort((a, b) => this.timelineItemTime(b) - this.timelineItemTime(a));
      },
    },
    methods: {
      ...ASF.methods,
      async refresh() {
        this.loadProvenance();
        const [metrics, compliance] = await Promise.all([this.fetchJson('/api/metrics'), this.fetchJson('/api/compliance')]);
        this.metrics = metrics; this.compliance = compliance;
        this.dataAsOf = metrics.data_as_of || null; this.dbSource = metrics.db_source || '';
        this.lastRefresh = new Date().toLocaleTimeString();
      },
      evidenceState(item) {
        // Maps the backend status string to an explicit, defensible evidence state.
        // We never claim "compliant"; we claim only what the recorded events support.
        const s = String(item.status || '').toLowerCase();
        if (s.startsWith('active') && item.event_count > 0) return { cls: 'ev-state-verified', label: 'Evidence recorded' };
        if (s.startsWith('active')) return { cls: 'ev-state-mechanism', label: 'Mechanism present' };
        if (s.startsWith('partial')) return { cls: 'ev-state-partial', label: 'Partial evidence' };
        if (s.startsWith('configured')) return { cls: 'ev-state-partial', label: 'Configured' };
        if (s.includes('not applicable') || s.includes('n/a')) return { cls: 'ev-state-na', label: 'Not applicable' };
        return { cls: 'ev-state-none', label: 'No evidence' };
      },
      async toggleArticle(article) {
        if (this.expandedArticle === article) { this.expandedArticle = null; this.timelineAllEvents = []; this.modalCluster = null; return; }
        this.expandedArticle = article; await this.loadArticle(article);
      },
      async loadArticle(article) {
        this.loadingArticle = true;
        try {
          this.modalCluster = null;
          this.timelineAllEvents = await this.fetchJson(`/api/compliance/${encodeURIComponent(article)}?limit=500&offset=0&window=${encodeURIComponent(this.timelineWindow)}`);
          if (this.timelineAgentFilter && !this.timelineAgentOptions.includes(this.timelineAgentFilter)) this.timelineAgentFilter = '';
        } finally { this.loadingArticle = false; }
      },
      async changeTimelineWindow(window) {
        if (this.timelineWindow === window) return;
        this.timelineWindow = window;
        if (this.expandedArticle) await this.loadArticle(this.expandedArticle);
      },
      timelineClusterMs() {
        if (this.timelineWindow === '1h') return 60 * 1000;
        if (this.timelineWindow === '7d') return 60 * 60 * 1000;
        return 5 * 60 * 1000;
      },
      timelineTime(ev) {
        const d = this.parseUtcDate(ev?.timestamp);
        return d ? d.getTime() : 0;
      },
      timelineItemTime(item) {
        if (item.type === 'cluster' || item.type === 'call') return this.timelineTime(item.event || item.events[0]);
        return this.timelineTime(item.event);
      },
      timelineLabel(v) {
        const d = this.parseUtcDate(v);
        if (!d) return '';
        if (this.timelineWindow === '7d') {
          const day = d.toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: '2-digit' });
          const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
          return `${day} ${time}`;
        }
        if (this.timelineWindow === '24h') {
          return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      },
      openClusterModal(item) {
        this.modalCluster = item;
      },
      closeModal() {
        this.modalCluster = null;
      },
      timelineColor(ev) {
        const outcome = String(ev?.outcome || ev?.verdict || '').toUpperCase();
        const allow = new Set(['ALLOW', 'ALLOWED', 'HEURISTIC_CLEAR', 'HITL_APPROVED']);
        const hitl = new Set(['HITL', 'HITL_REQUESTED']);
        const deny = new Set(['DENY', 'BLOCK', 'BLOCKED', 'KILL_SWITCH', 'OUTPUT_BLOCK', 'L1.5_BLOCK', 'ONNX_BLOCK', 'HEURISTIC_BLOCK', 'HITL_REJECTED']);
        if (allow.has(outcome)) return '#52c47a';
        if (deny.has(outcome) || outcome.endsWith('_BLOCK')) return '#c0392b';
        if (hitl.has(outcome)) return '#f0a500';
        if (outcome === 'INTERCEPTOR_START') return '#888';
        return '#888';
      },
      timelineTerminalEvent(events) {
        const terminal = new Set(['ALLOWED', 'HEURISTIC_CLEAR', 'BLOCKED', 'KILL_SWITCH', 'OUTPUT_BLOCK', 'L1.5_BLOCK', 'ONNX_BLOCK', 'HEURISTIC_BLOCK', 'HITL_REQUESTED', 'HITL_APPROVED', 'HITL_REJECTED']);
        const ordered = events.slice().sort((a, b) => this.timelineTime(a) - this.timelineTime(b));
        return ordered.slice().reverse().find(ev => terminal.has(String(ev?.outcome || '').toUpperCase())) || ordered[ordered.length - 1];
      },
      timelineBadgeStyle(ev) {
        const color = this.timelineColor(ev);
        return { color, borderColor: `${color}80`, background: `${color}20` };
      },
      timelineClusterStyle(item) {
        const color = this.timelineColor(item.event || item.events[0]);
        return { background: color, borderColor: '#fff' };
      },
      timelineTooltip(ev) {
        return {
          agent_id: ev.agent_id || 'not recorded',
          agent_model: ev.agent_model || 'not recorded',
          security_model: ev.security_model || 'not recorded',
          confidence: this.formatConfidence(ev.confidence),
          reason: ev.reason || 'No reason recorded.',
          latency_ms: ev.latency_ms != null ? this.formatDuration(ev.latency_ms) : 'not recorded',
        };
      },
      formatConfidence(value) {
        if (value == null || value === '') return 'not recorded';
        const n = Number(value);
        if (!Number.isFinite(n)) return String(value);
        return `${Math.round((n <= 1 ? n * 100 : n) * 10) / 10}%`;
      },
    },
  }).mount('#app');
})();

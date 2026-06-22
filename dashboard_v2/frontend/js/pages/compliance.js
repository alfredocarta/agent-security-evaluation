const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('compliance');
  createApp({
    template: ASF.shell('compliance', 'EU AI Act', content),
    data: () => ({
      metrics: {}, compliance: [],
      expandedArticle: null, loadingArticle: false,
      timelineWindow: '7d', timelineAgentFilter: '', timelineOutcomeFilter: '',
      timelineAllEvents: [], expandedClusters: new Set(),
      lastRefresh: '', refreshLabel: '5s', footerText: ASF.versionStr(), dataAsOf: null, dbSource: '', activeEnv: 'production',
    }),
    mounted() { this.refresh(); setInterval(this.refresh, 5000); },
    computed: {
      timelineAgentOptions() {
        return [...new Set(this.timelineAllEvents.map(ev => ev.agent_id).filter(Boolean))].sort();
      },
      timelineEvents() {
        const filtered = this.timelineAllEvents
          .filter(ev => !this.timelineAgentFilter || ev.agent_id === this.timelineAgentFilter)
          .filter(ev => !this.timelineOutcomeFilter || ev.outcome === this.timelineOutcomeFilter)
          .slice()
          .sort((a, b) => this.timelineTime(b) - this.timelineTime(a));
        const threshold = this.timelineClusterMs();
        const buckets = new Map();
        for (const ev of filtered) {
          const time = this.timelineTime(ev);
          const bucket = Math.floor(time / threshold) * threshold;
          const key = `${this.timelineWindow}:${bucket}`;
          if (!buckets.has(key)) buckets.set(key, []);
          buckets.get(key).push(ev);
        }
        const items = [];
        for (const [key, events] of buckets.entries()) {
          if (events.length > 1 && !this.expandedClusters.has(key)) {
            items.push({ type: 'cluster', key, events, count: events.length, timestamp: events[0].timestamp });
          } else if (events.length > 1) {
            items.push({ type: 'cluster-expanded', key, events, count: events.length, timestamp: events[0].timestamp });
            events.forEach(ev => items.push({ type: 'event', key: ev.event_id || `${key}:${ev.timestamp}`, event: ev }));
          } else {
            events.forEach(ev => items.push({ type: 'event', key: ev.event_id || `${key}:${ev.timestamp}`, event: ev }));
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
        if (this.expandedArticle === article) { this.expandedArticle = null; this.timelineAllEvents = []; this.expandedClusters = new Set(); return; }
        this.expandedArticle = article; await this.loadArticle(article);
      },
      async loadArticle(article) {
        this.loadingArticle = true;
        try {
          this.expandedClusters = new Set();
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
        return item.type === 'cluster' ? this.timelineTime(item.events[0]) : this.timelineTime(item.event);
      },
      toggleCluster(key) {
        const next = new Set(this.expandedClusters);
        if (next.has(key)) next.delete(key); else next.add(key);
        this.expandedClusters = next;
      },
      timelineColor(ev) {
        const outcome = String(ev?.outcome || ev?.verdict || '').toUpperCase();
        if (outcome === 'DENY' || outcome === 'KILL_SWITCH') return '#e05252';
        if (outcome === 'BLOCKED') return '#c0392b';
        if (outcome === 'ALLOWED' || outcome === 'ALLOW') return '#52c47a';
        if (outcome === 'HITL_REQUESTED' || outcome === 'HITL') return '#f0a500';
        return '#888';
      },
      timelineBadgeStyle(ev) {
        const color = this.timelineColor(ev);
        return { color, borderColor: `${color}80`, background: `${color}20` };
      },
      timelineClusterStyle(item) {
        const color = this.timelineColor(item.events[0]);
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

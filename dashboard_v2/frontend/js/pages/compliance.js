const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('compliance');
  createApp({
    template: ASF.shell('compliance', 'EU AI Act', content),
    data: () => ({
      metrics: {}, compliance: [], articleEvents: [], articleCache: {}, articleHasMore: {},
      articleLoadingMore: false, articlePageSize: 20, expandedArticle: null, loadingArticle: false,
      lastRefresh: '', refreshLabel: '5s', footerText: 'ASF v2', dataAsOf: null, dbSource: '',
    }),
    mounted() { this.refresh(); setInterval(this.refresh, 5000); },
    methods: {
      ...ASF.methods,
      async refresh() {
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
        if (this.expandedArticle === article) { this.expandedArticle = null; this.articleEvents = []; return; }
        this.expandedArticle = article; await this.loadArticle(article);
      },
      async loadArticle(article, { append = false } = {}) {
        const cached = this.articleCache[article];
        if (!append && cached) { this.articleEvents = cached; this.loadingArticle = false; return; }
        const offset = append ? (this.articleCache[article]?.length || 0) : 0;
        if (append) this.articleLoadingMore = true; else this.loadingArticle = true;
        try {
          const events = await this.fetchJson(`/api/compliance/${encodeURIComponent(article)}?limit=${this.articlePageSize}&offset=${offset}`);
          const existing = append ? (this.articleCache[article] || []) : [];
          const merged = append ? existing.concat(events) : events;
          this.articleCache[article] = merged; this.articleEvents = merged;
          this.articleHasMore = { ...this.articleHasMore, [article]: events.length === this.articlePageSize };
        } finally { this.loadingArticle = false; this.articleLoadingMore = false; }
      },
      async loadMoreArticleEvents() { if (this.expandedArticle && !this.articleLoadingMore) await this.loadArticle(this.expandedArticle, { append: true }); },
    },
  }).mount('#app');
})();

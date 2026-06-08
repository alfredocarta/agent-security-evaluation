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
        this.lastRefresh = new Date().toLocaleTimeString('it-IT');
      },
      evidenceState(item) {
        // Maps the backend status string to an explicit, defensible evidence state.
        // We never claim "compliant"; we claim only what the recorded events support.
        const s = String(item.status || '').toLowerCase();
        if (s.startsWith('active') && item.event_count > 0) return { cls: 'ev-state-verified', label: 'Evidenza registrata' };
        if (s.startsWith('active')) return { cls: 'ev-state-mechanism', label: 'Meccanismo presente' };
        if (s.startsWith('partial')) return { cls: 'ev-state-partial', label: 'Evidenza parziale' };
        if (s.startsWith('configured')) return { cls: 'ev-state-partial', label: 'Configurato' };
        if (s.includes('not applicable') || s.includes('n/a')) return { cls: 'ev-state-na', label: 'Non applicabile' };
        return { cls: 'ev-state-none', label: 'Nessuna evidenza' };
      },
      complianceControl(value) {
        const labels = {
          'Risk management': 'Gestione del rischio',
          'Data governance': 'Governance dei dati',
          'Record keeping': 'Tenuta dei registri',
          'Transparency': 'Trasparenza',
          'Human oversight': 'Supervisione umana',
          'Accuracy': 'Accuratezza',
          'Quality management': 'Gestione della qualità',
        };
        return labels[value] || value || '';
      },
      complianceText(value) {
        const labels = {
          'Blocking and kill-switch events provide evidence of active risk controls.': 'Gli eventi di blocco e kill-switch forniscono evidenza di controlli del rischio attivi.',
          'Classifier trained on labeled prompt injection data. deepset/prompt-injections and Open Prompt Injection benchmarks provide independent validation.': 'Classificatore addestrato su dati di prompt injection etichettati. I benchmark deepset/prompt-injections e Open Prompt Injection forniscono validazione indipendente.',
          'Training data quality documented in STAGE3_MODEL_COMPARISON.md': 'Qualità dei dati di training documentata in STAGE3_MODEL_COMPARISON.md.',
          'All intercepted tool calls are retained in the SHA-256 hash-chained append-only audit trail.': 'Tutte le chiamate strumento intercettate sono conservate nel registro di audit append-only con catena hash SHA-256.',
          'Count shows unique intercepted tool calls; every entry is evidence of record-keeping.': 'Il conteggio mostra chiamate strumento intercettate uniche; ogni voce è evidenza di tenuta dei registri.',
          'Every security decision includes a reason field explaining which stage made the decision and why.': 'Ogni decisione di sicurezza include un campo motivo che spiega quale stadio ha preso la decisione e perché.',
          'Reason is logged for each decision; structured end-user transparency reporting is not yet exposed.': "Il motivo viene registrato per ogni decisione; la reportistica strutturata di trasparenza per l'utente finale non è ancora esposta.",
          'HITL requests show cases escalated for human review.': 'Le richieste HITL mostrano i casi inoltrati a revisione umana.',
          'Zero escalations means the HITL mechanism was not triggered - not that it is absent.': 'Zero escalation significa che il meccanismo HITL non è stato attivato, non che sia assente.',
          'Allowed events show requests that passed ASF security controls.': 'Gli eventi consentiti mostrano richieste che hanno superato i controlli di sicurezza ASF.',
          'Evaluation suite T01-T09 and external benchmarks (deepset, Open Prompt Injection) provide continuous quality validation.': 'La suite di valutazione T01-T09 e i benchmark esterni (deepset, Open Prompt Injection) forniscono validazione continua della qualità.',
          'QMS evidence is operational and test-based; formal QMS documentation remains partial.': "L'evidenza QMS è operativa e basata sui test; la documentazione QMS formale resta parziale.",
        };
        return labels[value] || value || '';
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

const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('overview');
  const app = createApp({
    template: ASF.shell('overview', 'Panoramica', content),
    data: () => ({
      metrics: {},
      lastRefresh: '',
      refreshLabel: '5s',
      footerText: 'ASF v2',
      dataAsOf: null,
      dbSource: '',
      refreshInterval: null,
      charts: null,
      chartsWindow: '24h',
    }),
    computed: {
      blockRateValueStyle() {
        return 'color:var(--text-primary)';
      },
      blockStageSegments() {
        const funnel = (this.charts && this.charts.stage_funnel) || [];
        return funnel
          .filter(s => (s.blocked || 0) > 0)
          .map(s => {
            const display = ASF.stageDisplay(s.stage);
            return { label: display.label, technical: display.technical, value: s.blocked, color: ASFCharts.stageColor(s.stage) };
          });
      },
      callsSpark() {
        const tl = (this.charts && this.charts.timeline) || [];
        return tl.map(p => (p.blocked || 0) + (p.allowed || 0) + (p.hitl || 0));
      },
      blockSpark() {
        const tl = (this.charts && this.charts.timeline) || [];
        return tl.map(p => p.blocked || 0);
      },
      posture() {
        const m = this.metrics;
        const terminal = (m.blocked_count || 0) + (m.allowed_count || 0) + (m.hitl_count || 0);
        if (!terminal) return { cls: 'posture-attn', label: 'Nessuna decisione di sicurezza registrata', detail: 'La pipeline non ha prodotto verdetti terminali in questo dataset.' };
        const fresh = this.dataAsOf ? !this.freshness(this.dataAsOf).stale : false;
        if (!fresh) return { cls: 'posture-attn', label: 'Operativa - dati non aggiornati', detail: "L'evento di audit più recente risale a oltre un'ora fa; le metriche potrebbero non essere aggiornate." };
        if (m.hitl_count > 0) return { cls: 'posture-attn', label: 'Operativa - revisione umana in attesa', detail: `${m.hitl_count} escalation instradata/e alla supervisione umana.` };
        return { cls: 'posture-ok', label: 'Operativa - controlli attivi', detail: 'Le chiamate strumento vengono ispezionate e i verdetti terminali registrati.' };
      },
    },
    mounted() { this.startRefresh(); },
    beforeUnmount() { this.stopRefresh(); },
    methods: {
      ...ASF.methods,
      startRefresh() {
        this.stopRefresh();
        this.refreshLabel = '5s';
        this.refresh();
        this.refreshInterval = setInterval(this.refresh, 5000);
      },
      stopRefresh() {
        if (this.refreshInterval) {
          clearInterval(this.refreshInterval);
          this.refreshInterval = null;
        }
      },
      async refresh() {
        this.metrics = await this.fetchJson('/api/metrics');
        this.dataAsOf = this.metrics.data_as_of || null;
        this.dbSource = this.metrics.db_source || '';
        try {
          this.charts = await this.fetchJson(`/api/metrics/charts?window=${this.chartsWindow}`);
        } catch (_e) {
          // charts are a non-critical enrichment; keep KPIs rendering if this fails
        }
        this.lastRefresh = new Date().toLocaleTimeString('it-IT');
      },
      async setChartsWindow(window) {
        if (this.chartsWindow === window) return;
        this.chartsWindow = window;
        this.charts = await this.fetchJson(`/api/metrics/charts?window=${window}`);
      },
      decisionWidth(blocked, allowed, hitl, kind) {
        const values = { blocked: blocked || 0, allowed: allowed || 0, hitl: hitl || 0 };
        const total = values.blocked + values.allowed + values.hitl;
        if (!total) return kind === 'allowed' ? '100%' : '0%';
        return `${(values[kind] / total) * 100}%`;
      },
    },
  });
  ASFCharts.install(app);
  app.mount('#app');
})();

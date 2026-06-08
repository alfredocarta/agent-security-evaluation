const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('report');
  createApp({
    template: ASF.shell('report', 'Daily Report', content),
    data: () => ({ dailyReport: {}, reportDate: '', reportLoading: false, lastRefresh: '', refreshLabel: '5s', footerText: 'ASF v2', dataAsOf: null, dbSource: '' }),
    mounted() { this.loadDailyReport(); setInterval(() => this.loadDailyReport(this.reportDate || undefined, { silent: true }), 5000); },
    methods: {
      ...ASF.methods,
      async loadDailyReport(date, { silent = false } = {}) {
        this.reportLoading = true;
        try {
          const qs = date ? `?date=${encodeURIComponent(date)}` : '';
          const report = await this.fetchJson(`/api/report/daily${qs}`);
          this.dailyReport = report; this.reportDate = report.date || date || this.reportDate;
          this.loadProvenance();
          this.lastRefresh = new Date().toLocaleTimeString();
        } catch (err) { if (!silent) alert(err.message || String(err)); }
        finally { this.reportLoading = false; }
      },
    },
  }).mount('#app');
})();

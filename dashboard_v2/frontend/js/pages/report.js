const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('report');
  createApp({
    template: ASF.shell('report', 'Daily Report', content),
    data: () => ({ dailyReport: {}, reportDate: '', reportLoading: false, lastRefresh: '', refreshLabel: '', footerText: 'ASF v2' }),
    mounted() { this.loadDailyReport(); },
    methods: {
      ...ASF.methods,
      async loadDailyReport(date) {
        this.reportLoading = true;
        try {
          const qs = date ? `?date=${encodeURIComponent(date)}` : '';
          const report = await this.fetchJson(`/api/report/daily${qs}`);
          this.dailyReport = report; this.reportDate = report.date || date || this.reportDate;
          this.lastRefresh = new Date().toLocaleTimeString();
        } catch (err) { alert(err.message || String(err)); }
        finally { this.reportLoading = false; }
      },
    },
  }).mount('#app');
})();

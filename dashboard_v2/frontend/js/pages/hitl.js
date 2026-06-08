const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('hitl');
  const modal = `<div v-if="hitlModal" class="modal-backdrop" @click.self="closeHitlModal">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="hitl-modal-title">
    <div class="modal-hdr"><div id="hitl-modal-title" class="modal-title"><span :class="hitlModal.decision === 'approve' ? 'c-success' : 'c-danger'">{{ hitlModal.decision === 'approve' ? 'Allow HITL request' : 'Block HITL request' }}</span><span class="badge badge-neutral">Art. 14</span></div><button class="hitl-btn" @click="closeHitlModal" :disabled="hitlDeciding[hitlModal.event.event_id]">Close</button></div>
    <div class="modal-body">
      <div class="modal-copy">This will write a human oversight decision to the ASF audit trail and remove the request from the pending queue.</div>
      <div class="modal-summary"><div class="modal-summary-row"><span>Agent</span><span>{{ hitlModal.event.agent_id }}</span></div><div class="modal-summary-row"><span>Tool</span><span>{{ hitlModal.event.tool_name || hitlModal.event.action }}</span></div><div class="modal-summary-row"><span>Stage</span><span>{{ hitlModal.event.stage }}</span></div><div class="modal-summary-row"><span>Reason</span><span class="modal-summary-reason">{{ hitlModal.event.reason }}</span></div></div>
      <div class="modal-field-grid"><label><span class="modal-field-label">Reviewer</span><input class="modal-input" type="text" v-model="hitlModal.reviewer" placeholder="dashboard-user" autofocus /></label><label><span class="modal-field-label">Note (optional)</span><input class="modal-input" type="text" v-model="hitlModal.note" placeholder="Optional decision note" /></label></div>
    </div>
    <div class="modal-actions"><button class="modal-btn" @click="closeHitlModal" :disabled="hitlDeciding[hitlModal.event.event_id]">Cancel</button><button class="modal-btn" :class="hitlModal.decision === 'approve' ? 'modal-btn-success' : 'modal-btn-danger'" :disabled="hitlDeciding[hitlModal.event.event_id]" @click="confirmHitlDecision">{{ hitlModal.decision === 'approve' ? 'Allow' : 'Block' }}</button></div>
  </div>
</div>`;
  createApp({
    template: ASF.shell('hitl', 'Human Oversight', content, modal),
    data: () => ({ hitlEvents: [], hitlDeciding: {}, hitlModal: null, lastRefresh: '', refreshLabel: '5s', footerText: 'ASF v2', dataAsOf: null, dbSource: '' }),
    mounted() { this.refresh(); setInterval(this.refresh, 5000); },
    methods: {
      ...ASF.methods,
      async refresh() { this.hitlEvents = await this.fetchJson('/api/hitl'); this.loadProvenance(); this.lastRefresh = new Date().toLocaleTimeString(); },
      openHitlModal(ev, decision) { this.hitlModal = { event: ev, decision, reviewer: 'dashboard-user', note: '' }; },
      closeHitlModal() { if (this.hitlModal && this.hitlDeciding[this.hitlModal.event.event_id]) return; this.hitlModal = null; },
      async confirmHitlDecision() {
        if (!this.hitlModal) return;
        await this.decideHitl(this.hitlModal.event, this.hitlModal.decision, { reviewer: (this.hitlModal.reviewer || 'dashboard-user').trim() || 'dashboard-user', note: (this.hitlModal.note || '').trim() });
      },
      async decideHitl(ev, decision, meta = {}) {
        this.hitlDeciding = { ...this.hitlDeciding, [ev.event_id]: true };
        try {
          await fetch(`/api/hitl/${encodeURIComponent(ev.event_id)}/${decision === 'approve' ? 'approve' : 'reject'}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reviewer: meta.reviewer || 'dashboard-user', note: meta.note || null }) }).then(r => { if (!r.ok) throw new Error(`HITL ${decision} failed: ${r.status}`); return r.json(); });
          this.hitlEvents = this.hitlEvents.filter(x => x.event_id !== ev.event_id); this.hitlModal = null; await this.refresh();
        } catch (err) { alert(err.message || String(err)); } finally { const next = { ...this.hitlDeciding }; delete next[ev.event_id]; this.hitlDeciding = next; }
      },
    },
  }).mount('#app');
})();

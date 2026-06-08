const { createApp } = Vue;
(async () => {
  const content = await ASF.loadSection('hitl');
  const modal = `<div v-if="hitlModal" class="modal-backdrop" @click.self="closeHitlModal">
  <div class="modal-card hitl-modal-card" role="dialog" aria-modal="true" aria-labelledby="hitl-modal-title">
    <div class="modal-hdr">
      <div id="hitl-modal-title" class="modal-title"><span>Rivedi richiesta HITL</span><span class="badge badge-neutral">Art. 14</span></div>
      <button class="hitl-btn" @click="closeHitlModal" :disabled="hitlDeciding[hitlModal.event.event_id]">Chiudi</button>
    </div>
    <div class="modal-body hitl-modal-body">
      <div class="modal-copy">Rivedi il contesto ASF completo prima di scegliere Consenti o Blocca. La decisione verrà scritta nel registro di audit append-only e rimuoverà la richiesta dalla coda in attesa.</div>
      <div v-if="hitlExplanationLoading[hitlModal.event.event_id]" class="hitl-modal-loading">Caricamento spiegazione...</div>
      <div v-if="hitlExplanationErrors[hitlModal.event.event_id]" class="hitl-modal-warning">Spiegazione non disponibile. Viene mostrato l'evento HITL di base per consentire la revisione.</div>

      <div class="decision-context">
        <div class="decision-context-title">Contesto della decisione</div>
        <div class="decision-context-grid">
          <div class="decision-context-meta"><span>Agente</span><b>{{ hitlExplanation().agent_id || hitlModal.event.agent_id || 'non registrato' }}</b></div>
          <div class="decision-context-meta"><span>Modello</span><b>{{ hitlExplanation().agent_model || hitlModal.event.agent_model || 'non registrato' }}</b></div>
          <div class="decision-context-meta"><span>Strumento</span><b>{{ hitlExplanation().tool_name || hitlModal.event.tool_name || hitlModal.event.action || 'non registrato' }}</b></div>
          <div class="decision-context-meta"><span>Modello di sicurezza</span><b>{{ hitlExplanation().security_model || hitlModal.event.security_model || 'non registrato' }}</b></div>
        </div>
        <div class="event-explanation-reason">{{ hitlExplanation().final_reason || hitlModal.event.reason || 'Nessun motivo registrato.' }}</div>
      </div>

      <div v-if="hitlFlaggingStage()" class="pipeline-card pipeline-detail-card" :class="stageToneClass(hitlFlaggingStage())" style="margin-bottom:14px;">
        <div class="pipeline-card-hdr">
          <div class="pipeline-detail-title">
            <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;">
              <span class="pipeline-detail-name">Stadio che ha richiesto la revisione: {{ stageLabel(hitlFlaggingStage().stage) }}</span>
              <span :class="verdictBadgeClass(hitlFlaggingStage())">{{ hitlFlaggingStage().verdict || hitlFlaggingStage().outcome || 'HITL' }}</span>
            </div>
            <div class="pipeline-detail-tech" :title="stageTechnical(hitlFlaggingStage().stage)">Tecnico: {{ stageTechnical(hitlFlaggingStage().stage) }}</div>
          </div>
          <div class="pipeline-score">{{ stageConfidenceLabel(hitlFlaggingStage()) }}</div>
        </div>
        <div class="pipeline-reason">{{ hitlFlaggingStage().reason || hitlExplanation().final_reason || hitlModal.event.reason || 'Nessun motivo registrato per questo stadio.' }}</div>
      </div>

      <div class="pipeline-timeline" style="margin-bottom:14px;">
        <div class="decision-context-title">Percorso decisionale</div>
        <div class="pipeline-stepper" role="tablist" aria-label="Stadi della pipeline decisionale">
          <button v-for="(stageEv, idx) in hitlPipeline()" :key="hitlModal.event.event_id + '-hitl-step-' + idx" type="button" class="pipeline-step" :class="[stageToneClass(stageEv), { active: hitlModal.selectedPipelineIndex === idx }]" :title="stageStepTitle(stageEv, idx)" @click.stop="selectHitlPipelineStage(idx)">
            <span class="pipeline-step-index">{{ idx + 1 }}</span>
            <span class="pipeline-step-text">
              <span class="pipeline-step-label">{{ stageLabel(stageEv.stage) }}</span>
              <span class="pipeline-step-tech">{{ stageShortTech(stageEv.stage) }}</span>
            </span>
            <span v-if="stageEv.terminal" class="pipeline-step-final">finale</span>
          </button>
        </div>
        <div v-if="hitlSelectedPipelineStage()" class="pipeline-card pipeline-detail-card" :class="stageToneClass(hitlSelectedPipelineStage())">
          <div class="pipeline-card-hdr">
            <div class="pipeline-detail-title">
              <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;">
                <span class="pipeline-detail-name">{{ stageLabel(hitlSelectedPipelineStage().stage) }}</span>
                <span :class="verdictBadgeClass(hitlSelectedPipelineStage())">{{ hitlSelectedPipelineStage().verdict || hitlSelectedPipelineStage().outcome || 'nessun verdetto' }}</span>
                <span v-if="hitlSelectedPipelineStage().terminal" class="badge badge-neutral">finale</span>
              </div>
              <div class="pipeline-detail-tech" :title="stageTechnical(hitlSelectedPipelineStage().stage)">Tecnico: {{ stageTechnical(hitlSelectedPipelineStage().stage) }}</div>
            </div>
            <div class="pipeline-score">{{ stageConfidenceLabel(hitlSelectedPipelineStage()) }}</div>
          </div>
          <div class="pipeline-reason">{{ hitlSelectedPipelineStage().reason || 'Nessun motivo registrato per questo stadio.' }}</div>
          <div class="pipeline-meta">
            <span v-if="hitlSelectedPipelineStage().timestamp">{{ timeOnly(hitlSelectedPipelineStage().timestamp) }}</span>
            <span v-if="hitlSelectedPipelineStage().latency_ms != null">{{ formatDuration(hitlSelectedPipelineStage().latency_ms) }}</span>
            <span>{{ hitlSelectedPipelineStage().outcome || 'nessun outcome' }}</span>
          </div>
        </div>
      </div>

      <div class="decision-context">
        <div class="decision-context-title">Input/Output della chiamata</div>
        <div class="decision-io">
          <div class="decision-io-head"><span>Input</span><span v-if="hitlExplanation().input_troncato" class="badge badge-neutral">troncato</span></div>
          <pre class="decision-io-block" :class="{ 'decision-io-empty': !hitlExplanation().tool_input }">{{ hitlExplanation().tool_input || 'input non registrato' }}</pre>
        </div>
        <div class="decision-io">
          <div class="decision-io-head"><span>Output</span><span v-if="hitlExplanation().output_troncato" class="badge badge-neutral">troncato</span></div>
          <pre class="decision-io-block" :class="{ 'decision-io-empty': !hitlExplanation().tool_output }">{{ hitlExplanation().tool_output || 'output non registrato' }}</pre>
        </div>
      </div>

      <div class="modal-field-grid">
        <label><span class="modal-field-label">Revisore</span><input class="modal-input" type="text" v-model="hitlModal.reviewer" placeholder="dashboard-user" autofocus /></label>
        <label><span class="modal-field-label">Nota (facoltativa)</span><input class="modal-input" type="text" v-model="hitlModal.note" placeholder="Nota facoltativa sulla decisione" /></label>
      </div>
    </div>
    <div class="modal-actions">
      <button class="modal-btn" @click="closeHitlModal" :disabled="hitlDeciding[hitlModal.event.event_id]">Annulla</button>
      <button class="modal-btn modal-btn-success" :disabled="hitlDeciding[hitlModal.event.event_id]" @click="confirmHitlDecision('approve')">Consenti</button>
      <button class="modal-btn modal-btn-danger" :disabled="hitlDeciding[hitlModal.event.event_id]" @click="confirmHitlDecision('reject')">Blocca</button>
    </div>
  </div>
</div>`;
  createApp({
    template: ASF.shell('hitl', 'Supervisione umana', content, modal),
    data: () => ({
      hitlEvents: [],
      hitlDeciding: {},
      hitlModal: null,
      hitlExplanationCache: {},
      hitlExplanationLoading: {},
      hitlExplanationErrors: {},
      lastRefresh: '',
      refreshLabel: '5s',
      footerText: 'ASF v2',
      dataAsOf: null,
      dbSource: '',
    }),
    mounted() { this.refresh(); setInterval(this.refresh, 5000); },
    methods: {
      ...ASF.methods,
      async refresh() {
        this.hitlEvents = await this.fetchJson('/api/hitl');
        this.loadProvenance();
        this.lastRefresh = new Date().toLocaleTimeString('it-IT');
      },
      openHitlModal(ev) {
        this.hitlModal = { event: ev, reviewer: 'dashboard-user', note: '', selectedPipelineIndex: 0 };
        this.loadHitlExplanation(ev);
      },
      closeHitlModal() {
        if (this.hitlModal && this.hitlDeciding[this.hitlModal.event.event_id]) return;
        this.hitlModal = null;
      },
      async loadHitlExplanation(ev) {
        if (!ev?.event_id) return;
        const eventId = ev.event_id;
        if (this.hitlExplanationCache[eventId]) {
          this.setHitlSelectedPipelineIndex(eventId);
          return;
        }
        this.hitlExplanationLoading = { ...this.hitlExplanationLoading, [eventId]: true };
        const errors = { ...this.hitlExplanationErrors };
        delete errors[eventId];
        this.hitlExplanationErrors = errors;
        try {
          const explanation = await this.fetchJson(`/api/events/${encodeURIComponent(eventId)}/explanation`);
          this.hitlExplanationCache = { ...this.hitlExplanationCache, [eventId]: explanation };
        } catch (_err) {
          this.hitlExplanationCache = { ...this.hitlExplanationCache, [eventId]: this.fallbackHitlExplanation(ev) };
          this.hitlExplanationErrors = { ...this.hitlExplanationErrors, [eventId]: true };
        } finally {
          const next = { ...this.hitlExplanationLoading };
          delete next[eventId];
          this.hitlExplanationLoading = next;
          this.setHitlSelectedPipelineIndex(eventId);
        }
      },
      fallbackHitlExplanation(ev) {
        return {
          event_id: ev.event_id,
          agent_id: ev.agent_id,
          agent_model: ev.agent_model,
          tool_name: ev.tool_name || ev.action,
          final_verdict: ev.verdict,
          final_outcome: ev.outcome,
          final_reason: ev.reason || 'Nessun motivo registrato.',
          security_model: ev.security_model,
          tool_input: ev.tool_input || '',
          tool_output: ev.tool_output || '',
          input_troncato: ev.input_troncato || false,
          output_troncato: ev.output_troncato || false,
          pipeline: [{
            stage: ev.stage || 'Stadio sconosciuto',
            outcome: ev.outcome || 'HITL_REQUESTED',
            verdict: ev.verdict || 'HITL',
            confidence: ev.confidence,
            reason: ev.reason || 'Nessun motivo registrato.',
            timestamp: ev.timestamp,
            latency_ms: ev.latency_ms,
            terminal: true,
          }],
        };
      },
      hitlExplanation() {
        if (!this.hitlModal) return {};
        const ev = this.hitlModal.event;
        return this.hitlExplanationCache[ev.event_id] || this.fallbackHitlExplanation(ev);
      },
      hitlPipeline() {
        return this.meaningfulPipeline(this.hitlExplanation().pipeline || []);
      },
      hitlFlaggingStage() {
        const stages = this.hitlPipeline();
        if (!stages.length) return null;
        const modalStage = String(this.hitlModal?.event?.stage || '').toLowerCase();
        const idx = stages.findIndex(s => String(s?.outcome || '').toUpperCase() === 'HITL_REQUESTED' || String(s?.verdict || '').toUpperCase() === 'HITL');
        if (idx >= 0) return stages[idx];
        const byStage = stages.find(s => modalStage && String(s?.stage || '').toLowerCase() === modalStage);
        if (byStage) return byStage;
        const terminal = stages.find(s => s?.terminal);
        return terminal || stages[stages.length - 1];
      },
      setHitlSelectedPipelineIndex(eventId) {
        if (!this.hitlModal || this.hitlModal.event.event_id !== eventId) return;
        const stages = this.hitlPipeline();
        const flagged = this.hitlFlaggingStage();
        const idx = flagged ? stages.indexOf(flagged) : -1;
        this.hitlModal = { ...this.hitlModal, selectedPipelineIndex: idx >= 0 ? idx : Math.max(0, stages.length - 1) };
      },
      selectHitlPipelineStage(idx) {
        if (!this.hitlModal) return;
        this.hitlModal = { ...this.hitlModal, selectedPipelineIndex: idx };
      },
      hitlSelectedPipelineStage() {
        const stages = this.hitlPipeline();
        return stages[this.hitlModal?.selectedPipelineIndex || 0] || null;
      },
      stageStepTitle(stage, idx) {
        const display = this.stageDisplay(stage?.stage);
        return `Passo ${idx + 1}: ${display.label} (${display.technical})`;
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
          if (name.includes('l1.5') || name.includes('policy') || name.includes('regex')) return 'basato su regole';
          return '-';
        }
        const n = Number(v);
        return n <= 1 ? `${(n * 100).toFixed(0)}%` : `${n.toFixed(1)}%`;
      },
      async confirmHitlDecision(decision) {
        if (!this.hitlModal || !['approve', 'reject'].includes(decision)) return;
        await this.decideHitl(this.hitlModal.event, decision, { reviewer: (this.hitlModal.reviewer || 'dashboard-user').trim() || 'dashboard-user', note: (this.hitlModal.note || '').trim() });
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

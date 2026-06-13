window.ASF = (() => {
  const navItems = [
    { id: 'overview', label: 'Overview', href: '/overview', icon: '<path d="M1 1h6v6H1V1zm7 0h6v6H8V1zM1 8h6v6H1V8zm7 0h6v6H8V8z"/>' },
    { id: 'sessions', label: 'Audit Trail', href: '/sessions', icon: '<path d="M1 2h13v2H1V2zm0 4h13v2H1V6zm0 4h9v2H1v-2z"/>' },
    { id: 'compliance', label: 'EU AI Act', href: '/compliance', icon: '<path d="M7.5 1 1.5 4v4c0 3.3 2.4 6.1 6 7 3.6-.9 6-3.7 6-7V4L7.5 1zm-1 9L4 7.5l.9-.9L6.5 8l3.1-3 .9.9L6.5 10z"/>' },
    { id: 'hitl', label: 'Human Oversight', href: '/hitl', icon: '<path d="M7.5 1a3.5 3.5 0 100 7 3.5 3.5 0 000-7zM2 9.5a5.5 5.5 0 0111 0V11H2V9.5zM1 12h13v2H1v-2z"/>', badge: true },
  ];

  function shell(activeSection, title, content, modal = '') {
    const nav = navItems.map(item => `
      <a class="nav-item ${item.id === activeSection ? 'active' : ''}" href="${item.href}">
        <svg width="14" height="14" viewBox="0 0 15 15" fill="currentColor" style="flex-shrink:0;">${item.icon}</svg>
        ${item.label}
        ${item.badge ? '<span v-if="hitlEvents && hitlEvents.length > 0" class="nav-badge">{{ hitlEvents.length }}</span>' : ''}
      </a>`).join('');
    return `
      <div class="app-layout">
        <aside class="sidebar">
          <div class="sidebar-logo">
            <div class="sidebar-logo-text">
              <div class="sidebar-logo-title">Agent Security Framework</div>
              <div class="sidebar-logo-sub">Compliance &amp; Audit</div>
            </div>
          </div>
          <nav class="sidebar-nav">${nav}</nav>
          <div class="sidebar-footer">
            <div style="font-size:11px;color:var(--text-muted);">{{ footerText || 'ASF v2' }}</div>
          </div>
        </aside>
        <div class="content-wrapper">
          <header class="topbar">
            <div class="topbar-title">Agent Security Framework / ${title}</div>
            <div class="topbar-actions">
              <div class="env-selector" style="display:flex;align-items:center;gap:6px;">
                <span v-if="activeEnv === 'test'" @click="switchEnv('production')" style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border:1px solid rgba(210,153,34,.5);border-radius:5px;background:rgba(210,153,34,.12);font-size:11px;font-weight:700;color:var(--warning);cursor:pointer;letter-spacing:.04em;" title="Test database active — click to switch to production">
                  <span class="pulse-dot"></span>TEST
                </span>
                <span v-else @click="switchEnv('test')" style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border:1px solid var(--border);border-radius:5px;background:transparent;font-size:11px;color:var(--text-muted);cursor:pointer;" title="Click to switch to test database">
                  PROD
                </span>
              </div>
              <div class="provenance">
                <span v-if="dbSource" class="provenance-item" title="Audit data source">
                  <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor"><ellipse cx="8" cy="3.5" rx="6" ry="2.2"/><path d="M2 6.2c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2V9c0 1.2-2.7 2.2-6 2.2S2 10.2 2 9V6.2z"/><path d="M2 9.8c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2v2.4c0 1.2-2.7 2.2-6 2.2s-6-1-6-2.2V9.8z"/></svg>
                  {{ dbSource }}
                </span>
                <span v-if="dataAsOf" class="provenance-item" :class="freshness(dataAsOf).stale ? 'provenance-stale' : 'provenance-fresh'" title="Most recent audit event">
                  <span class="status-dot" :class="freshness(dataAsOf).stale ? 'status-dot-warning' : 'status-dot-success'"></span>
                  data {{ freshness(dataAsOf).label }}
                </span>
                <span class="provenance-item" title="Client view refreshed">refresh {{ lastRefresh || 'pending' }}<span v-if="refreshLabel"> · {{ refreshLabel }}</span></span>
              </div>
            </div>
          </header>
          <main style="padding:24px;flex:1;">
            <div style="max-width:1280px;margin:0 auto;display:flex;flex-direction:column;gap:24px;">
              ${content}
            </div>
          </main>
        </div>
        ${modal}
      </div>`;
  }

  async function loadSection(name) {
    const r = await fetch(`/assets/sections/${name}.html`);
    if (!r.ok) throw new Error(`Failed to load section: ${name}`);
    return r.text();
  }

  async function fetchJson(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(`${path} ${r.status}`);
    return r.json();
  }
  function parseUtcDate(v) {
    if (!v) return null;
    const normalized = String(v).trim().replace(' ', 'T');
    const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(normalized);
    const date = new Date(hasZone ? normalized : `${normalized}Z`);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  function decisionTone(ev) {
    const v = String(ev?.verdict || '').toUpperCase();
    const outcome = String(ev?.outcome || '').toUpperCase();
    // ERROR is kept distinct from DENY: a pipeline failure is not a security block,
    // and conflating the two inflates the block numbers and hides outages.
    if (['ERROR', 'FAILED', 'EXCEPTION', 'TIMEOUT'].includes(v) ||
        ['ERROR', 'FAILED', 'EXCEPTION', 'TIMEOUT', 'INTERCEPTOR_ERROR'].includes(outcome)) return 'error';
    if (['DENY', 'BLOCKED', 'KILL_SWITCH', 'L1.5_BLOCK', 'ONNX_BLOCK', 'OUTPUT_BLOCK'].includes(v) ||
        ['BLOCKED', 'KILL_SWITCH', 'L1.5_BLOCK', 'ONNX_BLOCK', 'OUTPUT_BLOCK', 'HITL_REJECTED'].includes(outcome)) return 'deny';
    if (['ALLOW', 'ALLOWED', 'HEURISTIC_CLEAR'].includes(v) ||
        ['ALLOWED', 'HEURISTIC_CLEAR', 'HITL_APPROVED'].includes(outcome)) return 'allow';
    if (['HITL', 'HITL_REQUESTED'].includes(v) || outcome === 'HITL_REQUESTED') return 'hitl';
    return 'neutral';
  }

  function stageDisplay(stage) {
    const technical = stage || 'Unknown stage';
    const s = String(technical).toLowerCase();
    let label = 'ASF check';
    let shortTech = technical;
    let isFallback = true;
    if (s.includes('output guard')) {
      label = 'Output check';
      shortTech = 'Output guard';
      isFallback = false;
    } else if (s.includes('onnx')) {
      label = 'ONNX scan';
      shortTech = 'Stage 3 ONNX Prompt Guard';
      isFallback = false;
    } else if (s.includes('stage 3') || s.includes('llm')) {
      label = 'LLM review';
      shortTech = 'Stage 3 LLM';
      isFallback = false;
    } else if ((s.includes('stage 2.5') || s.includes('2.5')) && s.includes('prompt guard')) {
      label = 'Injection guard';
      shortTech = 'Stage 2.5b Prompt Guard';
      isFallback = false;
    } else if (s.includes('stage 2.5') || s.includes('deberta')) {
      label = 'Content analysis';
      shortTech = 'Stage 2.5 DeBERTa';
      isFallback = false;
    } else if (s.includes('stage 2') || s.includes('tf-idf') || s.includes('random forest')) {
      label = 'Statistical check';
      shortTech = 'Stage 2 TF-IDF + Random Forest';
      isFallback = false;
    } else if (s.includes('stage 1') || s.includes('regex')) {
      label = 'Known patterns';
      shortTech = 'Stage 1 regex';
      isFallback = false;
    } else if (s.includes('l1.5') || s.includes('fast-path') || s.includes('heuristic')) {
      label = 'Quick screening';
      shortTech = 'L1.5 fast-path';
      isFallback = false;
    }
    return { label, technical, shortTech, isFallback };
  }

  function meaningfulPipeline(pipeline) {
    const full = Array.isArray(pipeline) ? pipeline : [];
    const meaningful = full.filter(s => {
      const outcome = String(s?.outcome || '').toUpperCase();
      return outcome !== 'INTERCEPTOR_START' && !outcome.endsWith('_START');
    });
    const result = meaningful.length ? meaningful : full;
    const withoutFallback = result.filter(s => !stageDisplay(s?.stage).isFallback);
    return withoutFallback.length ? withoutFallback : result;
  }

  const methods = {
    fetchJson,
    async loadProvenance() {
      try {
        const [p, e] = await Promise.all([
          fetchJson('/api/metrics/provenance'),
          fetchJson('/api/env'),
        ]);
        this.dbSource = p.db_source || '';
        this.dataAsOf = p.data_as_of || null;
        this.activeEnv = e.active_env || 'production';
      } catch (_e) { /* keep previous provenance on transient error */ }
    },
    async switchEnv(name) {
      try {
        await fetch('/api/env/switch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ env: name }),
        });
        await this.loadProvenance();
      } catch (_e) {}
    },
    fmtNum(v) { return (v ?? 0).toLocaleString(); },
    percent(v) { return `${Math.round((v || 0) * 100)}%`; },
    fmtLatency(ms) { return (!ms || ms === 0) ? '< 1' : String(Math.round(ms)); },
    parseUtcDate,
    stageDisplay,
    meaningfulPipeline,
    stageLabel(stage) { return stageDisplay(stage).label; },
    stageTechnical(stage) { return stageDisplay(stage).technical; },
    stageShortTech(stage) { return stageDisplay(stage).shortTech; },
    formatDuration(ms) {
      ms = Number(ms) || 0;
      if (ms < 1000) return `${Math.round(ms)}ms`;
      if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
      if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
      return `${(ms / 3600000).toFixed(1)}h`;
    },
    ratioWidth(blocked, allowed, isBlocked) {
      const t = (blocked || 0) + (allowed || 0);
      if (!t) return isBlocked ? '0%' : '100%';
      return `${((isBlocked ? blocked : allowed) / t) * 100}%`;
    },
    truncate(v, n) { v = v || ''; return v.length > n ? v.slice(0, n) + '…' : v; },
    formatTime(v) { const d = parseUtcDate(v); return d ? d.toLocaleString() : ''; },
    timeOnly(v) { const d = parseUtcDate(v); return d ? d.toLocaleTimeString() : ''; },
    decisionTone,
    verdictBadgeClass(ev) {
      const tone = decisionTone(ev);
      if (tone === 'deny') return 'badge badge-deny';
      if (tone === 'allow') return 'badge badge-allow';
      if (tone === 'hitl') return 'badge badge-hitl';
      if (tone === 'error') return 'badge badge-error';
      return 'badge badge-neutral';
    },
    verdictShortLabel(ev) {
      const outcome = String(ev?.outcome || '').toUpperCase();
      const verdict = String(ev?.verdict || '').toUpperCase();
      if (outcome === 'KILL_SWITCH') return 'Kill switch';
      if (outcome === 'HITL_REQUESTED') return 'Pending review';
      if (outcome === 'HITL_APPROVED') return 'Approved';
      if (outcome === 'HITL_REJECTED') return 'Rejected';
      if (outcome === 'BLOCKED' || verdict === 'DENY') return 'Blocked';
      if (outcome === 'ALLOWED' || verdict === 'ALLOW') return 'Allowed';
      if (outcome === 'HEURISTIC_CLEAR') return 'Cleared';
      if (outcome === 'L1.5_BLOCK' || outcome === 'ONNX_BLOCK' || outcome === 'OUTPUT_BLOCK') return 'Blocked';
      if (verdict === 'HITL' || outcome.startsWith('HITL')) return 'Pending review';
      return ev?.verdict || ev?.outcome || 'Unknown';
    },
    evRowClass(ev) {
      const tone = decisionTone(ev);
      if (tone === 'deny') return 'ev-deny';
      if (tone === 'allow') return 'ev-allow';
      if (tone === 'hitl') return 'ev-hitl';
      if (tone === 'error') return 'ev-error';
      return '';
    },
    async copyId(text) {
      const value = String(text == null ? '' : text);
      try {
        await navigator.clipboard.writeText(value);
      } catch (_e) {
        const ta = document.createElement('textarea');
        ta.value = value; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch (_err) {}
        document.body.removeChild(ta);
      }
    },
    freshness(ts) {
      const d = parseUtcDate(ts);
      if (!d) return { label: 'unknown', stale: true };
      const mins = Math.floor((Date.now() - d.getTime()) / 60000);
      const stale = mins > 60;
      let label;
      if (mins < 1) label = 'just now';
      else if (mins < 60) label = `${mins}m ago`;
      else if (mins < 1440) label = `${Math.floor(mins / 60)}h ago`;
      else label = `${Math.floor(mins / 1440)}d ago`;
      return { label, stale };
    },
    stageBadgeClass(stage) {
      if (!stage) return 'badge badge-stage badge-stage-unk';
      const s = stage.toLowerCase();
      if (s.includes('l1.5')) return 'badge badge-stage badge-stage-l15';
      if (s.includes('stage 2.5') || s.includes('deberta')) return 'badge badge-stage badge-stage-25';
      if (s.includes('stage 2')) return 'badge badge-stage badge-stage-2';
      if (s.includes('stage 1')) return 'badge badge-stage badge-stage-1';
      if (s.includes('stage 3') || s.includes('llm') || s.includes('onnx')) return 'badge badge-stage badge-stage-3';
      if (s.includes('output guard')) return 'badge badge-stage badge-stage-output';
      if (s.includes('prompt guard')) return 'badge badge-stage badge-stage-pg';
      return 'badge badge-stage badge-stage-unk';
    },
    agentDotColor(agentId) {
      const id = (agentId || '').toLowerCase();
      if (id.includes('asf-eval')) return '#4f8ef7';
      if (id.includes('smolagents')) return '#1fb855';
      if (id.includes('autogen')) return '#e8a020';
      if (id.includes('crewai')) return '#a855f7';
      if (id.includes('openhands')) return '#f472b6';
      if (id.includes('pyrit')) return '#f05252';
      return '#64748b';
    },
  };
  return { shell, loadSection, fetchJson, methods, stageDisplay, meaningfulPipeline };
})();

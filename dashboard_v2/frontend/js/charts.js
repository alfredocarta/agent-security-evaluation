// ASF dashboard charting primitives.
// Inline-SVG / CSS only, no chart library, to match the existing hand-rolled visuals
// (.kpi-ratio, pipeline-node) and keep the page dependency-free. Exposed as Vue 3
// component options under window.ASFCharts; a page registers them with ASFCharts.install(app).
window.ASFCharts = (() => {
  const REASON_COLORS = {
    governance: 'var(--text-muted)',
    rbac: 'var(--warning)',
    content_detection: 'var(--danger)',
    output_guard: 'var(--error)',
    other: 'var(--unknown)',
  };
  const REASON_LABELS = {
    governance: 'Governance (agent gate)',
    rbac: 'RBAC / permissions',
    content_detection: 'Content detection',
    output_guard: 'Output guard',
    other: 'Other',
  };

  // Distinct color per pipeline stage, for the "blocks by detection stage" donut.
  function stageColor(stage) {
    const s = (stage || '').toLowerCase();
    if (s.includes('output guard')) return 'var(--partial)';
    if (s.includes('stage 2.5') || s.includes('deberta')) return 'var(--block)';
    if (s.includes('stage 3') || s.includes('onnx') || s.includes('prompt guard') || s.includes('llm')) return 'var(--verified)';
    if (s.includes('stage 2')) return 'var(--error)';
    if (s.includes('stage 1') || s.includes('regex')) return 'var(--hitl)';
    if (s.includes('l1.5') || s.includes('fast-path')) return 'var(--accent)';
    return 'var(--unknown)';
  }

  const Sparkline = {
    props: {
      points: { type: Array, default: () => [] },
      width: { type: Number, default: 120 },
      height: { type: Number, default: 26 },
      color: { type: String, default: 'var(--accent)' },
    },
    computed: {
      path() {
        const pts = this.points || [];
        if (pts.length < 2) return '';
        const max = Math.max(...pts), min = Math.min(...pts);
        const span = (max - min) || 1;
        const step = this.width / (pts.length - 1);
        return pts.map((v, i) =>
          `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(this.height - ((v - min) / span) * this.height).toFixed(1)}`
        ).join(' ');
      },
    },
    template: `<svg :width="width" :height="height" class="spark" preserveAspectRatio="none">
      <path v-if="path" :d="path" fill="none" :stroke="color" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
    </svg>`,
  };

  const ChartFunnel = {
    props: { items: { type: Array, default: () => [] } },
    computed: {
      maxTotal() { return Math.max(1, ...this.items.map(i => i.total || 0)); },
    },
    methods: {
      barWidth(t) { return `${(100 * (t || 0) / this.maxTotal).toFixed(1)}%`; },
      seg(v, total) { return total ? `${(100 * (v || 0) / total).toFixed(1)}%` : '0%'; },
    },
    template: `<div class="cf">
      <div v-if="!items.length" class="chart-empty">No pipeline decisions in window</div>
      <div v-for="it in items" :key="it.stage" class="cf-row">
        <div class="cf-label" :title="it.stage">{{ it.stage }}</div>
        <div class="cf-track">
          <div class="cf-bar" :style="{ width: barWidth(it.total) }"
               :title="it.stage + ': ' + it.total + ' (blocked ' + it.blocked + ' / allowed ' + it.allowed + ' / hitl ' + it.hitl + ')'">
            <div class="cf-seg cf-block" :style="{ width: seg(it.blocked, it.total) }"></div>
            <div class="cf-seg cf-hitl" :style="{ width: seg(it.hitl, it.total) }"></div>
            <div class="cf-seg cf-allow" :style="{ width: seg(it.allowed, it.total) }"></div>
          </div>
        </div>
        <div class="cf-count">{{ it.total }}</div>
      </div>
    </div>`,
  };

  const ChartDonut = {
    props: {
      segments: { type: Array, default: () => [] },
      size: { type: Number, default: 116 },
    },
    computed: {
      total() { return this.segments.reduce((a, s) => a + (s.value || 0), 0); },
      r() { return this.size / 2 - 9; },
      circ() { return 2 * Math.PI * this.r; },
      arcs() {
        let off = 0; const total = this.total || 1;
        return this.segments.map(s => {
          const frac = (s.value || 0) / total;
          const arc = { color: s.color, dash: `${frac * this.circ} ${this.circ}`, offset: -off * this.circ };
          off += frac; return arc;
        });
      },
    },
    template: `<div class="cd">
      <div v-if="!total" class="chart-empty">No blocks in window</div>
      <template v-else>
        <svg :width="size" :height="size" class="cd-svg">
          <g :transform="'translate(' + size / 2 + ',' + size / 2 + ') rotate(-90)'">
            <circle :r="r" fill="none" stroke="var(--border)" stroke-width="10"></circle>
            <circle v-for="(a, i) in arcs" :key="i" :r="r" fill="none" :stroke="a.color"
                    stroke-width="10" :stroke-dasharray="a.dash" :stroke-dashoffset="a.offset"></circle>
          </g>
          <text :x="size / 2" :y="size / 2" text-anchor="middle" dominant-baseline="central" class="cd-total">{{ total }}</text>
        </svg>
        <div class="cd-legend">
          <div v-for="s in segments" :key="s.label" class="cd-leg">
            <span class="cd-dot" :style="{ background: s.color }"></span>{{ s.label }} <b>{{ s.value }}</b>
          </div>
        </div>
      </template>
    </div>`,
  };

  const ChartHistogram = {
    props: {
      buckets: { type: Array, default: () => [] },
      stats: { type: Object, default: () => ({}) },
    },
    computed: { maxC() { return Math.max(1, ...this.buckets.map(b => b.count || 0)); } },
    methods: { h(c) { return `${(100 * (c || 0) / this.maxC).toFixed(1)}%`; } },
    template: `<div class="chh">
      <div v-if="!stats || !stats.sample_count" class="chart-empty">No latency samples in window</div>
      <template v-else>
        <div class="chh-bars">
          <div v-for="b in buckets" :key="b.label" class="chh-col">
            <div class="chh-wrap"><div class="chh-bar" :style="{ height: h(b.count) }" :title="b.label + ': ' + b.count"></div></div>
            <div class="chh-x">{{ b.label }}</div>
          </div>
        </div>
        <div class="chh-stats">p50 {{ Math.round(stats.p50_ms) }}ms · p95 {{ Math.round(stats.p95_ms) }}ms · p99 {{ Math.round(stats.p99_ms) }}ms · n={{ stats.sample_count }}</div>
      </template>
    </div>`,
  };

  const ChartHBar = {
    props: { items: { type: Array, default: () => [] } },
    computed: { maxTotal() { return Math.max(1, ...this.items.map(i => i.total || 0)); } },
    methods: {
      w(t) { return `${(100 * (t || 0) / this.maxTotal).toFixed(1)}%`; },
      pct(v) { return `${Math.round((v || 0) * 100)}%`; },
    },
    template: `<div class="hb">
      <div v-if="!items.length" class="chart-empty">No agent activity in window</div>
      <div v-for="it in items" :key="it.agent_id" class="hb-row">
        <div class="hb-label" :title="it.agent_id">{{ it.agent_id }}</div>
        <div class="hb-track"><div class="hb-bar" :style="{ width: w(it.total) }"></div></div>
        <div class="hb-meta">{{ it.total }} · <span :style="{ color: it.block_rate > 0.5 ? 'var(--danger)' : 'var(--text-muted)' }">{{ pct(it.block_rate) }} blk</span></div>
      </div>
    </div>`,
  };

  const ChartTimeline = {
    props: { points: { type: Array, default: () => [] } },
    computed: { maxC() { return Math.max(1, ...this.points.map(p => (p.blocked || 0) + (p.allowed || 0) + (p.hitl || 0))); } },
    methods: {
      seg(v) { return `${(100 * (v || 0) / this.maxC).toFixed(1)}%`; },
      tip(p) { return `${p.bucket}  blocked ${p.blocked} / allowed ${p.allowed} / hitl ${p.hitl}`; },
    },
    template: `<div class="tl">
      <div v-if="!points.length" class="chart-empty">No activity in window</div>
      <div v-else class="tl-bars">
        <div v-for="p in points" :key="p.bucket" class="tl-col" :title="tip(p)">
          <div class="tl-stack">
            <div class="tl-seg tl-block" :style="{ height: seg(p.blocked) }"></div>
            <div class="tl-seg tl-hitl" :style="{ height: seg(p.hitl) }"></div>
            <div class="tl-seg tl-allow" :style="{ height: seg(p.allowed) }"></div>
          </div>
        </div>
      </div>
    </div>`,
  };

  const components = {
    'chart-sparkline': Sparkline,
    'chart-funnel': ChartFunnel,
    'chart-donut': ChartDonut,
    'chart-histogram': ChartHistogram,
    'chart-hbar': ChartHBar,
    'chart-timeline': ChartTimeline,
  };

  return {
    components,
    REASON_COLORS,
    REASON_LABELS,
    stageColor,
    install(app) {
      Object.entries(components).forEach(([name, def]) => app.component(name, def));
    },
  };
})();

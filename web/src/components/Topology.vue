<script setup>
// Topology of the overlay: nodes, links (dialer → listener) and attached
// clients, drawn as SVG with a small deterministic force layout.
import { computed } from 'vue'
import { t } from '../lib/i18n.js'

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  links: { type: Array, default: () => [] },
  clients: { type: Array, default: () => [] },
})

function role(n) {
  const caps = n.capabilities || []
  if (caps.includes('exit')) return 'exit'
  if (caps.includes('relay')) return 'relay'
  return 'node'
}

// Links per pair: tunxd uses the best enabled one, the rest are standby.
function linkStates(links) {
  const best = new Map()
  const k = (l) => [l.dialer, l.listener].sort().join('\u0000')
  const better = (a, b) =>
    (a.priority || 0) - (b.priority || 0) || (a.cost || 10) - (b.cost || 10) || a.name.localeCompare(b.name)
  for (const l of links) {
    if (l.disabled) continue
    const cur = best.get(k(l))
    if (!cur || better(l, cur) < 0) best.set(k(l), l)
  }
  return (l) => (l.disabled ? 'disabled' : best.get(k(l)) === l ? 'active' : 'standby')
}

const layout = computed(() => {
  const nodes = props.nodes
  const n = nodes.length
  if (!n) return null
  const idx = new Map(nodes.map((x, i) => [x.name, i]))
  const edges = props.links.filter((l) => idx.has(l.dialer) && idx.has(l.listener))
  // Initial positions on a circle, ordered by degree so hubs end up central.
  const deg = new Array(n).fill(0)
  edges.forEach((l) => {
    deg[idx.get(l.dialer)]++
    deg[idx.get(l.listener)]++
  })
  const pos = nodes.map((_, i) => {
    const a = (2 * Math.PI * i) / n + 0.3
    const r = deg[i] > 1 && n > 2 ? 40 : 160
    return { x: Math.cos(a) * r, y: Math.sin(a) * r }
  })
  const K = 150
  let temp = 60
  for (let it = 0; it < 300; it++) {
    const disp = pos.map(() => ({ x: 0, y: 0 }))
    for (let i = 0; i < n; i++)
      for (let j = i + 1; j < n; j++) {
        let dx = pos[i].x - pos[j].x
        let dy = pos[i].y - pos[j].y
        let d = Math.hypot(dx, dy)
        if (d < 0.01) {
          dx = 0.1 * (i - j)
          dy = 0.1
          d = Math.hypot(dx, dy)
        }
        const f = (K * K) / d
        disp[i].x += (dx / d) * f
        disp[i].y += (dy / d) * f
        disp[j].x -= (dx / d) * f
        disp[j].y -= (dy / d) * f
      }
    for (const l of edges) {
      const a = idx.get(l.dialer)
      const b = idx.get(l.listener)
      if (a === b) continue
      const dx = pos[a].x - pos[b].x
      const dy = pos[a].y - pos[b].y
      const d = Math.max(Math.hypot(dx, dy), 0.01)
      const f = (d * d) / K
      disp[a].x -= (dx / d) * f
      disp[a].y -= (dy / d) * f
      disp[b].x += (dx / d) * f
      disp[b].y += (dy / d) * f
    }
    // weak gravity keeps disconnected nodes in view
    for (let i = 0; i < n; i++) {
      disp[i].x -= pos[i].x * 0.05
      disp[i].y -= pos[i].y * 0.05
      const d = Math.max(Math.hypot(disp[i].x, disp[i].y), 0.01)
      pos[i].x += (disp[i].x / d) * Math.min(d, temp)
      pos[i].y += (disp[i].y / d) * Math.min(d, temp)
    }
    temp = Math.max(temp * 0.985, 1)
  }
  // Wider than tall reads better on desktop; keep the aspect if it is already wide.
  const cx = pos.reduce((s, p) => s + p.x, 0) / n
  const cy = pos.reduce((s, p) => s + p.y, 0) / n

  const state = linkStates(edges)
  const pairCount = new Map()
  const drawn = edges.map((l) => {
    const a = pos[idx.get(l.dialer)]
    const b = pos[idx.get(l.listener)]
    const key = [l.dialer, l.listener].sort().join('\u0000')
    const nth = pairCount.get(key) || 0
    pairCount.set(key, nth + 1)
    const mx = (a.x + b.x) / 2
    const my = (a.y + b.y) / 2
    const dx = b.x - a.x
    const dy = b.y - a.y
    const len = Math.max(Math.hypot(dx, dy), 1)
    const bend = nth === 0 ? 0 : (nth % 2 ? 1 : -1) * Math.ceil(nth / 2) * 28
    const qx = mx + (-dy / len) * bend
    const qy = my + (dx / len) * bend
    // point and tangent at t = 0.5 of the quadratic curve
    const px = 0.25 * a.x + 0.5 * qx + 0.25 * b.x
    const py = 0.25 * a.y + 0.5 * qy + 0.25 * b.y
    const ang = (Math.atan2(b.y - a.y, b.x - a.x) * 180) / Math.PI
    return { l, d: `M${a.x} ${a.y} Q${qx} ${qy} ${b.x} ${b.y}`, px, py, ang, state: state(l) }
  })

  // Clients sit around their node, away from the centre.
  const byNode = new Map()
  props.clients.forEach((c) => {
    if (!idx.has(c.node)) return
    if (!byNode.has(c.node)) byNode.set(c.node, [])
    byNode.get(c.node).push(c)
  })
  const clients = []
  for (const [name, list] of byNode) {
    const p = pos[idx.get(name)]
    let base = Math.atan2(p.y - cy, p.x - cx)
    if (Math.hypot(p.x - cx, p.y - cy) < 1) base = -Math.PI / 2
    list.forEach((c, i) => {
      const a = base + (i - (list.length - 1) / 2) * 0.55
      clients.push({ c, x: p.x + Math.cos(a) * 82, y: p.y + Math.sin(a) * 82, from: p })
    })
  }

  const all = [...pos, ...clients]
  const minX = Math.min(...all.map((p) => p.x)) - 70
  const maxX = Math.max(...all.map((p) => p.x)) + 70
  const minY = Math.min(...all.map((p) => p.y)) - 40
  const maxY = Math.max(...all.map((p) => p.y)) + 56
  return {
    view: `${minX} ${minY} ${Math.max(maxX - minX, 300)} ${Math.max(maxY - minY, 200)}`,
    nodes: nodes.map((x, i) => ({ n: x, ...pos[i], role: role(x), enrolled: !!x.public_key })),
    edges: drawn,
    clients,
  }
})

const legend = computed(() => [
  { cls: 'relay', label: t('ov.legendRelay') },
  { cls: 'exit', label: t('ov.legendExit') },
  { cls: 'node', label: t('ov.legendNode') },
  { cls: 'pending', label: t('ov.legendPending') },
  { cls: 'client', label: t('ov.legendClient') },
])
</script>

<template>
  <div class="topo">
    <a-empty v-if="!layout" :description="t('ov.empty')" />
    <template v-else>
      <svg :viewBox="layout.view" class="topo-svg" role="img" :aria-label="t('ov.topology')" data-test="topology">
        <g class="edges">
          <g v-for="e in layout.edges" :key="e.l.name" :class="['edge', e.state]">
            <title>{{ e.l.name }}: {{ e.l.dialer }} → {{ e.l.listener }}/{{ e.l.endpoint }} · cost {{ e.l.cost || 10 }} · {{ e.state }}</title>
            <path :d="e.d" class="edge-line" />
            <path :d="e.d" class="edge-hit" />
            <polygon
              points="-6,-4.5 6,0 -6,4.5"
              class="edge-arrow"
              :transform="`translate(${e.px} ${e.py}) rotate(${e.ang})`"
            />
            <text :x="e.px" :y="e.py - 9" class="edge-label">{{ e.l.name }}</text>
          </g>
        </g>
        <g class="clients">
          <g v-for="c in layout.clients" :key="'c-' + c.c.name" :class="['client', { off: c.c.disabled }]">
            <title>{{ c.c.name }} → {{ c.c.node }}/{{ c.c.endpoint }}</title>
            <line :x1="c.from.x" :y1="c.from.y" :x2="c.x" :y2="c.y" class="client-line" />
            <rect :x="c.x - 7" :y="c.y - 10" width="14" height="20" rx="3" class="client-dot" />
            <text :x="c.x" :y="c.y + 24" class="client-label">{{ c.c.name }}</text>
          </g>
        </g>
        <g class="nodes">
          <g
            v-for="v in layout.nodes"
            :key="v.n.name"
            :class="['vertex', v.role, { pending: !v.enrolled }]"
            :transform="`translate(${v.x} ${v.y})`"
          >
            <title>{{ v.n.name }} · {{ (v.n.capabilities || []).join(', ') || '—' }}{{ v.enrolled ? '' : ' · ' + t('ov.legendPending') }}</title>
            <circle r="19" class="halo" />
            <circle r="15" class="dot" />
            <text y="4.5" class="glyph">{{ v.role === 'exit' ? 'E' : v.role === 'relay' ? 'R' : '' }}</text>
            <text y="34" class="v-name">{{ v.n.name }}</text>
            <text y="48" class="v-addr">{{ (v.n.addresses || [])[0] || '' }}</text>
          </g>
        </g>
      </svg>
      <div class="legend">
        <span v-for="l in legend" :key="l.cls" class="lg"><i :class="['sw', l.cls]" />{{ l.label }}</span>
        <span class="lg"><i class="sw line" />{{ t('nav.links') }}</span>
        <span class="lg"><i class="sw line dashed" />{{ t('ov.legendDisabled') }}</span>
      </div>
    </template>
  </div>
</template>

<style scoped>
.topo-svg {
  width: 100%;
  height: auto;
  max-height: 460px;
  display: block;
  font-family: inherit;
}
.edge-line {
  fill: none;
  stroke: var(--topo-edge);
  stroke-width: 2.2;
}
.edge-hit {
  fill: none;
  stroke: transparent;
  stroke-width: 12;
}
.edge.active .edge-line {
  stroke: var(--primary);
}
.edge.standby .edge-line {
  stroke-dasharray: 2 5;
}
.edge.disabled .edge-line {
  stroke-dasharray: 7 6;
  opacity: 0.6;
}
.edge-arrow {
  fill: var(--topo-edge);
}
.edge.active .edge-arrow {
  fill: var(--primary);
}
.edge-label {
  font-size: 11px;
  fill: var(--topo-label);
  text-anchor: middle;
  paint-order: stroke;
  stroke: var(--card);
  stroke-width: 4px;
}
.halo {
  fill: none;
  stroke: currentColor;
  stroke-width: 2;
  opacity: 0.25;
}
.vertex {
  color: var(--topo-node);
}
.vertex.relay {
  color: var(--topo-relay);
}
.vertex.exit {
  color: var(--topo-exit);
}
.vertex.pending {
  color: var(--topo-pending);
}
.vertex.pending .halo {
  stroke-dasharray: 3 3;
  opacity: 0.8;
}
.dot {
  fill: currentColor;
}
.glyph {
  fill: #fff;
  font-size: 13px;
  font-weight: 700;
  text-anchor: middle;
}
.v-name {
  fill: var(--text);
  font-size: 13px;
  font-weight: 600;
  text-anchor: middle;
  paint-order: stroke;
  stroke: var(--card);
  stroke-width: 4px;
}
.v-addr {
  fill: var(--muted);
  font-size: 11px;
  text-anchor: middle;
  paint-order: stroke;
  stroke: var(--card);
  stroke-width: 4px;
}
.client-line {
  stroke: var(--topo-client);
  stroke-width: 1.5;
  stroke-dasharray: 3 3;
  opacity: 0.7;
}
.client-dot {
  fill: var(--card);
  stroke: var(--topo-client);
  stroke-width: 2;
}
.client.off {
  opacity: 0.45;
}
.client-label {
  font-size: 11px;
  fill: var(--topo-label);
  text-anchor: middle;
}
.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 16px;
  font-size: 12px;
  color: var(--muted);
  margin-top: 8px;
}
.lg {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.sw {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}
.sw.relay {
  background: var(--topo-relay);
}
.sw.exit {
  background: var(--topo-exit);
}
.sw.node {
  background: var(--topo-node);
}
.sw.pending {
  background: var(--topo-pending);
}
.sw.client {
  border-radius: 2px;
  border: 2px solid var(--topo-client);
  width: 7px;
  height: 10px;
}
.sw.line {
  width: 18px;
  height: 0;
  border-radius: 0;
  border-top: 2px solid var(--primary);
}
.sw.line.dashed {
  border-top: 2px dashed var(--topo-edge);
}
</style>

// Shared panel state: preferences, the signed-in admin and a cache of the
// whole network used by forms (selector options, endpoint lists).
import { reactive, computed } from 'vue'
import { api, KINDS } from './api.js'

function load(key, fallback) {
  try {
    return localStorage.getItem(key) || fallback
  } catch {
    return fallback
  }
}
function save(key, value) {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* private mode: preferences are not remembered */
  }
}

const mq = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null
const browserLang = (navigator.languages?.[0] || navigator.language || 'en').toLowerCase().startsWith('zh') ? 'zh' : 'en'

export const state = reactive({
  theme: load('tunx.theme', mq?.matches ? 'dark' : 'light'),
  lang: load('tunx.lang', browserLang),
  width: window.innerWidth,
  me: null,
  network: null,
  spec: Object.fromEntries(KINDS.map((k) => [k, []])),
  loaded: false,
})

window.addEventListener('resize', () => {
  state.width = window.innerWidth
})

export const isMobile = computed(() => state.width < 768)

export function setTheme(t) {
  state.theme = t
  save('tunx.theme', t)
}
export function setLang(l) {
  state.lang = l
  save('tunx.lang', l)
}

// refresh reloads the network and the given kinds (default all).
export async function refresh(kinds = KINDS) {
  const [network, ...lists] = await Promise.all([api.network(), ...kinds.map((k) => api.list(k))])
  state.network = network
  kinds.forEach((k, i) => {
    state.spec[k] = lists[i]
  })
  state.loaded = true
}

// Option lists for selector inputs.
export const selectorOptions = computed(() => {
  const s = state.spec
  const tags = new Set()
  s.nodes.forEach((n) => (n.tags || []).forEach((t) => tags.add(t)))
  s.clients.forEach((c) => (c.tags || []).forEach((t) => tags.add(t)))
  return {
    nodes: s.nodes.map((n) => `node:${n.name}`),
    clients: s.clients.map((c) => `client:${c.name}`),
    tags: [...tags].sort().map((t) => `tag:${t}`),
    groups: s.groups.map((g) => `group:${g.name}`),
  }
})

export function findNode(name) {
  return state.spec.nodes.find((n) => n.name === name)
}

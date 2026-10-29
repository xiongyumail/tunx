// Ordered policies (access, egress): evaluated by priority, then name.
// Moving a rule swaps priorities with its neighbour, or renumbers the list
// by tens when priorities collide, and saves the rules that changed.
import { computed, ref } from 'vue'
import { api } from './api.js'
import { state, refresh } from './store.js'
import { clean, clone } from './render.js'

export function byPriority(a, b) {
  return (a.priority || 0) - (b.priority || 0) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
}

export function useOrdered(kind) {
  const list = computed(() => [...state.spec[kind]].sort(byPriority))
  const moving = ref(false)

  async function move(index, dir) {
    const cur = list.value
    const j = index + dir
    if (j < 0 || j >= cur.length || moving.value) return
    const next = [...cur]
    ;[next[index], next[j]] = [next[j], next[index]]
    const prios = cur.map((x) => x.priority || 0)
    const distinct = new Set(prios).size === prios.length
    const want = next.map((x, i) => (distinct ? prios[i] : (i + 1) * 10))
    moving.value = true
    try {
      for (let i = 0; i < next.length; i++) {
        if ((next[i].priority || 0) === want[i]) continue
        const body = clean({ ...clone(next[i]), priority: want[i] })
        body.priority = want[i]
        await api.put(kind, next[i].name, body)
      }
    } finally {
      moving.value = false
      await refresh([kind])
    }
  }
  return { list, move, moving }
}

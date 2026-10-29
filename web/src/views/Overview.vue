<script setup>
import { computed, ref, watch } from 'vue'
import { ApiOutlined, BranchesOutlined, ClusterOutlined, MobileOutlined, SafetyCertificateOutlined, SyncOutlined, SwapOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh } from '../lib/store.js'
import Topology from '../components/Topology.vue'

const s = computed(() => state.spec)
const stats = computed(() => [
  {
    key: 'nodes',
    icon: ClusterOutlined,
    color: '#2f7de1',
    label: t('ov.nodes'),
    value: s.value.nodes.length,
    sub: t('ov.enrolled', { n: s.value.nodes.filter((n) => n.public_key).length }),
  },
  {
    key: 'links',
    icon: ApiOutlined,
    color: '#008771',
    label: t('ov.links'),
    value: s.value.links.length,
    sub: t('ov.linksEnabled', { n: s.value.links.filter((l) => !l.disabled).length }),
  },
  {
    key: 'clients',
    icon: MobileOutlined,
    color: '#8b5cf6',
    label: t('ov.clients'),
    value: s.value.clients.length,
    sub: t('ov.clientsEnabled', { n: s.value.clients.filter((c) => !c.disabled).length }),
  },
  {
    key: 'routes',
    icon: BranchesOutlined,
    color: '#e08a1e',
    label: t('ov.routes'),
    value: s.value.routes.length,
    sub: s.value.routes.map((r) => r.prefix).slice(0, 2).join(', ') || '—',
  },
  {
    key: 'policies',
    icon: SafetyCertificateOutlined,
    color: '#d4380d',
    label: t('ov.policies'),
    value: s.value.access.length + s.value.egress.length,
    sub: t('ov.policiesDetail', { a: s.value.access.length, e: s.value.egress.length }),
  },
  { key: 'traffic', icon: SwapOutlined, color: '#64748b', label: t('ov.traffic'), value: '—', sub: t('ov.notReported') },
])

// Render warnings come from each node's rendered bundle.
const warnings = ref([])
const loadingWarn = ref(false)
async function loadWarnings() {
  loadingWarn.value = true
  try {
    const out = []
    const bundles = await Promise.allSettled(state.spec.nodes.map((n) => api.nodeConfig(n.name)))
    bundles.forEach((b, i) => {
      const node = state.spec.nodes[i].name
      if (b.status === 'fulfilled') (b.value.warnings || []).forEach((w) => out.push({ node, w }))
      else out.push({ node, w: b.reason.message, error: true })
    })
    warnings.value = out
  } finally {
    loadingWarn.value = false
  }
}
watch(() => state.spec.nodes, loadWarnings, { immediate: true })

const busy = ref(false)
async function reload() {
  busy.value = true
  try {
    await refresh()
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="page">
    <a-row :gutter="[16, 16]">
      <a-col v-for="st in stats" :key="st.key" :xs="12" :sm="12" :md="8" :xl="4">
        <a-card class="stat-card" :bordered="false" :data-test="'stat-' + st.key">
          <div class="stat-icon" :style="{ background: st.color + '1f', color: st.color }"><component :is="st.icon" /></div>
          <div class="stat-body">
            <div class="stat-label">{{ st.label }}</div>
            <div class="stat-value">{{ st.value }}</div>
            <div class="stat-sub">{{ st.sub }}</div>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <a-alert type="info" show-icon :message="t('ov.statusGap')" />

    <a-row :gutter="[16, 16]">
      <a-col :xs="24" :xl="16">
        <a-card :title="t('ov.topology')" :bordered="false">
          <template #extra>
            <a-button size="small" :loading="busy" @click="reload"><SyncOutlined /></a-button>
          </template>
          <Topology :nodes="s.nodes" :links="s.links" :clients="s.clients" />
        </a-card>
      </a-col>
      <a-col :xs="24" :xl="8">
        <div class="side-col">
          <a-card :title="t('ov.network')" :bordered="false">
            <a-descriptions :column="1" size="small">
              <a-descriptions-item :label="t('set.networkName')">
                <span class="mono">{{ state.network?.name || '—' }}</span>
              </a-descriptions-item>
              <a-descriptions-item :label="t('ov.prefixes')">
                <div class="tags">
                  <a-tag v-for="p in state.network?.prefixes || []" :key="p" class="mono">{{ p }}</a-tag>
                  <span v-if="!state.network?.prefixes?.length" class="muted">—</span>
                </div>
              </a-descriptions-item>
              <a-descriptions-item :label="t('ov.dnsSuffix')">{{ state.network?.dns_suffix || '—' }}</a-descriptions-item>
              <a-descriptions-item :label="t('ov.hopLimit')">{{ state.network?.hop_limit || t('c.default', { v: '' }).trim() }}</a-descriptions-item>
            </a-descriptions>
          </a-card>
          <a-card :title="t('ov.warnings')" :bordered="false" data-test="warnings">
            <a-spin :spinning="loadingWarn">
              <p v-if="!warnings.length" class="hint">{{ t('ov.noWarnings') }}</p>
              <ul v-else class="warn-list">
                <li v-for="(w, i) in warnings" :key="i">
                  <a-tag :color="w.error ? 'red' : 'orange'">{{ w.node }}</a-tag>
                  <span class="break">{{ w.w }}</span>
                </li>
              </ul>
            </a-spin>
          </a-card>
        </div>
      </a-col>
    </a-row>
  </div>
</template>

<style scoped>
.side-col {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.warn-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
  font-size: 13px;
}
</style>

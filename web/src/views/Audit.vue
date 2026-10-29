<script setup>
import { computed, h, ref, watch } from 'vue'
import { Tag } from 'ant-design-vue'
import { SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { isMobile } from '../lib/store.js'
import { fmtTime, ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'

const entries = ref([])
const loading = ref(false)
const limit = ref(200)
const filter = ref('')

async function load() {
  loading.value = true
  try {
    entries.value = await api.audit(limit.value)
  } catch (e) {
    ui.message.error(e.message)
  } finally {
    loading.value = false
  }
}
watch(limit, load, { immediate: true })

const shown = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return entries.value
  return entries.value.filter((e) => `${e.actor} ${e.action} ${e.kind} ${e.name}`.toLowerCase().includes(q))
})

const colors = { create: 'green', update: 'blue', delete: 'red', login: 'cyan', 'login-failed': 'volcano', enroll: 'purple' }
const hasDiff = (d) => d && !(typeof d === 'object' && !Array.isArray(d) && !Object.keys(d).length)

const columns = computed(() => [
  { title: t('audit.time'), key: 'at', customRender: ({ record }) => h('span', { class: 'mono' }, fmtTime(record.at)) },
  { title: t('audit.actor'), key: 'actor', customRender: ({ record }) => h('span', { class: 'mono' }, record.actor) },
  { title: t('audit.action'), key: 'action', customRender: ({ record }) => h(Tag, { color: colors[record.action] }, () => record.action) },
  {
    title: t('audit.object'),
    key: 'object',
    customRender: ({ record }) => h('span', { class: 'mono break' }, record.kind ? `${record.kind}/${record.name}` : record.name),
  },
])
const expand = (r) =>
  hasDiff(r.diff) ? h('pre', { class: 'block', style: 'max-height:320px' }, JSON.stringify(r.diff, null, 2)) : h('span', { class: 'muted' }, '—')
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('nav.audit') }}</h2>
      <div class="tools">
        <a-input-search v-model:value="filter" :placeholder="t('audit.filter')" allow-clear :style="{ width: isMobile ? '100%' : '260px' }" />
        <a-select
          v-model:value="limit"
          :options="[100, 200, 500, 1000].map((v) => ({ value: v, label: `${v}` }))"
          style="width: 96px"
          :aria-label="t('audit.limit')"
        />
        <a-button :loading="loading" @click="load"><SyncOutlined /></a-button>
      </div>
    </div>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="shown" row-key="id" :loading="loading" :page-size="isMobile ? 20 : 50" :expand="expand" />
    </a-card>
  </div>
</template>

<style scoped>
.bare-card {
  background: transparent;
  box-shadow: none;
}
</style>

<script setup>
import { computed, reactive, ref } from 'vue'
import { DeleteOutlined, EditOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh, isMobile } from '../lib/store.js'
import { actions, clean, clone, strong, tags } from '../lib/render.js'
import { ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'
import SelectorInput from '../components/SelectorInput.vue'

const loading = ref(false)
async function reload() {
  loading.value = true
  try {
    await refresh()
  } catch (e) {
    ui.message.error(e.message)
  } finally {
    loading.value = false
  }
}
async function remove(g) {
  try {
    await api.remove('groups', g.name)
    ui.message.success(t('c.deleted'))
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}

const open = ref(false)
const editing = ref(null)
const busy = ref(false)
const f = reactive({ name: '', members: [] })
function openForm(g) {
  editing.value = g
  const x = clone(g) || {}
  f.name = x.name || ''
  f.members = x.members || []
  open.value = true
}

// Members matched now, for a quick check of what a group selects.
function resolve(g) {
  const out = new Set()
  const glob = (p) => new RegExp('^' + p.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$')
  const ids = [
    ...state.spec.nodes.map((n) => ({ kind: 'node', name: n.name, tags: n.tags || [] })),
    ...state.spec.clients.map((c) => ({ kind: 'client', name: c.name, tags: c.tags || [] })),
  ]
  for (const m of g.members || []) {
    for (const id of ids) {
      if (m === `${id.kind}:${id.name}`) out.add(id.name)
      else if (m.startsWith('tag:') && id.tags.includes(m.slice(4))) out.add(id.name)
      else if (!m.includes(':') && glob(m).test(id.name)) out.add(id.name)
    }
  }
  return [...out].sort()
}

async function save() {
  const b = clean({ name: f.name.trim(), members: f.members })
  b.members = f.members
  if (!b.name) return ui.message.error(`${t('c.name')}: ${t('c.required')}`)
  busy.value = true
  try {
    if (editing.value) await api.put('groups', editing.value.name, b)
    else await api.create('groups', b)
    ui.message.success(t('c.saved'))
    open.value = false
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  } finally {
    busy.value = false
  }
}

const columns = computed(() => [
  { title: t('c.name'), dataIndex: 'name', key: 'name', customRender: ({ record }) => strong(record.name) },
  { title: t('grp.members'), key: 'members', customRender: ({ record }) => tags(record.members, 'blue') },
  { title: t('grp.resolved'), key: 'resolved', customRender: ({ record }) => tags(resolve(record), 'default', t('c.none')) },
  {
    title: t('c.actions'),
    key: 'actions',
    customRender: ({ record }) =>
      actions([
        { label: t('c.edit'), icon: EditOutlined, onClick: () => openForm(record), test: 'edit' },
        { label: t('c.delete'), icon: DeleteOutlined, danger: true, confirm: t('c.confirmDelete', { name: record.name }), onClick: () => remove(record) },
      ]),
  },
])
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('nav.groups') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <p class="hint">{{ t('grp.hint') }}</p>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="state.spec.groups" :loading="!state.loaded" />
    </a-card>

    <a-modal
      v-model:open="open"
      :title="editing ? `${t('c.edit')} · ${editing.name}` : `${t('c.add')} · ${t('nav.groups')}`"
      :width="isMobile ? '100%' : 560"
      :confirm-loading="busy"
      :ok-text="t('c.save')"
      :cancel-text="t('c.cancel')"
      :mask-closable="false"
      @ok="save"
    >
      <a-form layout="vertical">
        <a-form-item :label="t('c.name')" required><a-input v-model:value="f.name" :disabled="!!editing" placeholder="sites" data-test="f-name" /></a-form-item>
        <a-form-item :label="t('grp.members')" required><SelectorInput v-model:value="f.members" :groups="false" placeholder="tag:site" /></a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.bare-card {
  background: transparent;
  box-shadow: none;
}
</style>

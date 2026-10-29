<script setup>
import { computed, h, reactive, ref } from 'vue'
import { Button, Space, Tag, Tooltip } from 'ant-design-vue'
import { ArrowDownOutlined, ArrowUpOutlined, DeleteOutlined, EditOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { refresh, isMobile, state } from '../lib/store.js'
import { actions, clean, clone, strong, tags } from '../lib/render.js'
import { useOrdered } from '../lib/ordered.js'
import { ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'
import SelectorInput from '../components/SelectorInput.vue'

const { list, move, moving } = useOrdered('egress')

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
async function doMove(i, d) {
  try {
    await move(i, d)
    ui.message.success(t('acc.reordered'))
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}
async function remove(r) {
  try {
    await api.remove('egress', r.name)
    ui.message.success(t('c.deleted'))
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}

const open = ref(false)
const editing = ref(null)
const busy = ref(false)
const f = reactive({})
function openForm(r) {
  editing.value = r
  const x = clone(r) || {}
  const last = list.value.length ? list.value[list.value.length - 1].priority || 0 : 0
  Object.assign(f, {
    name: x.name || '',
    priority: x.priority ?? last + 10,
    sources: x.sources || [],
    exit: x.exit,
    rules: x.xray_rules?.length ? JSON.stringify(x.xray_rules, null, 2) : '',
  })
  open.value = true
}
const exitOptions = computed(() =>
  state.spec.nodes.filter((n) => (n.capabilities || []).includes('exit')).map((n) => ({ value: n.name, label: n.name })),
)

async function save() {
  let rules
  if (f.rules.trim()) {
    try {
      rules = JSON.parse(f.rules)
    } catch (e) {
      return ui.message.error(t('c.invalidJSON', { err: e.message }))
    }
  }
  const b = clean({ name: f.name.trim(), sources: f.sources, exit: f.exit, xray_rules: rules })
  b.priority = f.priority || 0
  if (!b.name) return ui.message.error(`${t('c.name')}: ${t('c.required')}`)
  busy.value = true
  try {
    if (editing.value) await api.put('egress', editing.value.name, b)
    else await api.create('egress', b)
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
  {
    title: t('c.name'),
    dataIndex: 'name',
    key: 'name',
    customRender: ({ record }) =>
      h('span', { style: 'display:inline-flex;gap:8px;align-items:center' }, [
        h(Tag, { bordered: false, class: 'mono' }, () => String(record.priority || 0)),
        strong(record.name),
      ]),
  },
  { title: t('c.sources'), key: 'src', customRender: ({ record }) => tags(record.sources, 'blue') },
  { title: t('eg.exit'), key: 'exit', customRender: ({ record }) => h(Tag, { color: 'orange' }, () => record.exit) },
  {
    title: t('eg.rules'),
    key: 'rules',
    customRender: ({ record }) => {
      const n = record.xray_rules?.length || 0
      if (!n) return h('span', { class: 'muted' }, '—')
      return h(Tooltip, { title: h('pre', { class: 'mono', style: 'margin:0;white-space:pre-wrap' }, JSON.stringify(record.xray_rules, null, 2)) }, () =>
        h(Tag, null, () => `${n} × rule`),
      )
    },
  },
  {
    title: t('c.actions'),
    key: 'actions',
    customRender: ({ record, index }) =>
      h(Space, { size: 2 }, () => [
        h(Button, { type: 'text', size: 'small', disabled: index === 0 || moving.value, 'aria-label': t('c.moveUp'), 'data-test': 'up', onClick: () => doMove(index, -1) }, { icon: () => h(ArrowUpOutlined) }),
        h(Button, { type: 'text', size: 'small', disabled: index === list.value.length - 1 || moving.value, 'aria-label': t('c.moveDown'), 'data-test': 'down', onClick: () => doMove(index, 1) }, { icon: () => h(ArrowDownOutlined) }),
        actions([
          { label: t('c.edit'), icon: EditOutlined, onClick: () => openForm(record), test: 'edit' },
          { label: t('c.delete'), icon: DeleteOutlined, danger: true, confirm: t('c.confirmDelete', { name: record.name }), onClick: () => remove(record) },
        ]),
      ]),
  },
])
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('nav.egress') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <p class="hint">{{ t('eg.hint') }}</p>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="list" :loading="!state.loaded" />
    </a-card>

    <a-modal
      v-model:open="open"
      :title="editing ? `${t('c.edit')} · ${editing.name}` : `${t('c.add')} · ${t('nav.egress')}`"
      :width="isMobile ? '100%' : 640"
      :confirm-loading="busy"
      :ok-text="t('c.save')"
      :cancel-text="t('c.cancel')"
      :mask-closable="false"
      @ok="save"
    >
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('c.name')" required><a-input v-model:value="f.name" :disabled="!!editing" data-test="f-name" /></a-form-item>
          </a-col>
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('c.priority')"><a-input-number v-model:value="f.priority" style="width: 100%" /></a-form-item>
          </a-col>
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('eg.exit')" required><a-select v-model:value="f.exit" :options="exitOptions" /></a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="t('c.sources')" required><SelectorInput v-model:value="f.sources" placeholder="group:sites" /></a-form-item>
        <a-form-item :label="t('eg.xrayRules')">
          <a-textarea
            v-model:value="f.rules"
            :auto-size="{ minRows: 4, maxRows: 14 }"
            class="yaml-editor"
            spellcheck="false"
            placeholder='[{"domain": ["domain:ads.example.org"], "outboundTag": "block"}]'
          />
        </a-form-item>
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

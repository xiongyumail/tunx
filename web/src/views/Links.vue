<script setup>
import { computed, h, reactive, ref, watch } from 'vue'
import { Switch, Tag } from 'ant-design-vue'
import { DeleteOutlined, EditOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh, isMobile, findNode } from '../lib/store.js'
import { actions, clean, clone, mono, stack, strong, transportColor } from '../lib/render.js'
import { ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'

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

function endpointOf(l) {
  return findNode(l.listener)?.endpoints?.find((e) => e.name === l.endpoint)
}

async function toggle(l, enabled) {
  const body = { ...clone(l), disabled: !enabled }
  try {
    await api.put('links', l.name, clean(body))
    await refresh(['links'])
  } catch (e) {
    ui.message.error(t('link.toggleFailed', { err: e.message }))
  }
}

async function remove(l) {
  try {
    await api.remove('links', l.name)
    ui.message.success(t('c.deleted'))
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}

// Form
const open = ref(false)
const editing = ref(null)
const busy = ref(false)
const f = reactive({})
function openForm(l) {
  editing.value = l
  const x = clone(l) || {}
  Object.assign(f, {
    name: x.name || '',
    dialer: x.dialer,
    listener: x.listener,
    endpoint: x.endpoint,
    cost: x.cost ?? null,
    priority: x.priority ?? null,
    interface: x.interface || '',
    mark: x.mark ?? null,
    dialer_proxy: x.dialer_proxy,
    disabled: !!x.disabled,
    uuid: x.uuid || '',
    short_id: x.short_id || '',
  })
  open.value = true
}
const nodeOptions = computed(() => state.spec.nodes.map((n) => ({ value: n.name, label: n.name })))
const listenerOptions = computed(() =>
  state.spec.nodes.filter((n) => n.endpoints?.length).map((n) => ({ value: n.name, label: n.name })),
)
const endpointOptions = computed(() =>
  (findNode(f.listener)?.endpoints || []).map((e) => ({ value: e.name, label: `${e.name} · ${stack(e)}` })),
)
const proxyOptions = computed(() => (findNode(f.dialer)?.proxies || []).map((p) => ({ value: p.name, label: p.name })))
const chosenEndpoint = computed(() => findNode(f.listener)?.endpoints?.find((e) => e.name === f.endpoint))
// Keep the endpoint and proxy consistent with the chosen nodes.
watch(
  () => f.listener,
  () => {
    const opts = endpointOptions.value
    if (!opts.some((o) => o.value === f.endpoint)) f.endpoint = opts.length === 1 ? opts[0].value : undefined
  },
)
watch(
  () => f.dialer,
  () => {
    if (f.dialer_proxy && !proxyOptions.value.some((o) => o.value === f.dialer_proxy)) f.dialer_proxy = undefined
  },
)

async function save() {
  const b = clean({ ...f, name: f.name.trim(), disabled: f.disabled || undefined })
  if (!b.name) return ui.message.error(`${t('c.name')}: ${t('c.required')}`)
  busy.value = true
  try {
    if (editing.value) await api.put('links', editing.value.name, b)
    else await api.create('links', b)
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
  {
    title: t('link.path'),
    key: 'path',
    customRender: ({ record }) =>
      h('span', { class: 'mono' }, `${record.dialer} → ${record.listener}/${record.endpoint}`),
  },
  {
    title: t('link.stack'),
    key: 'stack',
    customRender: ({ record }) => {
      const ep = endpointOf(record)
      return h(Tag, { color: transportColor[ep?.transport] }, () => stack(ep))
    },
  },
  { title: t('link.cost'), key: 'cost', customRender: ({ record }) => String(record.cost || 10) },
  { title: t('c.priority'), key: 'priority', customRender: ({ record }) => String(record.priority || 0) },
  {
    title: t('link.socket'),
    key: 'socket',
    customRender: ({ record }) => {
      const parts = []
      if (record.interface) parts.push(`dev ${record.interface}`)
      if (record.mark) parts.push(`mark ${record.mark}`)
      if (record.dialer_proxy) parts.push(`via ${record.dialer_proxy}`)
      return mono(parts.join(' · '))
    },
  },
  {
    title: t('c.enabled'),
    key: 'enabled',
    customRender: ({ record }) =>
      h(Switch, { size: 'small', checked: !record.disabled, 'data-test': 'toggle', onChange: (v) => toggle(record, v) }),
  },
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
      <h2>{{ t('nav.links') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="state.spec.links" :loading="!state.loaded" />
    </a-card>

    <a-modal
      v-model:open="open"
      :title="editing ? `${t('c.edit')} · ${editing.name}` : `${t('c.add')} · ${t('nav.links')}`"
      :width="isMobile ? '100%' : 680"
      :confirm-loading="busy"
      :ok-text="t('c.save')"
      :cancel-text="t('c.cancel')"
      :mask-closable="false"
      @ok="save"
    >
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('c.name')" required>
              <a-input v-model:value="f.name" :disabled="!!editing" placeholder="a-hub" data-test="f-name" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('c.enabled')"><a-switch :checked="!f.disabled" @change="(v) => (f.disabled = !v)" /></a-form-item>
          </a-col>
          <a-col :xs="24" :sm="8">
            <a-form-item :label="t('link.dialer')" required>
              <a-select v-model:value="f.dialer" :options="nodeOptions" show-search />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="8">
            <a-form-item :label="t('link.listener')" required>
              <a-select v-model:value="f.listener" :options="listenerOptions" show-search />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="8">
            <a-form-item :label="t('link.endpoint')" required>
              <a-select v-model:value="f.endpoint" :options="endpointOptions" />
            </a-form-item>
          </a-col>
        </a-row>
        <div class="stack-box">
          <span class="muted">{{ t('link.stack') }}</span>
          <a-tag :color="transportColor[chosenEndpoint?.transport]" data-test="stack">{{ chosenEndpoint ? stack(chosenEndpoint) : '—' }}</a-tag>
          <span v-if="chosenEndpoint" class="mono muted">{{ chosenEndpoint.address }}:{{ chosenEndpoint.port }}{{ chosenEndpoint.path || '' }}</span>
          <div class="hint">{{ t('link.stackHint') }}</div>
        </div>
        <a-row :gutter="12">
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('link.cost')"><a-input-number v-model:value="f.cost" :min="0" placeholder="10" style="width: 100%" /></a-form-item>
          </a-col>
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('c.priority')"><a-input-number v-model:value="f.priority" placeholder="0" style="width: 100%" /></a-form-item>
          </a-col>
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('link.interface')"><a-input v-model:value="f.interface" placeholder="eth1" /></a-form-item>
          </a-col>
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('link.mark')"><a-input-number v-model:value="f.mark" :min="0" :max="4294967295" style="width: 100%" /></a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('link.dialerProxy')">
              <a-select v-model:value="f.dialer_proxy" :options="proxyOptions" allow-clear :placeholder="t('c.none')" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-collapse ghost>
          <a-collapse-panel key="cred" :header="t('link.credentials')">
            <a-row :gutter="12">
              <a-col :xs="24" :sm="14">
                <a-form-item :label="t('link.uuid')"><a-input v-model:value="f.uuid" :placeholder="t('c.generated')" class="mono" /></a-form-item>
              </a-col>
              <a-col :xs="24" :sm="10">
                <a-form-item :label="t('link.shortId')"><a-input v-model:value="f.short_id" :placeholder="t('c.generated')" class="mono" /></a-form-item>
              </a-col>
            </a-row>
          </a-collapse-panel>
        </a-collapse>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.bare-card {
  background: transparent;
  box-shadow: none;
}
.stack-box {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 10px;
  align-items: center;
  padding: 10px 12px;
  border: 1px dashed var(--border);
  border-radius: 8px;
  margin-bottom: 16px;
}
.stack-box .hint {
  flex-basis: 100%;
  font-size: 12px;
}
</style>

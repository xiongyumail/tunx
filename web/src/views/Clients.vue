<script setup>
import { computed, h, reactive, ref, watch } from 'vue'
import { Switch, Tag } from 'ant-design-vue'
import { DeleteOutlined, DownloadOutlined, EditOutlined, PlusOutlined, QrcodeOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh, isMobile, findNode } from '../lib/store.js'
import { actions, clean, clone, stack, strong, tags, transportColor } from '../lib/render.js'
import { download, ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'
import CopyField from '../components/CopyField.vue'
import QrCode from '../components/QrCode.vue'

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
const endpointOf = (c) => findNode(c.node)?.endpoints?.find((e) => e.name === c.endpoint)

async function toggle(c, enabled) {
  try {
    await api.put('clients', c.name, clean({ ...clone(c), disabled: enabled ? undefined : true }))
    await refresh(['clients'])
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}
async function remove(c) {
  try {
    await api.remove('clients', c.name)
    ui.message.success(t('c.deleted'))
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}

// Share
const share = ref(null)
const shareTab = ref('link')
function b64(s) {
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  bytes.forEach((b) => (bin += String.fromCharCode(b)))
  return btoa(bin)
}
async function openShare(c) {
  try {
    const r = await api.share(c.name)
    share.value = { client: c, link: r.link, sub: b64(r.link + '\n') }
    shareTab.value = 'link'
  } catch (e) {
    ui.message.error(e.message)
  }
}

// Form
const open = ref(false)
const editing = ref(null)
const busy = ref(false)
const f = reactive({})
function openForm(c) {
  editing.value = c
  const x = clone(c) || {}
  Object.assign(f, {
    name: x.name || '',
    node: x.node,
    endpoint: x.endpoint,
    tags: x.tags || [],
    disabled: !!x.disabled,
    uuid: x.uuid || '',
    short_id: x.short_id || '',
    password: x.password || '',
  })
  open.value = true
}
const nodeOptions = computed(() =>
  state.spec.nodes.filter((n) => n.endpoints?.some((e) => e.clients)).map((n) => ({ value: n.name, label: n.name })),
)
const endpointOptions = computed(() =>
  (findNode(f.node)?.endpoints || []).filter((e) => e.clients).map((e) => ({ value: e.name, label: `${e.name} · ${stack(e)}` })),
)
watch(
  () => f.node,
  () => {
    const o = endpointOptions.value
    if (!o.some((x) => x.value === f.endpoint)) f.endpoint = o.length === 1 ? o[0].value : undefined
  },
)

async function save() {
  const b = clean({ ...f, name: f.name.trim(), disabled: f.disabled || undefined })
  if (!b.name) return ui.message.error(`${t('c.name')}: ${t('c.required')}`)
  busy.value = true
  try {
    if (editing.value) await api.put('clients', editing.value.name, b)
    else await api.create('clients', b)
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
  { title: t('cl.node'), key: 'node', customRender: ({ record }) => h('span', { class: 'mono' }, `${record.node}/${record.endpoint}`) },
  {
    title: t('link.stack'),
    key: 'stack',
    customRender: ({ record }) => {
      const ep = endpointOf(record)
      return h(Tag, { color: transportColor[ep?.transport] }, () => stack(ep))
    },
  },
  { title: t('c.tags'), key: 'tags', customRender: ({ record }) => tags(record.tags) },
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
        { label: t('cl.share'), icon: QrcodeOutlined, onClick: () => openShare(record), test: 'share' },
        { label: t('c.edit'), icon: EditOutlined, onClick: () => openForm(record), test: 'edit' },
        { label: t('c.delete'), icon: DeleteOutlined, danger: true, confirm: t('c.confirmDelete', { name: record.name }), onClick: () => remove(record) },
      ]),
  },
])
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('nav.clients') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="state.spec.clients" :loading="!state.loaded" />
    </a-card>

    <a-modal :open="!!share" :title="share ? t('cl.shareTitle', { name: share.client.name }) : ''" :footer="null" :width="isMobile ? '100%' : 520" @cancel="share = null">
      <template v-if="share">
        <a-alert v-if="share.client.disabled" type="warning" show-icon :message="t('cl.disabledShare')" style="margin-bottom: 12px" />
        <a-tabs v-model:activeKey="shareTab" centered size="small">
          <a-tab-pane key="link" :tab="t('cl.link')">
            <QrCode :value="share.link" />
            <CopyField :value="share.link" />
          </a-tab-pane>
          <a-tab-pane key="sub" :tab="t('cl.subscription')">
            <QrCode :value="share.sub" />
            <CopyField :value="share.sub" />
            <p class="hint" style="margin-bottom: 10px">{{ t('cl.subHint') }}</p>
            <a-button block @click="download(`${share.client.name}.txt`, share.sub)"><DownloadOutlined />{{ t('c.download') }}</a-button>
          </a-tab-pane>
        </a-tabs>
      </template>
    </a-modal>

    <a-modal
      v-model:open="open"
      :title="editing ? `${t('c.edit')} · ${editing.name}` : `${t('c.add')} · ${t('nav.clients')}`"
      :width="isMobile ? '100%' : 600"
      :confirm-loading="busy"
      :ok-text="t('c.save')"
      :cancel-text="t('c.cancel')"
      :mask-closable="false"
      @ok="save"
    >
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :xs="24" :sm="14">
            <a-form-item :label="t('c.name')" required><a-input v-model:value="f.name" :disabled="!!editing" placeholder="phone" data-test="f-name" /></a-form-item>
          </a-col>
          <a-col :xs="24" :sm="10">
            <a-form-item :label="t('c.enabled')"><a-switch :checked="!f.disabled" @change="(v) => (f.disabled = !v)" /></a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('cl.node')" required><a-select v-model:value="f.node" :options="nodeOptions" /></a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('cl.endpoint')" required :extra="f.node && !endpointOptions.length ? t('cl.noEndpoint') : ''">
              <a-select v-model:value="f.endpoint" :options="endpointOptions" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="t('c.tags')"><a-select v-model:value="f.tags" mode="tags" :open="false" :token-separators="[',', ' ']" /></a-form-item>
        <a-collapse ghost>
          <a-collapse-panel key="cred" :header="t('link.credentials')">
            <a-form-item :label="t('link.uuid')"><a-input v-model:value="f.uuid" :placeholder="t('c.generated')" class="mono" /></a-form-item>
            <a-row :gutter="12">
              <a-col :xs="24" :sm="12">
                <a-form-item :label="t('link.shortId')"><a-input v-model:value="f.short_id" :placeholder="t('c.generated')" class="mono" /></a-form-item>
              </a-col>
              <a-col :xs="24" :sm="12">
                <a-form-item :label="t('cl.password')"><a-input-password v-model:value="f.password" :placeholder="t('c.generated')" class="mono" /></a-form-item>
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
</style>

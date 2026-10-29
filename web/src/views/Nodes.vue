<script setup>
import { computed, h, ref } from 'vue'
import { Badge, Tag } from 'ant-design-vue'
import { DeleteOutlined, EditOutlined, FileSearchOutlined, KeyOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh, isMobile } from '../lib/store.js'
import { actions, stack, strong, tags, transportColor } from '../lib/render.js'
import { ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'
import CopyField from '../components/CopyField.vue'
import NodeForm from './NodeForm.vue'

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

const formOpen = ref(false)
const editing = ref(null)
function openForm(n) {
  editing.value = n
  formOpen.value = true
}

async function remove(n) {
  try {
    await api.remove('nodes', n.name)
    ui.message.success(t('c.deleted'))
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}

// Enrolment
const enroll = ref(null)
function askEnroll(n) {
  ui.modal.confirm({
    title: t('node.enrollTitle', { name: n.name }),
    content: t('node.enrollConfirm', { name: n.name }),
    okText: n.public_key ? t('node.reenroll') : t('node.enroll'),
    cancelText: t('c.cancel'),
    onOk: async () => {
      try {
        enroll.value = await api.enrollToken(n.name)
      } catch (e) {
        ui.message.error(e.message)
      }
    },
  })
}
const installCmd = computed(() => {
  if (!enroll.value) return ''
  const body = JSON.stringify({ token: enroll.value.token })
  return `(umask 077; curl -fsS -X POST ${location.origin}/api/enroll \\\n  -H 'Content-Type: application/json' \\\n  -d '${body}' -o enroll.json)`
})

// Rendered config
const cfg = ref(null)
const cfgNode = ref('')
const cfgTab = ref('tunxd')
async function showConfig(n) {
  cfgNode.value = n.name
  cfg.value = null
  cfgTab.value = 'tunxd'
  try {
    cfg.value = await api.nodeConfig(n.name)
  } catch (e) {
    cfgNode.value = ''
    ui.message.error(e.message)
  }
}

const columns = computed(() => [
  {
    title: t('c.name'),
    dataIndex: 'name',
    key: 'name',
    fixed: isMobile.value ? undefined : 'left',
    customRender: ({ record }) =>
      h('span', { style: 'display:inline-flex;gap:8px;align-items:center' }, [
        h(Badge, { status: record.public_key ? 'success' : 'default' }),
        strong(record.name),
      ]),
  },
  { title: t('node.addresses'), key: 'addresses', customRender: ({ record }) => tags(record.addresses) },
  { title: t('node.capabilities'), key: 'caps', customRender: ({ record }) => tags(record.capabilities, 'cyan') },
  { title: t('c.tags'), key: 'tags', customRender: ({ record }) => tags(record.tags) },
  {
    title: t('node.endpoints'),
    key: 'endpoints',
    customRender: ({ record }) =>
      record.endpoints?.length
        ? h(
            'div',
            { class: 'tags' },
            record.endpoints.map((e) =>
              h(Tag, { color: transportColor[e.transport], key: e.name }, () => `${e.name} · ${stack(e)} · :${e.port}`),
            ),
          )
        : h('span', { class: 'muted' }, '—'),
  },
  {
    title: t('node.state'),
    key: 'state',
    customRender: ({ record }) =>
      h(Tag, { color: record.public_key ? 'success' : 'default' }, () => (record.public_key ? t('node.enrolled') : t('node.pending'))),
  },
  {
    title: t('c.actions'),
    key: 'actions',
    customRender: ({ record }) =>
      actions([
        { label: t('c.edit'), icon: EditOutlined, onClick: () => openForm(record), test: 'edit' },
        { label: record.public_key ? t('node.reenroll') : t('node.enroll'), icon: KeyOutlined, onClick: () => askEnroll(record), test: 'enroll' },
        { label: t('node.viewConfig'), icon: FileSearchOutlined, onClick: () => showConfig(record), test: 'config' },
        { label: t('c.delete'), icon: DeleteOutlined, danger: true, confirm: t('c.confirmDelete', { name: record.name }), onClick: () => remove(record) },
      ]),
  },
])
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('nav.nodes') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="state.spec.nodes" :loading="!state.loaded" />
    </a-card>

    <NodeForm v-model:open="formOpen" :node="editing" @saved="reload" />

    <a-modal
      :open="!!enroll"
      :title="enroll ? t('node.enrollTitle', { name: enroll.node }) : ''"
      :footer="null"
      :width="isMobile ? '100%' : 640"
      @cancel="enroll = null"
    >
      <template v-if="enroll">
        <a-alert type="warning" show-icon :message="t('node.onceWarn')" style="margin-bottom: 14px" />
        <CopyField :label="t('node.token')" :value="enroll.token" />
        <CopyField :label="t('node.installCmd')" :value="installCmd" />
        <p class="hint">{{ t('node.installHint') }}</p>
        <p class="hint">{{ t('node.expires') }}: {{ enroll.expires_at }}</p>
      </template>
    </a-modal>

    <a-drawer
      :open="!!cfgNode"
      :title="`${t('node.viewConfig')} · ${cfgNode}`"
      :width="isMobile ? '100%' : 720"
      @close="cfgNode = ''"
    >
      <a-spin :spinning="!cfg">
        <template v-if="cfg">
          <a-descriptions :column="1" size="small" style="margin-bottom: 12px">
            <a-descriptions-item :label="t('node.revision')"><span class="mono break">{{ cfg.revision }}</span></a-descriptions-item>
          </a-descriptions>
          <a-alert
            v-if="cfg.warnings?.length"
            type="warning"
            show-icon
            :message="t('node.warnings')"
            style="margin-bottom: 12px"
          >
            <template #description>
              <div v-for="(w, i) in cfg.warnings" :key="i" class="break">{{ w }}</div>
            </template>
          </a-alert>
          <a-tabs v-model:activeKey="cfgTab" size="small">
            <a-tab-pane key="tunxd" tab="tunxd" />
            <a-tab-pane key="xray" tab="Xray" />
            <a-tab-pane v-if="cfg.client_socks" key="client_socks" tab="client_socks" />
          </a-tabs>
          <CopyField :value="JSON.stringify(cfg[cfgTab], null, 2)" :rows="1" />
        </template>
      </a-spin>
    </a-drawer>
  </div>
</template>

<style scoped>
.bare-card {
  background: transparent;
  box-shadow: none;
}
</style>

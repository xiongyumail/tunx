<script setup>
import { computed, h, reactive, ref } from 'vue'
import { Button, Space, Tag } from 'ant-design-vue'
import { ArrowDownOutlined, ArrowUpOutlined, DeleteOutlined, EditOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { refresh, isMobile, state } from '../lib/store.js'
import { actions, clean, clone, strong, tags } from '../lib/render.js'
import { useOrdered } from '../lib/ordered.js'
import { ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'
import SelectorInput from '../components/SelectorInput.vue'

const { list, move, moving } = useOrdered('access')

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
    await api.remove('access', r.name)
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
    action: x.action || 'allow',
    description: x.description || '',
    sources: x.sources || [],
    source_prefixes: x.source_prefixes || [],
    destinations: x.destinations || [],
    proto: x.proto || [],
    ports: (x.ports || []).map(String),
  })
  open.value = true
}

async function save() {
  const b = clean({ ...f, name: f.name.trim() })
  b.priority = f.priority || 0
  if (!b.name) return ui.message.error(`${t('c.name')}: ${t('c.required')}`)
  busy.value = true
  try {
    if (editing.value) await api.put('access', editing.value.name, b)
    else await api.create('access', b)
    ui.message.success(t('c.saved'))
    open.value = false
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  } finally {
    busy.value = false
  }
}

const any = () => h('span', { class: 'muted' }, t('c.any'))
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
  {
    title: t('acc.action'),
    key: 'action',
    customRender: ({ record }) =>
      h(Tag, { color: record.action === 'allow' ? 'success' : 'error' }, () => t('acc.' + record.action)),
  },
  { title: t('c.sources'), key: 'src', customRender: ({ record }) => (record.sources?.length || record.source_prefixes?.length ? tags([...(record.sources || []), ...(record.source_prefixes || [])], 'blue') : any()) },
  { title: t('acc.destinations'), key: 'dst', customRender: ({ record }) => (record.destinations?.length ? tags(record.destinations, 'purple') : any()) },
  {
    title: t('acc.proto'),
    key: 'proto',
    customRender: ({ record }) => {
      const p = (record.proto || []).join('/') || t('c.any')
      return h('span', { class: 'mono' }, record.ports?.length ? `${p} : ${record.ports.join(',')}` : p)
    },
  },
  { title: t('acc.description'), key: 'desc', mobile: false, customRender: ({ record }) => record.description || '' },
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
      <h2>{{ t('nav.access') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <p class="hint">{{ t('acc.hint') }}</p>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="list" :loading="!state.loaded" />
    </a-card>

    <a-modal
      v-model:open="open"
      :title="editing ? `${t('c.edit')} · ${editing.name}` : `${t('c.add')} · ${t('nav.access')}`"
      :width="isMobile ? '100%' : 680"
      :confirm-loading="busy"
      :ok-text="t('c.save')"
      :cancel-text="t('c.cancel')"
      :mask-closable="false"
      @ok="save"
    >
      <a-form layout="vertical">
        <a-row :gutter="12">
          <a-col :xs="24" :sm="10">
            <a-form-item :label="t('c.name')" required>
              <a-input v-model:value="f.name" :disabled="!!editing" data-test="f-name" />
            </a-form-item>
          </a-col>
          <a-col :xs="12" :sm="6">
            <a-form-item :label="t('c.priority')"><a-input-number v-model:value="f.priority" style="width: 100%" /></a-form-item>
          </a-col>
          <a-col :xs="12" :sm="8">
            <a-form-item :label="t('acc.action')">
              <a-radio-group v-model:value="f.action" button-style="solid">
                <a-radio-button value="allow">{{ t('acc.allow') }}</a-radio-button>
                <a-radio-button value="deny">{{ t('acc.deny') }}</a-radio-button>
              </a-radio-group>
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="t('c.sources')"><SelectorInput v-model:value="f.sources" /></a-form-item>
        <a-form-item :label="t('acc.sourcePrefixes')">
          <a-select v-model:value="f.source_prefixes" mode="tags" :open="false" :token-separators="[',', ' ']" :placeholder="t('c.any')" />
        </a-form-item>
        <a-form-item :label="t('acc.destinations')">
          <SelectorInput v-model:value="f.destinations" :groups="false" :clients="false" placeholder="10.0.2.0/24, node:site-b, tag:core" />
        </a-form-item>
        <a-row :gutter="12">
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('acc.proto')">
              <a-checkbox-group v-model:value="f.proto" :options="['tcp', 'udp', 'icmp']" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('acc.ports')">
              <a-select v-model:value="f.ports" mode="tags" :open="false" :token-separators="[',', ' ']" placeholder="22, 8000-8999" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="t('acc.description')"><a-input v-model:value="f.description" /></a-form-item>
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

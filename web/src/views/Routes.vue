<script setup>
import { computed, h, reactive, ref } from 'vue'
import { Tag } from 'ant-design-vue'
import { DeleteOutlined, EditOutlined, PlusOutlined, SyncOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh, isMobile } from '../lib/store.js'
import { actions, clean, clone, strong, tags } from '../lib/render.js'
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

async function remove(r) {
  try {
    await api.remove('routes', r.name)
    ui.message.success(t('c.deleted'))
    reload()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  }
}

const open = ref(false)
const editing = ref(null)
const busy = ref(false)
const f = reactive({ name: '', prefix: '', advertisers: [] })
function openForm(r) {
  editing.value = r
  const x = clone(r) || {}
  f.name = x.name || ''
  f.prefix = x.prefix || ''
  f.advertisers = (x.advertisers || [{}]).map((a) => ({
    node: a.node,
    priority: a.priority ?? null,
    source: a.source || 'snat', // the hub default
    interface: a.interface || '',
    mark: a.mark ?? null,
  }))
  open.value = true
}
const advertiserOptions = computed(() =>
  state.spec.nodes
    .filter((n) => (n.capabilities || []).some((c) => c === 'advertise' || c === 'exit'))
    .map((n) => ({ value: n.name, label: n.name })),
)

async function save() {
  const b = clean({
    name: f.name.trim(),
    prefix: f.prefix.trim(),
    advertisers: f.advertisers.map((a) => ({ ...a })),
  })
  if (!b.name) return ui.message.error(`${t('c.name')}: ${t('c.required')}`)
  busy.value = true
  try {
    if (editing.value) await api.put('routes', editing.value.name, b)
    else await api.create('routes', b)
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
  { title: t('route.prefix'), key: 'prefix', customRender: ({ record }) => h('span', { class: 'mono' }, record.prefix) },
  {
    title: t('route.advertisers'),
    key: 'adv',
    customRender: ({ record }) =>
      h(
        'div',
        { class: 'tags' },
        (record.advertisers || []).map((a) =>
          h(Tag, { key: a.node, color: a.source === 'preserve' ? 'geekblue' : 'default' }, () =>
            [
              a.node,
              a.priority ? `p${a.priority}` : '',
              a.source === 'preserve' ? t('route.preserve') : t('route.snat'),
              a.interface ? `dev ${a.interface}` : '',
              a.mark ? `mark ${a.mark}` : '',
            ]
              .filter(Boolean)
              .join(' · '),
          ),
        ),
      ),
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

// Exits: nodes with the exit capability and the egress policies using them.
const exits = computed(() =>
  state.spec.nodes
    .filter((n) => (n.capabilities || []).includes('exit'))
    .map((n) => ({ ...n, policies: state.spec.egress.filter((e) => e.exit === n.name).map((e) => e.name) })),
)
const exitColumns = computed(() => [
  { title: t('route.node'), dataIndex: 'name', key: 'name', customRender: ({ record }) => strong(record.name) },
  { title: t('node.addresses'), key: 'addr', customRender: ({ record }) => tags(record.addresses) },
  { title: t('node.state'), key: 'state', customRender: ({ record }) => h(Tag, { color: record.public_key ? 'success' : 'default' }, () => (record.public_key ? t('node.enrolled') : t('node.pending'))) },
  { title: t('route.usedBy'), key: 'pol', customRender: ({ record }) => tags(record.policies, 'orange') },
])
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('route.routes') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="reload"><SyncOutlined /></a-button>
        <a-button type="primary" data-test="add" @click="openForm(null)"><PlusOutlined />{{ t('c.add') }}</a-button>
      </div>
    </div>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="columns" :data-source="state.spec.routes" :loading="!state.loaded" />
    </a-card>

    <div class="page-head">
      <h2>{{ t('route.exits') }}</h2>
    </div>
    <p class="hint">{{ t('route.exitsHint') }}</p>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '0' : '8px 8px 0' }" :class="{ 'bare-card': isMobile }">
      <DataList :columns="exitColumns" :data-source="exits" :loading="!state.loaded" />
    </a-card>

    <a-modal
      v-model:open="open"
      :title="editing ? `${t('c.edit')} · ${editing.name}` : `${t('c.add')} · ${t('route.routes')}`"
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
              <a-input v-model:value="f.name" :disabled="!!editing" placeholder="site-a-lan" data-test="f-name" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :sm="12">
            <a-form-item :label="t('route.prefix')" required>
              <a-input v-model:value="f.prefix" placeholder="10.0.1.0/24" class="mono" />
            </a-form-item>
          </a-col>
        </a-row>
        <div class="muted" style="margin-bottom: 8px">{{ t('route.advertisers') }}</div>
        <div v-for="(a, i) in f.advertisers" :key="i" class="sub-card">
          <a-row :gutter="12">
            <a-col :xs="24" :sm="9">
              <a-form-item :label="t('route.node')" required>
                <a-select v-model:value="a.node" :options="advertiserOptions" show-search />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="t('route.source')">
                <a-radio-group v-model:value="a.source" size="small" button-style="solid">
                  <a-radio-button value="snat">{{ t('route.snat') }}</a-radio-button>
                  <a-radio-button value="preserve">{{ t('route.preserve') }}</a-radio-button>
                </a-radio-group>
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="3" class="adv-del">
              <a-button type="text" danger :aria-label="t('c.delete')" :disabled="f.advertisers.length < 2" @click="f.advertisers.splice(i, 1)">
                <DeleteOutlined />
              </a-button>
            </a-col>
            <a-col :xs="8" :sm="6">
              <a-form-item :label="t('c.priority')"><a-input-number v-model:value="a.priority" style="width: 100%" /></a-form-item>
            </a-col>
            <a-col :xs="16" :sm="9">
              <a-form-item :label="t('link.interface')"><a-input v-model:value="a.interface" placeholder="eth0" /></a-form-item>
            </a-col>
            <a-col :xs="24" :sm="9">
              <a-form-item :label="t('link.mark')"><a-input-number v-model:value="a.mark" :min="0" style="width: 100%" /></a-form-item>
            </a-col>
          </a-row>
        </div>
        <a-button block type="dashed" @click="f.advertisers.push({ source: 'snat', priority: null, mark: null, interface: '' })">
          <PlusOutlined />{{ t('route.addAdvertiser') }}
        </a-button>
      </a-form>
    </a-modal>
  </div>
</template>

<style scoped>
.bare-card {
  background: transparent;
  box-shadow: none;
}
.adv-del {
  display: flex;
  justify-content: flex-end;
  align-items: flex-start;
  padding-top: 26px;
}
@media (max-width: 575px) {
  .adv-del {
    padding-top: 0;
    margin-top: -8px;
    margin-bottom: 4px;
  }
}
</style>

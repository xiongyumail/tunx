<script setup>
// Create or edit a node: basics, endpoints (transport stack), proxies and
// local listeners. Fields left empty are omitted so the hub applies its
// defaults and keeps generated secrets.
import { computed, reactive, ref, watch } from 'vue'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { isMobile } from '../lib/store.js'
import { clean, clone, stack } from '../lib/render.js'
import { ui } from '../lib/ui.js'

const props = defineProps({ open: Boolean, node: { type: Object, default: null } })
const emit = defineEmits(['update:open', 'saved'])

const CAPS = ['listen', 'relay', 'advertise', 'exit']
const TRANSPORTS = ['reality', 'tls', 'vless', 'socks']

const editing = computed(() => !!props.node)
const tab = ref('basic')
const busy = ref(false)
const f = reactive({})

function blankEndpoint() {
  return {
    name: '',
    transport: 'reality',
    address: '',
    port: 443,
    listen: '',
    network: 'raw',
    path: '',
    clients: false,
    reality: { target: '', server_names: [], fingerprint: '', private_key: '' },
    tls: { server_name: '', cert_file: '', key_file: '', fingerprint: '' },
  }
}

function reset() {
  const n = clone(props.node) || {}
  Object.assign(f, {
    name: n.name || '',
    public_key: n.public_key || '',
    addresses: n.addresses || [],
    tags: n.tags || [],
    capabilities: n.capabilities || [],
    tunName: n.tun?.name || '',
    tunMTU: n.tun?.mtu ?? null,
    link_listen: n.link_listen || '',
    client_listen: n.client_listen || '',
    dial_port_base: n.dial_port_base ?? null,
    status: n.status || '',
    log_level: n.log_level || undefined,
    endpoints: (n.endpoints || []).map((e) => {
      const b = blankEndpoint()
      return {
        ...b,
        ...e,
        network: e.network || 'raw',
        reality: { ...b.reality, ...(e.reality || {}) },
        tls: { ...b.tls, ...(e.tls || {}) },
      }
    }),
    proxies: (n.proxies || []).map((p) => ({ name: p.name, text: JSON.stringify(p.outbound ?? {}, null, 2) })),
  })
  tab.value = 'basic'
}
watch(
  () => props.open,
  (o) => o && reset(),
  { immediate: true },
)

function body() {
  const out = {
    name: f.name.trim(),
    public_key: f.public_key,
    addresses: f.addresses,
    tags: f.tags,
    capabilities: CAPS.filter((c) => f.capabilities.includes(c)),
    link_listen: f.link_listen,
    client_listen: f.client_listen,
    dial_port_base: f.dial_port_base,
    status: f.status,
    log_level: f.log_level,
  }
  if (f.tunName) out.tun = { name: f.tunName, mtu: f.tunMTU }
  out.endpoints = f.endpoints.map((e) => {
    const x = {
      name: e.name,
      transport: e.transport,
      address: e.address,
      port: e.port,
      listen: e.listen,
      network: e.transport === 'socks' || e.network === 'raw' ? '' : e.network,
      path: e.network === 'xhttp' && e.transport !== 'socks' ? e.path : '',
      clients: e.transport !== 'socks' && e.clients ? true : undefined,
    }
    if (e.transport === 'reality') x.reality = { ...e.reality }
    if (e.transport === 'tls') x.tls = { ...e.tls }
    return x
  })
  out.proxies = f.proxies.map((p) => {
    let outbound
    try {
      outbound = JSON.parse(p.text || '{}')
    } catch (err) {
      throw new Error(`${t('node.proxies')} ${p.name}: ${t('c.invalidJSON', { err: err.message })}`)
    }
    return { name: p.name, outbound }
  })
  return clean(out)
}

function addProxy() {
  f.proxies.push({ name: '', text: JSON.stringify({ protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: 1080 }] } }, null, 2) })
}

async function save() {
  let b
  try {
    b = body()
  } catch (e) {
    ui.message.error(e.message)
    return
  }
  if (!b.name) {
    ui.message.error(`${t('c.name')}: ${t('c.required')}`)
    return
  }
  busy.value = true
  try {
    if (editing.value) await api.put('nodes', props.node.name, b)
    else await api.create('nodes', b)
    ui.message.success(t('c.saved'))
    emit('saved')
    emit('update:open', false)
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  } finally {
    busy.value = false
  }
}

const capOptions = computed(() => CAPS.map((c) => ({ value: c, label: `${c} · ${t('node.cap.' + c)}` })))
</script>

<template>
  <a-modal
    :open="open"
    :title="editing ? `${t('c.edit')} · ${node.name}` : `${t('c.add')} · ${t('nav.nodes')}`"
    :width="isMobile ? '100%' : 760"
    :confirm-loading="busy"
    :ok-text="t('c.save')"
    :cancel-text="t('c.cancel')"
    :mask-closable="false"
    destroy-on-close
    @ok="save"
    @cancel="emit('update:open', false)"
  >
    <a-tabs v-model:activeKey="tab" size="small">
      <a-tab-pane key="basic" :tab="t('node.basic')">
        <a-form layout="vertical">
          <a-form-item :label="t('c.name')" required>
            <a-input v-model:value="f.name" :disabled="editing" placeholder="site-a" data-test="f-name" />
          </a-form-item>
          <a-form-item :label="t('node.addresses')">
            <a-select v-model:value="f.addresses" mode="tags" :token-separators="[',', ' ']" placeholder="10.200.0.5" :open="false" />
          </a-form-item>
          <a-form-item :label="t('c.tags')">
            <a-select v-model:value="f.tags" mode="tags" :token-separators="[',', ' ']" :open="false" />
          </a-form-item>
          <a-form-item :label="t('node.capabilities')">
            <a-checkbox-group v-model:value="f.capabilities" :options="capOptions" class="cap-group" />
          </a-form-item>
          <a-form-item v-if="f.public_key" :label="t('node.publicKey')">
            <span class="mono break">{{ f.public_key }}</span>
          </a-form-item>
        </a-form>
      </a-tab-pane>

      <a-tab-pane key="endpoints" :tab="`${t('node.endpoints')} (${f.endpoints.length})`">
        <p v-if="!f.endpoints.length" class="hint" style="margin-bottom: 12px">{{ t('node.noEndpoints') }}</p>
        <div v-for="(e, i) in f.endpoints" :key="i" class="sub-card">
          <div class="sub-card-head">
            <span>{{ e.name || '#' + (i + 1) }} <a-tag style="margin-left: 6px">{{ stack(e) }}</a-tag></span>
            <a-button type="text" danger size="small" :aria-label="t('c.delete')" @click="f.endpoints.splice(i, 1)">
              <DeleteOutlined />
            </a-button>
          </div>
          <a-form layout="vertical">
            <a-row :gutter="12">
              <a-col :xs="24" :sm="10">
                <a-form-item :label="t('c.name')" required><a-input v-model:value="e.name" placeholder="reality" /></a-form-item>
              </a-col>
              <a-col :xs="24" :sm="14">
                <a-form-item :label="t('ep.transport')">
                  <a-radio-group v-model:value="e.transport" button-style="solid" size="small">
                    <a-radio-button v-for="tr in TRANSPORTS" :key="tr" :value="tr">{{ tr.toUpperCase() }}</a-radio-button>
                  </a-radio-group>
                </a-form-item>
              </a-col>
              <a-col :xs="24" :sm="12">
                <a-form-item :label="t('ep.address')" :extra="e.transport === 'vless' ? t('ep.vlessHint') : t('ep.addressHint')">
                  <a-input v-model:value="e.address" placeholder="hub.example.com" />
                </a-form-item>
              </a-col>
              <a-col :xs="12" :sm="5">
                <a-form-item :label="t('ep.port')"><a-input-number v-model:value="e.port" :min="1" :max="65535" style="width: 100%" /></a-form-item>
              </a-col>
              <a-col :xs="12" :sm="7">
                <a-form-item :label="t('ep.listen')"><a-input v-model:value="e.listen" placeholder="0.0.0.0" /></a-form-item>
              </a-col>
              <template v-if="e.transport !== 'socks'">
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.network')">
                    <a-radio-group v-model:value="e.network" size="small" button-style="solid">
                      <a-radio-button value="raw">RAW</a-radio-button>
                      <a-radio-button value="xhttp">XHTTP</a-radio-button>
                    </a-radio-group>
                  </a-form-item>
                </a-col>
                <a-col v-if="e.network === 'xhttp'" :xs="24" :sm="12">
                  <a-form-item :label="t('ep.path')"><a-input v-model:value="e.path" placeholder="/tx" /></a-form-item>
                </a-col>
              </template>
              <template v-if="e.transport === 'reality'">
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.target')" required>
                    <a-input v-model:value="e.reality.target" placeholder="www.example.com:443" />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.serverNames')" required>
                    <a-select v-model:value="e.reality.server_names" mode="tags" :open="false" :token-separators="[',', ' ']" />
                  </a-form-item>
                </a-col>
                <a-col :xs="24" :sm="8">
                  <a-form-item :label="t('ep.fingerprint')"><a-input v-model:value="e.reality.fingerprint" placeholder="chrome" /></a-form-item>
                </a-col>
                <a-col :xs="24" :sm="16">
                  <a-form-item :label="t('ep.privateKey')">
                    <a-input-password v-model:value="e.reality.private_key" :placeholder="t('c.generated')" class="mono" />
                  </a-form-item>
                </a-col>
              </template>
              <template v-if="e.transport === 'tls'">
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.tlsServerName')" required><a-input v-model:value="e.tls.server_name" /></a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.fingerprint')"><a-input v-model:value="e.tls.fingerprint" placeholder="chrome" /></a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.certFile')" required><a-input v-model:value="e.tls.cert_file" placeholder="/etc/tunx/cert.pem" /></a-form-item>
                </a-col>
                <a-col :xs="24" :sm="12">
                  <a-form-item :label="t('ep.keyFile')" required><a-input v-model:value="e.tls.key_file" placeholder="/etc/tunx/key.pem" /></a-form-item>
                </a-col>
              </template>
              <a-col v-if="e.transport !== 'socks'" :span="24">
                <a-form-item>
                  <a-checkbox v-model:checked="e.clients">{{ t('ep.clients') }}</a-checkbox>
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </div>
        <a-button block type="dashed" @click="f.endpoints.push(blankEndpoint())"><PlusOutlined />{{ t('node.addEndpoint') }}</a-button>
      </a-tab-pane>

      <a-tab-pane key="proxies" :tab="`${t('node.proxies')} (${f.proxies.length})`">
        <p v-if="!f.proxies.length" class="hint" style="margin-bottom: 12px">{{ t('node.noProxies') }}</p>
        <div v-for="(p, i) in f.proxies" :key="i" class="sub-card">
          <div class="sub-card-head">
            <a-input v-model:value="p.name" :placeholder="t('c.name')" style="max-width: 240px" />
            <a-button type="text" danger size="small" :aria-label="t('c.delete')" @click="f.proxies.splice(i, 1)"><DeleteOutlined /></a-button>
          </div>
          <a-form layout="vertical">
            <a-form-item :label="t('node.outbound')">
              <a-textarea v-model:value="p.text" :auto-size="{ minRows: 4, maxRows: 14 }" class="yaml-editor" spellcheck="false" />
            </a-form-item>
          </a-form>
        </div>
        <a-button block type="dashed" @click="addProxy">
          <PlusOutlined />{{ t('node.addProxy') }}
        </a-button>
      </a-tab-pane>

      <a-tab-pane key="advanced" :tab="t('node.advanced')">
        <a-form layout="vertical">
          <a-row :gutter="12">
            <a-col :xs="12" :sm="12">
              <a-form-item :label="`${t('node.tun')} · ${t('node.tunName')}`"><a-input v-model:value="f.tunName" placeholder="tunx0" /></a-form-item>
            </a-col>
            <a-col :xs="12" :sm="12">
              <a-form-item :label="t('node.mtu')"><a-input-number v-model:value="f.tunMTU" :min="576" :max="65535" style="width: 100%" /></a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="t('node.linkListen')"><a-input v-model:value="f.link_listen" placeholder="127.0.0.1:7700" /></a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="t('node.clientListen')"><a-input v-model:value="f.client_listen" placeholder="127.0.0.1:7701" /></a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="t('node.dialPortBase')">
                <a-input-number v-model:value="f.dial_port_base" :min="1" :max="65535" placeholder="10800" style="width: 100%" />
              </a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="t('node.status')"><a-input v-model:value="f.status" placeholder="127.0.0.1:7790" /></a-form-item>
            </a-col>
            <a-col :xs="24" :sm="12">
              <a-form-item :label="t('node.logLevel')">
                <a-select v-model:value="f.log_level" allow-clear placeholder="info" :options="['debug', 'info', 'warn', 'error'].map((v) => ({ value: v, label: v }))" />
              </a-form-item>
            </a-col>
          </a-row>
        </a-form>
      </a-tab-pane>
    </a-tabs>
  </a-modal>
</template>

<style scoped>
.cap-group {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 6px;
}
</style>

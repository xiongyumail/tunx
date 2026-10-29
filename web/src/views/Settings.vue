<script setup>
import { computed, h, reactive, ref, watch } from 'vue'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, refresh, isMobile, setLang, setTheme } from '../lib/store.js'
import { actions, clean, strong } from '../lib/render.js'
import { fmtTime, ui } from '../lib/ui.js'
import DataList from '../components/DataList.vue'
import CopyField from '../components/CopyField.vue'

// Network
const net = reactive({ name: '', prefixes: [], dns_suffix: '', hop_limit: null })
watch(
  () => state.network,
  (n) => {
    if (!n) return
    net.name = n.name || ''
    net.prefixes = [...(n.prefixes || [])]
    net.dns_suffix = n.dns_suffix || ''
    net.hop_limit = n.hop_limit || null
  },
  { immediate: true },
)
const savingNet = ref(false)
async function saveNetwork() {
  savingNet.value = true
  try {
    await api.putNetwork(clean({ ...net }))
    ui.message.success(t('c.saved'))
    await refresh([])
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  } finally {
    savingNet.value = false
  }
}

// Tokens
const tokens = ref([])
const tokLoading = ref(false)
async function loadTokens() {
  tokLoading.value = true
  try {
    tokens.value = await api.tokens()
  } catch (e) {
    ui.message.error(e.message)
  } finally {
    tokLoading.value = false
  }
}
loadTokens()
const newOpen = ref(false)
const newName = ref('')
const created = ref(null)
const creating = ref(false)
async function createToken() {
  creating.value = true
  try {
    created.value = await api.createToken(newName.value.trim())
    newOpen.value = false
    newName.value = ''
    loadTokens()
  } catch (e) {
    ui.message.error({ content: e.message, duration: 6 })
  } finally {
    creating.value = false
  }
}
async function removeToken(tk) {
  try {
    await api.deleteToken(tk.name)
    ui.message.success(t('c.deleted'))
    loadTokens()
  } catch (e) {
    ui.message.error(e.message)
  }
}
const tokenColumns = computed(() => [
  { title: t('c.name'), dataIndex: 'name', key: 'name', customRender: ({ record }) => strong(record.name) },
  { title: t('set.createdBy'), key: 'by', customRender: ({ record }) => h('span', { class: 'mono' }, record.created_by) },
  { title: t('set.createdAt'), key: 'at', customRender: ({ record }) => h('span', { class: 'mono' }, fmtTime(record.created_at)) },
  {
    title: t('c.actions'),
    key: 'actions',
    customRender: ({ record }) =>
      actions([{ label: t('c.delete'), icon: DeleteOutlined, danger: true, confirm: t('c.confirmDelete', { name: record.name }), onClick: () => removeToken(record) }]),
  },
])
</script>

<template>
  <div class="page">
    <a-row :gutter="[16, 16]">
      <a-col :xs="24" :lg="12">
        <a-card :title="t('set.network')" :bordered="false">
          <a-form layout="vertical">
            <a-form-item :label="t('set.networkName')" :extra="t('set.networkHint')" required>
              <a-input v-model:value="net.name" class="mono" data-test="net-name" />
            </a-form-item>
            <a-form-item :label="t('ov.prefixes')">
              <a-select v-model:value="net.prefixes" mode="tags" :open="false" :token-separators="[',', ' ']" placeholder="10.200.0.0/24, fd74:756e:7800::/64" />
            </a-form-item>
            <a-row :gutter="12">
              <a-col :xs="24" :sm="14">
                <a-form-item :label="t('ov.dnsSuffix')"><a-input v-model:value="net.dns_suffix" placeholder="tunx.internal" /></a-form-item>
              </a-col>
              <a-col :xs="24" :sm="10">
                <a-form-item :label="t('ov.hopLimit')"><a-input-number v-model:value="net.hop_limit" :min="0" :max="255" style="width: 100%" /></a-form-item>
              </a-col>
            </a-row>
            <a-button type="primary" :loading="savingNet" data-test="save-network" @click="saveNetwork">{{ t('c.save') }}</a-button>
          </a-form>
        </a-card>
      </a-col>
      <a-col :xs="24" :lg="12">
        <div class="col">
          <a-card :title="t('set.account')" :bordered="false">
            <a-descriptions :column="1" size="small">
              <a-descriptions-item :label="t('set.signedIn')"><span class="mono">{{ state.me?.actor }}</span></a-descriptions-item>
              <a-descriptions-item :label="t('set.security')"><span class="muted">{{ t('set.securityGap') }}</span></a-descriptions-item>
            </a-descriptions>
          </a-card>
          <a-card :title="t('set.prefs')" :bordered="false">
            <a-form layout="vertical">
              <a-form-item :label="t('c.language')">
                <a-radio-group :value="state.lang" button-style="solid" @change="(e) => setLang(e.target.value)">
                  <a-radio-button value="zh">中文</a-radio-button>
                  <a-radio-button value="en">English</a-radio-button>
                </a-radio-group>
              </a-form-item>
              <a-form-item :label="t('c.theme')" style="margin-bottom: 0">
                <a-radio-group :value="state.theme" button-style="solid" @change="(e) => setTheme(e.target.value)">
                  <a-radio-button value="light">{{ t('c.light') }}</a-radio-button>
                  <a-radio-button value="dark">{{ t('c.dark') }}</a-radio-button>
                </a-radio-group>
              </a-form-item>
            </a-form>
          </a-card>
        </div>
      </a-col>
      <a-col :span="24">
        <a-card :title="t('set.tokens')" :bordered="false" :body-style="{ padding: isMobile ? '12px' : '8px 16px 16px' }">
          <template #extra>
            <a-button type="primary" size="small" data-test="new-token" @click="newOpen = true"><PlusOutlined />{{ t('set.newToken') }}</a-button>
          </template>
          <p class="hint" style="margin: 8px 0 12px">{{ t('set.tokensHint') }}</p>
          <DataList :columns="tokenColumns" :data-source="tokens" :loading="tokLoading" />
        </a-card>
      </a-col>
    </a-row>

    <a-modal
      v-model:open="newOpen"
      :title="t('set.newToken')"
      :ok-text="t('c.save')"
      :cancel-text="t('c.cancel')"
      :confirm-loading="creating"
      :width="isMobile ? '100%' : 420"
      @ok="createToken"
    >
      <a-form layout="vertical">
        <a-form-item :label="t('set.tokenName')" required><a-input v-model:value="newName" placeholder="ci" @press-enter="createToken" /></a-form-item>
      </a-form>
    </a-modal>
    <a-modal :open="!!created" :title="created?.name" :footer="null" :width="isMobile ? '100%' : 560" @cancel="created = null">
      <template v-if="created">
        <a-alert type="warning" show-icon :message="t('set.tokenOnce')" style="margin-bottom: 12px" />
        <CopyField :value="created.token" />
      </template>
    </a-modal>
  </div>
</template>

<style scoped>
.col {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
</style>

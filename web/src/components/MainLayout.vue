<script setup>
import { computed, h, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ApiOutlined, AuditOutlined, BranchesOutlined, BulbOutlined, ClusterOutlined, DashboardOutlined,
  ExportOutlined, FileTextOutlined, LogoutOutlined, MenuFoldOutlined, MenuOutlined, MenuUnfoldOutlined,
  MobileOutlined, SafetyCertificateOutlined, SettingOutlined, TeamOutlined, TranslationOutlined,
} from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, isMobile, setTheme, setLang, refresh } from '../lib/store.js'
import { ui } from '../lib/ui.js'

const route = useRoute()
const router = useRouter()
const collapsed = ref(false)
const drawer = ref(false)

const icon = (c) => () => h(c)
const items = computed(() => [
  { key: 'overview', icon: icon(DashboardOutlined), label: t('nav.overview') },
  {
    type: 'group',
    label: collapsed.value && !isMobile.value ? '' : t('nav.network'),
    children: [
      { key: 'nodes', icon: icon(ClusterOutlined), label: t('nav.nodes') },
      { key: 'links', icon: icon(ApiOutlined), label: t('nav.links') },
      { key: 'routes', icon: icon(BranchesOutlined), label: t('nav.routes') },
      { key: 'clients', icon: icon(MobileOutlined), label: t('nav.clients') },
      { key: 'groups', icon: icon(TeamOutlined), label: t('nav.groups') },
    ],
  },
  {
    type: 'group',
    label: collapsed.value && !isMobile.value ? '' : t('nav.policies'),
    children: [
      { key: 'access', icon: icon(SafetyCertificateOutlined), label: t('nav.access') },
      { key: 'egress', icon: icon(ExportOutlined), label: t('nav.egress') },
    ],
  },
  {
    type: 'group',
    label: collapsed.value && !isMobile.value ? '' : t('nav.system'),
    children: [
      { key: 'yaml', icon: icon(FileTextOutlined), label: t('nav.yaml') },
      { key: 'audit', icon: icon(AuditOutlined), label: t('nav.audit') },
      { key: 'settings', icon: icon(SettingOutlined), label: t('nav.settings') },
    ],
  },
])

const selected = computed(() => [route.name])
const title = computed(() => t('nav.' + String(route.name)))
watch(title, (v) => (document.title = `${v} · tunx hub`), { immediate: true })

function go({ key }) {
  drawer.value = false
  if (key !== route.name) router.push({ name: key })
}

async function logout() {
  try {
    await api.logout()
  } catch {
    /* the session may already be gone */
  }
  state.me = null
  router.push({ name: 'login' })
}

const loadError = ref('')
refresh().catch((e) => {
  loadError.value = e.message
  ui.message?.error(t('c.loadFailed', { err: e.message }))
})
</script>

<template>
  <a-layout class="shell">
    <a-layout-sider
      v-if="!isMobile"
      v-model:collapsed="collapsed"
      collapsible
      :trigger="null"
      :width="220"
      :collapsed-width="64"
      class="sider"
    >
      <div class="brand" :class="{ mini: collapsed }">
        <img src="/favicon.svg" alt="" width="28" height="28" />
        <span v-if="!collapsed">{{ t('app.name') }}</span>
      </div>
      <a-menu mode="inline" :selected-keys="selected" :items="items" class="side-menu" @click="go" />
      <div class="sider-foot">
        <a-button type="text" block @click="collapsed = !collapsed" :aria-label="t('c.menu')">
          <MenuUnfoldOutlined v-if="collapsed" />
          <MenuFoldOutlined v-else />
        </a-button>
      </div>
    </a-layout-sider>
    <a-drawer
      v-else
      v-model:open="drawer"
      placement="left"
      :width="248"
      :closable="false"
      :body-style="{ padding: 0 }"
      class="nav-drawer"
    >
      <div class="brand">
        <img src="/favicon.svg" alt="" width="28" height="28" />
        <span>{{ t('app.name') }}</span>
      </div>
      <a-menu mode="inline" :selected-keys="selected" :items="items" class="side-menu" @click="go" />
    </a-drawer>

    <a-layout class="main">
      <a-layout-header class="header">
        <div class="header-left">
          <a-button v-if="isMobile" type="text" :aria-label="t('c.menu')" data-test="menu" @click="drawer = true">
            <MenuOutlined />
          </a-button>
          <span class="header-title">{{ title }}</span>
        </div>
        <div class="header-right">
          <a-tooltip :title="t('c.theme')">
            <a-button
              type="text"
              data-test="theme"
              :aria-label="t('c.theme')"
              @click="setTheme(state.theme === 'dark' ? 'light' : 'dark')"
            >
              <BulbOutlined />
              <span v-if="!isMobile" class="hbtn-label">{{ state.theme === 'dark' ? t('c.light') : t('c.dark') }}</span>
            </a-button>
          </a-tooltip>
          <a-button
            type="text"
            data-test="lang"
            :aria-label="t('c.language')"
            @click="setLang(state.lang === 'zh' ? 'en' : 'zh')"
          >
            <TranslationOutlined />
            <span class="hbtn-label">{{ state.lang === 'zh' ? 'EN' : '中文' }}</span>
          </a-button>
          <a-tooltip :title="t('c.logout')">
            <a-button type="text" data-test="logout" :aria-label="t('c.logout')" @click="logout">
              <LogoutOutlined />
            </a-button>
          </a-tooltip>
        </div>
      </a-layout-header>
      <a-layout-content class="content">
        <a-alert v-if="loadError" type="error" show-icon :message="t('c.loadFailed', { err: loadError })" style="margin-bottom: 16px" />
        <router-view v-slot="{ Component }">
          <component :is="Component" />
        </router-view>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<style scoped>
.shell {
  min-height: 100vh;
}
.sider {
  position: sticky;
  top: 0;
  height: 100vh;
  border-right: 1px solid var(--border);
}
.sider :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
}
.brand {
  height: 56px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 18px;
  font-weight: 700;
  font-size: 17px;
  letter-spacing: 0.2px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  white-space: nowrap;
}
.brand.mini {
  justify-content: center;
  padding: 0;
}
.side-menu {
  flex: 1;
  overflow-y: auto;
  border-inline-end: none !important;
  background: transparent;
  padding: 6px 0;
}
.side-menu :deep(.ant-menu-item-group-title) {
  font-size: 12px;
  padding-top: 12px;
}
.sider-foot {
  border-top: 1px solid var(--border);
  padding: 6px;
}
.main {
  min-width: 0;
}
.header {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border);
  line-height: normal;
  height: 56px;
  padding: 0 16px;
  background: var(--card);
}
@media (max-width: 767px) {
  .header {
    padding: 0 6px;
  }
}
.header-left,
.header-right {
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
}
.header-left {
  flex: 1;
}
.header-right {
  flex: none;
}
.header-title {
  font-size: 16px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.hbtn-label {
  margin-left: 6px;
}
.content {
  padding: 20px;
  min-width: 0;
}
@media (max-width: 767px) {
  .content {
    padding: 12px;
  }
}
</style>

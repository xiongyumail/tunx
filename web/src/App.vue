<script setup>
import { computed, watchEffect } from 'vue'
import { theme } from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import enUS from 'ant-design-vue/es/locale/en_US'
import { state } from './lib/store.js'
import AppBridge from './components/AppBridge.vue'

const themeConfig = computed(() => {
  const dark = state.theme === 'dark'
  return {
    algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
    token: dark
      ? {
          colorPrimary: '#14a88f',
          colorBgLayout: '#0b1220',
          colorBgContainer: '#131c2e',
          colorBgElevated: '#1a2539',
          colorBorderSecondary: '#222e45',
          colorBorder: '#2f3d58',
          borderRadius: 8,
          fontSize: 14,
        }
      : { colorPrimary: '#008771', colorBgLayout: '#eef1f5', borderRadius: 8, fontSize: 14 },
    components: {
      Layout: { colorBgHeader: dark ? '#0f1727' : '#ffffff', colorBgBody: dark ? '#0b1220' : '#eef1f5' },
      Menu: { colorItemBgSelected: dark ? '#14303a' : '#e3f3ef', colorItemTextSelected: dark ? '#3fd0b4' : '#00745f' },
    },
  }
})
const locale = computed(() => (state.lang === 'zh' ? zhCN : enUS))

watchEffect(() => {
  document.documentElement.dataset.theme = state.theme
  document.documentElement.lang = state.lang === 'zh' ? 'zh-CN' : 'en'
})
</script>

<template>
  <a-config-provider :theme="themeConfig" :locale="locale">
    <a-app>
      <AppBridge>
        <router-view />
      </AppBridge>
    </a-app>
  </a-config-provider>
</template>

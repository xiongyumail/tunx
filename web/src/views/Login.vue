<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { BulbOutlined, LockOutlined, SafetyOutlined, TranslationOutlined, UserOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { state, setTheme, setLang } from '../lib/store.js'

const router = useRouter()
const route = useRoute()
const form = reactive({ username: '', password: '', totp: '' })
const busy = ref(false)
const error = ref('')

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const r = await api.login(form.username.trim(), form.password, form.totp.trim())
    state.me = r
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') ? route.query.next : '/overview'
    router.replace(next)
  } catch (e) {
    error.value = e.message
    form.totp = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login">
    <div class="corner">
      <a-button type="text" data-test="theme" :aria-label="t('c.theme')" @click="setTheme(state.theme === 'dark' ? 'light' : 'dark')">
        <BulbOutlined />
      </a-button>
      <a-button type="text" data-test="lang" @click="setLang(state.lang === 'zh' ? 'en' : 'zh')">
        <TranslationOutlined />
        <span style="margin-left: 6px">{{ state.lang === 'zh' ? 'EN' : '中文' }}</span>
      </a-button>
    </div>
    <a-card class="login-card" :bordered="false">
      <div class="login-brand">
        <img src="/favicon.svg" alt="" width="44" height="44" />
        <div>
          <div class="login-name">{{ t('app.name') }}</div>
          <div class="muted">{{ t('login.subtitle') }}</div>
        </div>
      </div>
      <h1 class="login-title">{{ t('login.title') }}</h1>
      <a-alert v-if="error" type="error" :message="error" show-icon style="margin-bottom: 16px" data-test="login-error" />
      <a-form layout="vertical" :model="form" @finish="submit" :required-mark="false">
        <a-form-item :label="t('login.username')" name="username" :rules="[{ required: true, message: t('c.required') }]">
          <a-input v-model:value="form.username" size="large" autocomplete="username" name="username" autofocus>
            <template #prefix><UserOutlined class="muted" /></template>
          </a-input>
        </a-form-item>
        <a-form-item :label="t('login.password')" name="password" :rules="[{ required: true, message: t('c.required') }]">
          <a-input-password v-model:value="form.password" size="large" autocomplete="current-password" name="password">
            <template #prefix><LockOutlined class="muted" /></template>
          </a-input-password>
        </a-form-item>
        <a-form-item
          :label="t('login.totp')"
          name="totp"
          :extra="t('login.totpHint')"
          :rules="[{ required: true, pattern: /^\s*\d{6}\s*$/, message: t('login.totpHint') }]"
        >
          <a-input
            v-model:value="form.totp"
            size="large"
            inputmode="numeric"
            autocomplete="one-time-code"
            name="totp"
            :maxlength="6"
          >
            <template #prefix><SafetyOutlined class="muted" /></template>
          </a-input>
        </a-form-item>
        <a-button type="primary" html-type="submit" size="large" block :loading="busy" data-test="login-submit">
          {{ t('login.submit') }}
        </a-button>
      </a-form>
    </a-card>
  </div>
</template>

<style scoped>
.login {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 16px;
  box-sizing: border-box;
  background:
    radial-gradient(1200px 600px at 10% -10%, color-mix(in srgb, var(--primary) 22%, transparent), transparent 60%),
    radial-gradient(900px 500px at 110% 110%, color-mix(in srgb, #2f7de1 18%, transparent), transparent 60%),
    var(--bg);
}
.corner {
  position: fixed;
  top: 10px;
  right: 10px;
  display: flex;
  gap: 4px;
}
.login-card {
  width: 100%;
  max-width: 380px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.12);
}
.login-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 18px;
}
.login-name {
  font-size: 20px;
  font-weight: 700;
}
.login-title {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 16px;
}
</style>

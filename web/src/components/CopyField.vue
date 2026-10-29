<script setup>
import { CopyOutlined } from '@ant-design/icons-vue'
import { copyText, ui } from '../lib/ui.js'
import { t } from '../lib/i18n.js'

const props = defineProps({ value: { type: String, required: true }, label: String, rows: { type: Number, default: 0 } })

async function copy() {
  try {
    await copyText(props.value)
    ui.message.success(t('c.copied'))
  } catch {
    ui.message.error(t('c.copyFailed'))
  }
}
</script>

<template>
  <div class="copy-field">
    <div v-if="label" class="cf-label">{{ label }}</div>
    <div class="cf-row">
      <pre class="block cf-text" :class="{ clamp: !rows }" data-test="copy-value">{{ value }}</pre>
      <a-button :aria-label="t('c.copy')" @click="copy"><CopyOutlined /></a-button>
    </div>
  </div>
</template>

<style scoped>
.copy-field {
  margin-bottom: 12px;
}
.cf-label {
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 4px;
}
.cf-row {
  display: flex;
  gap: 8px;
  align-items: flex-start;
}
.cf-text {
  flex: 1;
  min-width: 0;
}
.clamp {
  max-height: 160px;
}
</style>

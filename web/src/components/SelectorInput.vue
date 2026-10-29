<script setup>
// Free-form tag input for identity selectors with suggestions for known
// nodes, clients, tags and groups.
import { computed } from 'vue'
import { selectorOptions } from '../lib/store.js'
import { t } from '../lib/i18n.js'

const props = defineProps({
  value: { type: Array, default: () => [] },
  groups: { type: Boolean, default: true },
  clients: { type: Boolean, default: true },
  extra: { type: Array, default: () => [] },
  placeholder: { type: String, default: '' },
})
const emit = defineEmits(['update:value'])

const options = computed(() => {
  const o = selectorOptions.value
  const mk = (label, list) => ({ label, options: list.map((v) => ({ value: v, label: v })) })
  const out = []
  if (props.extra.length) out.push({ label: '…', options: props.extra.map((v) => ({ value: v, label: v })) })
  out.push(mk(t('nav.nodes'), o.nodes))
  if (props.clients) out.push(mk(t('nav.clients'), o.clients))
  out.push(mk(t('c.tags'), o.tags))
  if (props.groups) out.push(mk(t('nav.groups'), o.groups))
  return out.filter((g) => g.options.length)
})
</script>

<template>
  <a-select
    mode="tags"
    :value="value"
    :options="options"
    :placeholder="placeholder || t('c.any')"
    :token-separators="[',', ' ']"
    style="width: 100%"
    @update:value="(v) => emit('update:value', v)"
  />
</template>

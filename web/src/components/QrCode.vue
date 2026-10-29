<script setup>
import { computed } from 'vue'
import qrcode from 'qrcode-generator'

const props = defineProps({ value: { type: String, required: true } })

const svg = computed(() => {
  const qr = qrcode(0, 'M')
  qr.addData(props.value, 'Byte')
  qr.make()
  const n = qr.getModuleCount()
  let d = ''
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`
  return { n, d }
})
</script>

<template>
  <div class="qr-box">
    <svg :viewBox="`-2 -2 ${svg.n + 4} ${svg.n + 4}`" shape-rendering="crispEdges" role="img" aria-label="QR code" data-test="qr">
      <rect x="-2" y="-2" :width="svg.n + 4" :height="svg.n + 4" fill="#fff" />
      <path :d="svg.d" fill="#111" />
    </svg>
  </div>
</template>

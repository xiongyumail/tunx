<script setup>
import { App } from 'ant-design-vue'
import { ui } from '../lib/ui.js'
const a = App.useApp()
ui.message = a.message
ui.modal = a.modal
</script>
<template><slot /></template>

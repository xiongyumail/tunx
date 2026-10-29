<script setup>
import { computed, ref } from 'vue'
import { CloudDownloadOutlined, DiffOutlined, DownloadOutlined, FolderOpenOutlined } from '@ant-design/icons-vue'
import { api } from '../lib/api.js'
import { t } from '../lib/i18n.js'
import { refresh, isMobile } from '../lib/store.js'
import { diffLines, hunks } from '../lib/diff.js'
import { download, ui } from '../lib/ui.js'

const current = ref('')
const text = ref('')
const loading = ref(false)
const busy = ref(false)
const preview = ref(null)
const result = ref(null)
const fileInput = ref(null)

async function load() {
  loading.value = true
  try {
    current.value = await api.exportYAML()
    text.value = current.value
  } catch (e) {
    ui.message.error(e.message)
  } finally {
    loading.value = false
  }
}
load()

const dirty = computed(() => text.value !== current.value)

async function openPreview() {
  // Compare against what the hub has now, not what was loaded earlier.
  try {
    current.value = await api.exportYAML()
  } catch (e) {
    return ui.message.error(e.message)
  }
  const ops = diffLines(current.value, text.value)
  preview.value = {
    lines: hunks(ops),
    added: ops.filter((o) => o.t === '+').length,
    removed: ops.filter((o) => o.t === '-').length,
  }
}

async function doImport() {
  busy.value = true
  try {
    const r = await api.importYAML(text.value)
    result.value = r.changes || []
    preview.value = null
    ui.message.success(t('yaml.imported', { n: result.value.length }))
    await Promise.all([load(), refresh()])
  } catch (e) {
    ui.message.error({ content: e.message, duration: 8 })
  } finally {
    busy.value = false
  }
}

function pick() {
  fileInput.value?.click()
}
async function onFile(ev) {
  const file = ev.target.files?.[0]
  if (!file) return
  text.value = await file.text()
  ev.target.value = ''
}
function save() {
  const name = `network-${new Date().toISOString().slice(0, 10)}.yaml`
  download(name, text.value, 'application/yaml')
}
const actionColor = { create: 'green', update: 'blue', delete: 'red' }
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h2>{{ t('yaml.title') }}</h2>
      <div class="tools">
        <a-button :loading="loading" @click="load"><CloudDownloadOutlined />{{ isMobile ? '' : t('yaml.reload') }}</a-button>
        <a-button @click="pick"><FolderOpenOutlined />{{ isMobile ? '' : t('yaml.open') }}</a-button>
        <a-button @click="save"><DownloadOutlined />{{ isMobile ? '' : t('c.download') }}</a-button>
        <a-button type="primary" data-test="preview" @click="openPreview"><DiffOutlined />{{ t('yaml.preview') }}</a-button>
        <input ref="fileInput" type="file" accept=".yaml,.yml,text/yaml,application/yaml" hidden @change="onFile" />
      </div>
    </div>
    <p class="hint">{{ t('yaml.hint') }}</p>
    <a-alert v-if="result" type="success" show-icon closable :message="t('yaml.imported', { n: result.length })" @close="result = null">
      <template v-if="result.length" #description>
        <div class="tags">
          <a-tag v-for="c in result" :key="c.kind + c.name" :color="actionColor[c.action]">{{ c.action }} {{ c.kind }}/{{ c.name }}</a-tag>
        </div>
      </template>
    </a-alert>
    <a-card :bordered="false" :body-style="{ padding: isMobile ? '10px' : '16px' }">
      <div v-if="dirty" class="dirty"><a-badge status="processing" :text="t('yaml.modified')" /></div>
      <a-spin :spinning="loading">
        <a-textarea
          v-model:value="text"
          class="yaml-editor"
          :auto-size="{ minRows: 18, maxRows: 40 }"
          spellcheck="false"
          wrap="off"
          autocapitalize="off"
          autocomplete="off"
          data-test="yaml-editor"
        />
      </a-spin>
    </a-card>

    <a-modal
      :open="!!preview"
      :title="t('yaml.diffTitle')"
      :width="isMobile ? '100%' : 860"
      :ok-text="t('yaml.import')"
      :cancel-text="t('c.cancel')"
      :ok-button-props="{ disabled: !preview || (!preview.added && !preview.removed), danger: true }"
      :confirm-loading="busy"
      @ok="doImport"
      @cancel="preview = null"
    >
      <template v-if="preview">
        <p v-if="!preview.added && !preview.removed" class="hint">{{ t('yaml.same') }}</p>
        <template v-else>
          <p class="hint" style="margin-bottom: 8px">{{ t('yaml.lines', { a: preview.added, r: preview.removed }) }}</p>
          <div class="diff" data-test="diff">
            <div
              v-for="(l, i) in preview.lines"
              :key="i"
              :class="['diff-line', l.t === '+' ? 'diff-add' : l.t === '-' ? 'diff-del' : l.t === '…' ? 'diff-gap' : '']"
            >{{ l.t === '…' ? `… ${l.s} …` : `${l.t} ${l.s}` }}</div>
          </div>
        </template>
      </template>
    </a-modal>
  </div>
</template>

<style scoped>
.dirty {
  margin-bottom: 8px;
}
</style>

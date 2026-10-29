<script setup>
// A table on wide screens and a list of cards on phones, from one set of
// antd column definitions. Columns may set mobile: false to hide in cards;
// the column with key "actions" becomes the card footer and the first
// column the card title.
import { computed } from 'vue'
import { isMobile } from '../lib/store.js'

const props = defineProps({
  columns: { type: Array, required: true },
  dataSource: { type: Array, default: () => [] },
  rowKey: { type: [String, Function], default: 'name' },
  loading: Boolean,
  pageSize: { type: Number, default: 0 },
  expand: { type: Function, default: null },
})

const Cell = (p) => p.node

function render(col, record, index) {
  const text = col.dataIndex ? record[col.dataIndex] : undefined
  if (col.customRender) return col.customRender({ text, record, index, column: col })
  if (text === undefined || text === null || text === '') return '—'
  return String(text)
}
function key(record, i) {
  return typeof props.rowKey === 'function' ? props.rowKey(record) : (record[props.rowKey] ?? i)
}

const titleCol = computed(() => props.columns[0])
const bodyCols = computed(() => props.columns.slice(1).filter((c) => c.key !== 'actions' && c.mobile !== false))
const actionCol = computed(() => props.columns.find((c) => c.key === 'actions'))
const pagination = computed(() => (props.pageSize ? { pageSize: props.pageSize, size: 'small', showSizeChanger: false } : false))
const expandedRowRender = computed(() => (props.expand ? ({ record }) => props.expand(record) : undefined))
</script>

<template>
  <div v-if="isMobile" class="dl-cards">
    <a-spin :spinning="loading">
      <a-empty v-if="!dataSource.length && !loading" />
      <div class="dl-cards">
        <a-card v-for="(r, i) in dataSource" :key="key(r, i)" size="small" class="dl-card">
          <template #title><Cell :node="render(titleCol, r, i)" /></template>
          <div v-for="c in bodyCols" :key="c.key || c.dataIndex" class="dl-row">
            <div class="dl-key">{{ c.title }}</div>
            <div class="dl-val"><Cell :node="render(c, r, i)" /></div>
          </div>
          <div v-if="expand" class="dl-expand"><Cell :node="expand(r)" /></div>
          <div v-if="actionCol" class="dl-actions"><Cell :node="render(actionCol, r, i)" /></div>
        </a-card>
      </div>
    </a-spin>
  </div>
  <div v-else class="table-wrap">
    <a-table
      :columns="columns"
      :data-source="dataSource"
      :row-key="rowKey"
      :loading="loading"
      :pagination="pagination"
      :expanded-row-render="expandedRowRender"
      size="middle"
      :scroll="{ x: 'max-content' }"
    />
  </div>
</template>

<style scoped>
.dl-expand {
  padding-top: 6px;
}
</style>

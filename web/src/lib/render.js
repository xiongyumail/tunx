// Small render helpers shared by the table columns.
import { h } from 'vue'
import { Tag, Button, Popconfirm, Space, Tooltip } from 'ant-design-vue'
import { t } from './i18n.js'

export function tags(list, color, empty = '—') {
  if (!list || !list.length) return h('span', { class: 'muted' }, empty)
  return h('div', { class: 'tags' }, list.map((x) => h(Tag, { color, key: String(x) }, () => String(x))))
}

export function mono(s) {
  if (s === undefined || s === null || s === '') return h('span', { class: 'muted' }, '—')
  return h('span', { class: 'mono break' }, String(s))
}

export function strong(s) {
  return h('span', { style: 'font-weight:600' }, s)
}

// stack describes the transport of an endpoint, e.g. "VLESS · REALITY · XHTTP".
export function stack(ep) {
  if (!ep) return '?'
  const net = (ep.network || 'raw').toUpperCase()
  switch (ep.transport) {
    case 'reality':
      return `VLESS · REALITY · ${net}`
    case 'tls':
      return `VLESS · TLS · ${net}`
    case 'vless':
      return `VLESS · ${net}`
    case 'socks':
      return 'SOCKS5'
    default:
      return ep.transport || '?'
  }
}

export const transportColor = { reality: 'green', tls: 'blue', vless: 'orange', socks: 'purple' }

// actions renders a row of icon buttons; each item: {label, icon, onClick,
// danger, confirm, disabled, test}.
export function actions(items) {
  return h(
    Space,
    { size: 2, wrap: true },
    () =>
      items.map((it) => {
        const btn = (extra = {}) =>
          h(
            Button,
            {
              type: 'text',
              size: 'small',
              danger: it.danger,
              disabled: it.disabled,
              'aria-label': it.label,
              'data-test': it.test,
              ...extra,
            },
            { icon: () => h(it.icon), default: it.text ? () => it.label : undefined },
          )
        if (it.confirm)
          return h(
            Popconfirm,
            { title: it.confirm, onConfirm: it.onClick, okText: t('c.delete'), cancelText: t('c.cancel'), okButtonProps: { danger: true } },
            () => h(Tooltip, { title: it.label }, () => btn()),
          )
        return h(Tooltip, { title: it.label }, () => btn({ onClick: it.onClick }))
      }),
  )
}

// clean drops empty strings, empty arrays, null and undefined (recursively
// in plain objects) so the API sees omitted fields instead of zero values.
export function clean(v) {
  if (Array.isArray(v)) return v.map(clean)
  if (v && typeof v === 'object') {
    const out = {}
    for (const [k, x] of Object.entries(v)) {
      if (x === '' || x === null || x === undefined) continue
      if (Array.isArray(x) && !x.length) continue
      out[k] = clean(x)
    }
    return out
  }
  return v
}

export function clone(v) {
  return v === undefined ? undefined : JSON.parse(JSON.stringify(v))
}

// Thin client for the tunx-hub REST API. The session lives in an HttpOnly
// cookie; state-changing requests carry the CSRF header the hub requires.

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

async function request(method, path, { body, raw, text } = {}) {
  const headers = {}
  if (method !== 'GET' && method !== 'HEAD') headers['X-Tunx-CSRF'] = '1'
  let payload
  if (raw !== undefined) {
    headers['Content-Type'] = 'application/yaml'
    payload = raw
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' })
  if (res.status === 204) return null
  const ct = res.headers.get('Content-Type') || ''
  if (!res.ok) {
    let msg = res.statusText || `HTTP ${res.status}`
    if (ct.includes('json')) {
      try {
        msg = (await res.json()).error || msg
      } catch {
        /* keep status text */
      }
    }
    if (res.status === 401 && path !== '/api/login') onUnauthorized()
    throw new ApiError(res.status, msg)
  }
  if (text) return res.text()
  return ct.includes('json') ? res.json() : res.text()
}

const enc = encodeURIComponent

export const api = {
  login: (username, password, totp) => request('POST', '/api/login', { body: { username, password, totp } }),
  logout: () => request('POST', '/api/logout'),
  me: () => request('GET', '/api/me'),
  network: () => request('GET', '/api/network'),
  putNetwork: (n) => request('PUT', '/api/network', { body: n }),
  list: (kind) => request('GET', `/api/${kind}`),
  get: (kind, name) => request('GET', `/api/${kind}/${enc(name)}`),
  create: (kind, obj) => request('POST', `/api/${kind}`, { body: obj }),
  put: (kind, name, obj) => request('PUT', `/api/${kind}/${enc(name)}`, { body: obj }),
  remove: (kind, name) => request('DELETE', `/api/${kind}/${enc(name)}`),
  exportYAML: () => request('GET', '/api/export', { text: true }),
  importYAML: (yaml) => request('POST', '/api/import', { raw: yaml }),
  audit: (limit) => request('GET', `/api/audit?limit=${limit}`),
  tokens: () => request('GET', '/api/tokens'),
  createToken: (name) => request('POST', '/api/tokens', { body: { name } }),
  deleteToken: (name) => request('DELETE', `/api/tokens/${enc(name)}`),
  enrollToken: (node) => request('POST', `/api/nodes/${enc(node)}/enroll-token`),
  nodeConfig: (node) => request('GET', `/api/nodes/${enc(node)}/config`),
  share: (client) => request('GET', `/api/clients/${enc(client)}/share`),
}

export const KINDS = ['nodes', 'links', 'routes', 'access', 'egress', 'clients', 'groups']

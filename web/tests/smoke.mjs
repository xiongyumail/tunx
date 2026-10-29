// Smoke test of the tunx-hub panel. It builds tunx-hub (or uses $HUB_BIN),
// seeds a temporary database from examples/network.yaml, serves it on
// 127.0.0.1, signs in with password + TOTP through the UI and visits every
// page at phone and desktop width, failing on console errors, failed API
// calls or horizontal page scroll.
//
//   node tests/smoke.mjs                 # run the checks
//   SHOTS=/some/dir node tests/smoke.mjs # also save screenshots
//
// Needs Chromium for playwright-core (npx playwright-core install chromium).
import { spawn, execFileSync } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'

const here = dirname(fileURLToPath(import.meta.url))
const repo = resolve(here, '../..')
const SHOTS = process.env.SHOTS || ''
const LANGS = (process.env.SHOT_LANGS || 'zh').split(',')
const PASSWORD = 'smoke-test-password-1'
const PAGES = ['overview', 'nodes', 'links', 'routes', 'access', 'egress', 'clients', 'groups', 'yaml', 'audit', 'settings']

let failures = 0
function check(ok, msg) {
  if (ok) return
  failures++
  console.error('FAIL:', msg)
}
function log(...a) {
  console.log('·', ...a)
}

function totp(secret, at = Date.now()) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of secret.replace(/=+$/, '').toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)))
  const h = createHmac('sha1', key).update(msg).digest()
  const o = h[h.length - 1] & 15
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0')
}

function freePort() {
  return new Promise((ok, fail) => {
    const s = createServer()
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port
      s.close(() => ok(p))
    })
    s.on('error', fail)
  })
}

async function waitHealthy(base, proc) {
  for (let i = 0; i < 100; i++) {
    if (proc.exitCode !== null) throw new Error('tunx-hub exited early')
    try {
      const r = await fetch(base + '/api/health')
      if (r.ok) return
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('tunx-hub did not become healthy')
}

async function main() {
  const work = mkdtempSync(join(tmpdir(), 'tunx-panel-'))
  let bin = process.env.HUB_BIN
  if (!bin) {
    bin = join(work, 'tunx-hub')
    log('building tunx-hub')
    execFileSync('go', ['build', '-o', bin, './cmd/tunx-hub'], { cwd: repo, stdio: 'inherit' })
  }
  const db = join(work, 'hub.db')
  writeFileSync(join(work, 'pw'), PASSWORD + '\n')
  const out = execFileSync(bin, ['init', '-db', db, '-admin', 'admin', '-password-file', join(work, 'pw')]).toString()
  const secret = out.match(/TOTP secret \(shown once\): (\S+)/)[1]
  execFileSync(bin, ['import', '-db', db, join(repo, 'examples/network.yaml')])
  // One node is left unenrolled so the panel shows both states.
  const port = await freePort()
  const base = `http://127.0.0.1:${port}`
  const hub = spawn(bin, ['serve', '-db', db, '-listen', `127.0.0.1:${port}`, '-insecure-cookie'], { stdio: ['ignore', 'ignore', 'pipe'] })
  let hubLog = ''
  hub.stderr.on('data', (d) => (hubLog += d))
  const browser = await chromium.launch()
  try {
    await waitHealthy(base, hub)
    log('hub on', base)

    // Security headers on the panel.
    const idx = await fetch(base + '/nodes')
    check(idx.ok && (await idx.text()).includes('id="app"'), 'history fallback serves index.html')
    check((idx.headers.get('content-security-policy') || '').includes("script-src 'self'"), 'CSP header on the panel')

    const errors = []
    const watch = (page, tag) => {
      page.on('console', (m) => {
        if (m.type() !== 'error') return
        // The first visit checks the session with /api/me; 401 there is expected.
        if (m.location().url.endsWith('/api/me') && m.text().includes('401')) return
        errors.push(`${tag} console: ${m.text()} ${m.location().url}`)
      })
      page.on('pageerror', (e) => errors.push(`${tag} pageerror: ${e.message}`))
      page.on('response', (r) => {
        if (r.url().includes('/api/') && r.status() >= 400 && !r.url().endsWith('/api/me')) errors.push(`${tag} ${r.status()} ${r.url()}`)
      })
    }

    // Sign in through the UI.
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US' })
    const page = await ctx.newPage()
    watch(page, 'login')
    await page.goto(base + '/')
    await page.waitForURL(/\/login/)
    check(await page.getByText('Sign in', { exact: true }).first().isVisible(), 'login page shows "Sign in" for an English browser')
    await page.fill('input[name=username]', 'admin')
    await page.fill('input[name=password]', PASSWORD)
    await page.fill('input[name=totp]', totp(secret))
    await page.click('[data-test=login-submit]')
    await page.waitForURL(/\/overview/)
    await page.waitForSelector('[data-test=topology]')
    log('signed in')
    const state = await ctx.storageState()

    // Desktop: every page through the side menu, plus key dialogs.
    const menu = { overview: 'Overview', nodes: 'Nodes', links: 'Links', routes: 'Routes & exits', access: 'Access policies', egress: 'Egress policies', clients: 'Clients', groups: 'Groups', yaml: 'YAML import/export', audit: 'Audit log', settings: 'Settings' }
    for (const p of PAGES) {
      await page.locator('.ant-menu-item', { hasText: menu[p] }).first().click()
      await page.waitForURL(new RegExp('/' + p + '$'))
      await page.waitForLoadState('networkidle')
      check((await page.locator('.header-title').textContent()) === menu[p], `${p}: header title`)
    }
    // Nodes: config drawer and node form.
    await page.goto(base + '/nodes')
    await page.locator('tr', { hasText: 'site-a' }).locator('[data-test=config]').click()
    await page.waitForSelector('.ant-drawer pre')
    check((await page.locator('.ant-drawer pre').textContent()).includes('"node": "site-a"'), 'rendered config of site-a')
    await page.keyboard.press('Escape')
    await page.locator('tr', { hasText: 'hub' }).first().locator('[data-test=edit]').click()
    await page.getByRole('tab', { name: /Endpoints/ }).click()
    check(await page.getByText('VLESS · REALITY · RAW').first().isVisible(), 'endpoint transport stack in node form')
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click()
    await page.waitForSelector('.ant-message-success')
    // Enrolment token for site-b.
    await page.locator('tr', { hasText: 'site-b' }).locator('[data-test=enroll]').click()
    await page.locator('.ant-modal-confirm-btns .ant-btn-primary').click()
    await page.waitForSelector('text=tunx_et_')
    check((await page.locator('.ant-modal [data-test=copy-value]').nth(1).textContent()).includes('/api/enroll'), 'install command')
    await page.locator('.ant-modal-close').last().click()
    // Links: form shows the transport stack of the chosen endpoint.
    await page.goto(base + '/links')
    await page.locator('tr', { hasText: 'hub-exit' }).locator('[data-test=edit]').click()
    check((await page.locator('[data-test=stack]').textContent()) === 'VLESS · REALITY · XHTTP', 'link stack')
    await page.getByRole('button', { name: 'Cancel' }).click()
    // Clients: share link and QR code.
    await page.goto(base + '/clients')
    await page.locator('tr', { hasText: 'phone' }).locator('[data-test=share]').click()
    await page.waitForSelector('[data-test=qr]')
    check((await page.locator('.ant-modal [data-test=copy-value]').first().textContent()).startsWith('vless://'), 'share link')
    await page.locator('.ant-modal-close').click()
    // Access: move a rule down and back.
    await page.goto(base + '/access')
    const first = () => page.locator('.ant-table-tbody tr.ant-table-row').first().textContent()
    check((await first()).includes('core-any'), 'access order starts with core-any')
    await page.locator('.ant-table-tbody tr.ant-table-row').first().locator('[data-test=down]').click()
    await page.waitForFunction(() => document.querySelector('.ant-table-tbody tr.ant-table-row')?.textContent.includes('a-to-b'))
    await page.locator('.ant-table-tbody tr.ant-table-row').first().locator('[data-test=down]').click()
    await page.waitForFunction(() => document.querySelector('.ant-table-tbody tr.ant-table-row')?.textContent.includes('core-any'))
    // Groups: create and delete.
    await page.goto(base + '/groups')
    await page.click('[data-test=add]')
    await page.fill('[data-test=f-name]', 'smoke')
    await page.locator('.ant-modal .ant-select-selector').click()
    await page.keyboard.type('tag:core')
    await page.keyboard.press('Enter')
    await page.locator('.ant-modal-title').click()
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click()
    await page.waitForSelector('tr:has-text("smoke")')
    await page.locator('tr', { hasText: 'smoke' }).locator('.anticon-delete').click()
    await page.locator('.ant-popconfirm .ant-btn-dangerous').click()
    await page.waitForSelector('tr:has-text("smoke")', { state: 'detached' })
    // YAML: edit, preview the diff, import.
    await page.goto(base + '/yaml')
    const editor = page.locator('[data-test=yaml-editor]')
    await page.waitForFunction(() => document.querySelector('[data-test=yaml-editor]')?.value.includes('network:'))
    const yaml = await editor.inputValue()
    await editor.fill(yaml.replace('dns_suffix: tunx.internal', 'dns_suffix: smoke.internal'))
    await page.click('[data-test=preview]')
    await page.waitForSelector('[data-test=diff] .diff-add')
    check((await page.locator('[data-test=diff] .diff-add').first().textContent()).includes('smoke.internal'), 'diff shows the change')
    await page.getByRole('button', { name: 'Import', exact: true }).click()
    await page.waitForSelector('text=Imported: 1 changes')
    // Audit shows the import.
    await page.goto(base + '/audit')
    await page.waitForSelector('.ant-table-tbody tr.ant-table-row')
    check((await page.locator('.ant-table-tbody').textContent()).includes('admin:admin'), 'audit lists the admin')
    // Settings: create an API token.
    await page.goto(base + '/settings')
    await page.click('[data-test=new-token]')
    await page.fill('input[placeholder=ci]', 'smoke')
    await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click()
    await page.waitForSelector('text=tunx_at_')
    await page.locator('.ant-modal-close').last().click()
    await ctx.close()

    // Phone: drawer navigation and no horizontal scroll on any page.
    const pctx = await browser.newContext({ viewport: { width: 375, height: 812 }, locale: 'zh-CN', storageState: state, isMobile: true, hasTouch: true })
    const phone = await pctx.newPage()
    watch(phone, 'phone')
    await phone.goto(base + '/overview')
    await phone.click('[data-test=menu]')
    await phone.locator('.ant-drawer .ant-menu-item', { hasText: '链路' }).click()
    await phone.waitForURL(/\/links$/)
    for (const p of PAGES) {
      await phone.goto(base + '/' + p)
      await phone.waitForLoadState('networkidle')
      const over = await phone.evaluate(() => {
        // body hides horizontal overflow, so measure what sticks out.
        let right = Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)
        for (const el of document.querySelectorAll('#app *')) right = Math.max(right, el.getBoundingClientRect().right)
        return Math.round(right - window.innerWidth)
      })
      check(over <= 0, `${p} at 375px scrolls horizontally by ${over}px`)
    }
    await pctx.close()

    if (SHOTS) await screenshots(browser, base, state)

    check(errors.length === 0, 'console or API errors:\n  ' + errors.join('\n  '))
  } finally {
    await browser.close()
    hub.kill()
    if (failures) console.error(hubLog.split('\n').filter((l) => /"level":"(ERROR|WARN)"/.test(l)).join('\n'))
    rmSync(work, { recursive: true, force: true })
  }
  if (failures) {
    console.error(`${failures} check(s) failed`)
    process.exit(1)
  }
  console.log('smoke test passed')
}

async function screenshots(browser, base, state) {
  mkdirSync(SHOTS, { recursive: true })
  for (const lang of LANGS)
    for (const theme of ['light', 'dark'])
      for (const width of [375, 1440]) {
        const ctx = await browser.newContext({
          viewport: { width, height: width < 768 ? 812 : 900 },
          deviceScaleFactor: width < 768 ? 2 : 1,
          storageState: state,
        })
        await ctx.addInitScript(
          ([l, t]) => {
            localStorage.setItem('tunx.lang', l)
            localStorage.setItem('tunx.theme', t)
          },
          [lang, theme],
        )
        const page = await ctx.newPage()
        for (const p of PAGES) {
          await page.goto(base + '/' + p)
          await page.waitForLoadState('networkidle')
          await page.waitForTimeout(250)
          await page.screenshot({ path: join(SHOTS, `${lang}-${theme}-${width}-${p}.png`), fullPage: true })
        }
        // Dialogs worth a look.
        await page.goto(base + '/clients')
        await page.waitForLoadState('networkidle')
        await page.locator('[data-test=share]').first().click()
        await page.waitForSelector('[data-test=qr]')
        await page.waitForTimeout(300)
        await page.screenshot({ path: join(SHOTS, `${lang}-${theme}-${width}-clients-share.png`) })
        await page.goto(base + '/nodes')
        await page.waitForLoadState('networkidle')
        await page.locator('[data-test=edit]').nth(1).click()
        await page.locator('.ant-modal .ant-tabs-tab').nth(1).click()
        await page.waitForTimeout(300)
        await page.screenshot({ path: join(SHOTS, `${lang}-${theme}-${width}-nodes-form.png`) })
        await page.goto(base + '/links')
        await page.waitForLoadState('networkidle')
        await page.locator('[data-test=edit]').first().click()
        await page.waitForTimeout(300)
        await page.screenshot({ path: join(SHOTS, `${lang}-${theme}-${width}-links-form.png`) })
        await page.goto(base + '/yaml')
        await page.waitForLoadState('networkidle')
        await page.waitForFunction(() => document.querySelector('[data-test=yaml-editor]')?.value.includes('network:'))
        const ed = page.locator('[data-test=yaml-editor]')
        await ed.fill((await ed.inputValue()).replace('cost: 20', 'cost: 30'))
        await page.click('[data-test=preview]')
        await page.waitForSelector('[data-test=diff]')
        await page.waitForTimeout(300)
        await page.screenshot({ path: join(SHOTS, `${lang}-${theme}-${width}-yaml-diff.png`) })
        await ctx.close()
        // Login page, signed out.
        const lctx = await browser.newContext({ viewport: { width, height: width < 768 ? 812 : 900 }, deviceScaleFactor: width < 768 ? 2 : 1 })
        await lctx.addInitScript(
          ([l, t]) => {
            localStorage.setItem('tunx.lang', l)
            localStorage.setItem('tunx.theme', t)
          },
          [lang, theme],
        )
        const lp = await lctx.newPage()
        await lp.goto(base + '/login')
        await lp.waitForSelector('[data-test=login-submit]')
        await lp.screenshot({ path: join(SHOTS, `${lang}-${theme}-${width}-login.png`) })
        await lctx.close()
        log('screenshots', lang, theme, width)
      }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})

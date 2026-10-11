import { spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { chromium } from 'playwright'

const port = 4500 + Math.floor(Math.random() * 300)
const url = `http://127.0.0.1:${port}/`
const shots = process.env.SHOTS_DIR ?? 'shots'
mkdirSync(shots, { recursive: true })
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--port', String(port), '--strictPort', '--host', '127.0.0.1'], { stdio: 'ignore' })
let browser
const errors = []
const cleanup = () => { try { server.kill('SIGTERM') } catch {} }
async function waitForServer() { for (let i = 0; i < 60; i += 1) { try { if ((await fetch(url)).ok) return } catch {} await new Promise(resolve => setTimeout(resolve, 250)) } throw new Error('preview server did not start') }
async function fail(message) { console.error(`smoke: FAIL — ${message}`); await browser?.close().catch(() => {}); cleanup(); process.exit(1) }
try {
  await waitForServer()
  browser = await chromium.launch({ args: ['--ignore-gpu-blocklist'] })
  const desktop = await browser.newContext({ viewport: { width: 1365, height: 900 } })
  const page = await desktop.newPage()
  page.on('console', message => message.type() === 'error' && errors.push(message.text()))
  page.on('pageerror', error => errors.push(String(error)))
  await page.route('**/api/analyze', route => route.fulfill({ status: 200, contentType: 'application/json', body: '{' }))
  await page.goto(url)
  await page.waitForSelector('#scan-form')
  await page.screenshot({ path: `${shots}/empty.png` })
  await page.fill('#target-input', 'MoonAirdrop 100x')
  await page.click('[data-example="https://example.com"]')
  await page.fill('#target-input', '0x0000000000000000000000000000000000000000')
  await page.click('.scan-button')
  await page.waitForSelector('.report')
  if ((await page.locator('.score-block.high').count()) !== 1) throw new Error('high risk score did not render')
  if ((await page.locator('.flag-card.critical').count()) < 1) throw new Error('critical finding did not render')
  await page.screenshot({ path: `${shots}/report.png` })
  await page.click('[data-action="new-scan"]')
  await page.fill('#target-input', 'Blue Harbor')
  await page.press('#target-input', 'Enter')
  await page.waitForSelector('.report')
  if ((await page.locator('.recent-section').count()) !== 0) throw new Error('report state should prioritize current result')
  await desktop.close()
  const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true })
  const mobile = await phone.newPage()
  await mobile.goto(url)
  await mobile.waitForSelector('.scan-card')
  const width = await mobile.locator('.main-layout').evaluate(element => element.getBoundingClientRect().width)
  if (width > 390) throw new Error('mobile layout overflows viewport')
  await mobile.screenshot({ path: `${shots}/mobile.png` })
  await phone.close()
  if (errors.length) throw new Error(`console errors:\n${errors.join('\n')}`)
  await browser.close(); cleanup(); console.log('smoke: OK — scan form, risk report, findings, fallback, and mobile verified')
} catch (error) { await fail(error?.message ?? String(error)) }

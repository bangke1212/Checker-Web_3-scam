import './styles.css'
import { analyzeTarget, type Analysis, type RiskFlag } from './analyzer'

const root = document.querySelector<HTMLDivElement>('#app')!
if (!root) throw new Error('ScamGuard mount point is missing')

const examples = [
  { label: 'EVM address', value: '0x0000000000000000000000000000000000000000' },
  { label: 'Website URL', value: 'https://example.com' },
  { label: 'Token name', value: 'MoonAirdrop 100x' },
]

let lastResult: Analysis | undefined
let isScanning = false
let recent: Analysis[] = readRecent()

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)
}

function iconFor(severity: RiskFlag['severity']): string {
  if (severity === 'critical') return '×'
  if (severity === 'warning') return '!'
  if (severity === 'positive') return '✓'
  return 'i'
}

function renderShell(): void {
  root.innerHTML = `<div class="site-shell">
    <header class="topbar">
      <button class="brand" data-action="home" aria-label="ScamGuard home"><span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span>SCAM<span>GUARD</span></span></button>
      <div class="topbar-meta"><span class="status-dot"></span><span>HEURISTIC SCREENING</span><button class="help-link" data-action="how">How it works</button></div>
    </header>
    <main class="main-layout">
      <section class="hero-block">
        <div class="eyebrow"><span class="signal-line"></span>WEB3 RISK INTELLIGENCE</div>
        <h1>Know the risk<br /><em>before you connect.</em></h1>
        <p class="hero-copy">A calm second opinion for tokens, contract addresses, and websites. Start with the address, not the hype.</p>
      </section>
      <section class="scan-card" aria-labelledby="scan-title">
        <div class="scan-card-head"><div><span class="step-count">01 / INPUT</span><h2 id="scan-title">What do you want to check?</h2></div><span class="scan-icon" aria-hidden="true">⌁</span></div>
        <form id="scan-form" class="scan-form">
          <label class="sr-only" for="target-input">Token name, contract address, or website URL</label>
          <div class="input-wrap"><span class="input-prefix">⌕</span><input id="target-input" name="input" maxlength="300" autocomplete="off" placeholder="Paste a token name, contract address, or URL" value="${escapeHtml(lastResult?.input ?? '')}" /><kbd>ENTER</kbd></div>
          <div class="example-row"><span>TRY AN EXAMPLE</span>${examples.map(example => `<button type="button" class="example-chip" data-example="${escapeHtml(example.value)}"><b>${escapeHtml(example.label)}</b><small>${escapeHtml(example.value.length > 24 ? `${example.value.slice(0, 21)}…` : example.value)}</small></button>`).join('')}</div>
          <button class="scan-button" type="submit" ${isScanning ? 'disabled' : ''}><span class="button-pulse"></span><b>${isScanning ? 'SCANNING SIGNALS…' : 'ANALYZE TARGET'}</b><span class="button-arrow">↗</span></button>
        </form>
        <div class="privacy-note"><span>◌</span> Your input is screened only for this report. Never paste a seed phrase or private key.</div>
      </section>
      ${isScanning ? `<section class="loading-card"><div class="loading-orbit"><span></span><span></span><span></span></div><div><span class="eyebrow">RUNNING CHECKS</span><p>Parsing target format, looking for obvious risk signals…</p></div><span class="loading-code">SIG//${Math.floor(Math.random() * 900 + 100)}</span></section>` : ''}
      ${lastResult && !isScanning ? renderResult(lastResult) : renderEmptyState()}
      ${renderRecent()}
    </main>
    <footer class="site-footer"><span>SCAMGUARD / WEB3 RISK INTELLIGENCE</span><span>SCREEN FIRST. SIGN LAST.</span></footer>
    <div class="toast" role="status" aria-live="polite"></div>
  </div>`
  bindEvents()
}

function renderEmptyState(): string {
  return `<section class="empty-report"><div class="empty-mark">···</div><div><span class="eyebrow">REPORT PREVIEW</span><h2>Your signal report will appear here.</h2><p>We’ll separate format checks, security warnings, and what still needs independent verification.</p></div><div class="empty-rule"></div><div class="empty-foot"><span>NO INPUT YET</span><span>READY WHEN YOU ARE</span></div></section>`
}

function renderResult(result: Analysis): string {
  const levelClass = result.level.toLowerCase()
  const flags = [...result.flags].sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2, positive: 3 }
    return order[a.severity] - order[b.severity]
  })
  return `<section class="report" aria-live="polite">
    <div class="report-kicker"><span class="step-count">02 / SIGNAL REPORT</span><span class="source-pill"><i></i>${result.source === 'heuristic+http' ? 'HTTP + HEURISTIC' : 'HEURISTIC ONLY'}</span></div>
    <div class="report-head"><div class="score-block ${levelClass}"><div class="score-ring"><svg viewBox="0 0 120 120" aria-hidden="true"><circle class="ring-track" cx="60" cy="60" r="52"></circle><circle class="ring-value" cx="60" cy="60" r="52" style="--score:${result.score}"></circle></svg><strong>${result.score}</strong><span>/ 100</span></div><div><span class="eyebrow">RISK LEVEL</span><h2>${result.level} risk</h2><p>${escapeHtml(result.summary)}</p></div></div><div class="target-meta"><span class="eyebrow">ANALYZED TARGET</span><b>${escapeHtml(result.normalized)}</b><span>${escapeHtml(result.label)} · ${formatTime(result.checkedAt)} · ${result.latencyMs}ms</span></div></div>
    <div class="report-stats"><div><span>CHECKS RUN</span><b>${result.checks}</b></div><div><span>CRITICAL</span><b class="critical-text">${result.flags.filter(flag => flag.severity === 'critical').length}</b></div><div><span>WARNINGS</span><b class="warning-text">${result.flags.filter(flag => flag.severity === 'warning').length}</b></div><div><span>POSITIVE SIGNALS</span><b class="positive-text">${result.flags.filter(flag => flag.severity === 'positive').length}</b></div></div>
    <div class="report-grid"><div class="flags-column"><div class="section-heading"><div><span class="eyebrow">FINDINGS</span><h3>What stood out</h3></div><span class="finding-count">${flags.length} SIGNALS</span></div>${flags.map(renderFlag).join('')}</div><aside class="report-aside"><div class="aside-card caution"><span class="aside-icon">!</span><div><span class="eyebrow">NON-NEGOTIABLE</span><h3>Never sign from pressure.</h3><p>No risk score can see everything. If a site asks for your seed phrase or private key, leave immediately.</p></div></div><div class="aside-card"><span class="eyebrow">LIMITS OF THIS SCAN</span>${result.limitations.map(item => `<p class="limit-line"><span>—</span>${escapeHtml(item)}</p>`).join('')}</div><button class="outline-button" data-action="new-scan">← CHECK ANOTHER TARGET</button></aside></div>
  </section>`
}

function renderFlag(flag: RiskFlag): string {
  return `<article class="flag-card ${flag.severity}"><div class="flag-icon" aria-hidden="true">${iconFor(flag.severity)}</div><div class="flag-content"><div class="flag-title-row"><h4>${escapeHtml(flag.title)}</h4><span class="severity-label">${flag.severity}</span></div><p>${escapeHtml(flag.detail)}</p><div class="evidence"><span>EVIDENCE</span><code>${escapeHtml(flag.evidence)}</code></div><div class="action-line"><span>↳</span><b>NEXT:</b>${escapeHtml(flag.action)}</div></div></article>`
}

function renderRecent(): string {
  if (!recent.length || lastResult) return ''
  return `<section class="recent-section"><div class="section-heading"><div><span class="eyebrow">LOCAL MEMORY</span><h3>Recent checks</h3></div><button class="clear-button" data-action="clear-recent">Clear</button></div><div class="recent-row">${recent.slice(0, 3).map(item => `<button class="recent-chip" data-recent="${escapeHtml(item.input)}"><span class="recent-score ${item.level.toLowerCase()}">${item.score}</span><span><b>${escapeHtml(item.normalized.slice(0, 28))}</b><small>${escapeHtml(item.level)} · ${escapeHtml(item.label)}</small></span><span>↗</span></button>`).join('')}</div></section>`
}

function formatTime(value: string): string {
  try { return new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit' }).format(new Date(value)) } catch { return 'just now' }
}

function readRecent(): Analysis[] {
  try { return JSON.parse(localStorage.getItem('scamguard-recent') ?? '[]') as Analysis[] } catch { return [] }
}
function writeRecent(result: Analysis): void {
  recent = [result, ...recent.filter(item => item.input !== result.input)].slice(0, 5)
  localStorage.setItem('scamguard-recent', JSON.stringify(recent))
}
function toast(message: string): void {
  const element = root.querySelector<HTMLDivElement>('.toast')
  if (!element) return
  element.textContent = message
  element.classList.add('visible')
  window.setTimeout(() => element.classList.remove('visible'), 2600)
}

async function runScan(input: string): Promise<void> {
  if (!input.trim() || isScanning) return
  isScanning = true
  renderShell()
  const started = Date.now()
  let result: Analysis | undefined
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input }) })
    if (!response.ok) throw new Error(`API ${response.status}`)
    result = await response.json() as Analysis
  } catch {
    result = await analyzeTarget(input)
    toast('API unavailable — showing transparent local heuristics')
  }
  result.latencyMs = Math.max(result.latencyMs, Date.now() - started)
  lastResult = result
  writeRecent(result)
  isScanning = false
  renderShell()
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

function bindEvents(): void {
  root.querySelector<HTMLFormElement>('#scan-form')?.addEventListener('submit', event => {
    event.preventDefault()
    const input = root.querySelector<HTMLInputElement>('#target-input')?.value ?? ''
    void runScan(input)
  })
  root.querySelectorAll<HTMLButtonElement>('[data-example]').forEach(button => button.addEventListener('click', () => {
    const input = root.querySelector<HTMLInputElement>('#target-input')
    if (input) { input.value = button.dataset.example ?? ''; input.focus() }
  }))
  root.querySelectorAll<HTMLButtonElement>('[data-recent]').forEach(button => button.addEventListener('click', () => { lastResult = undefined; const input = button.dataset.recent ?? ''; void runScan(input) }))
  root.querySelector<HTMLButtonElement>('[data-action="new-scan"]')?.addEventListener('click', () => { lastResult = undefined; renderShell(); root.querySelector<HTMLInputElement>('#target-input')?.focus() })
  root.querySelector<HTMLButtonElement>('[data-action="clear-recent"]')?.addEventListener('click', () => { recent = []; localStorage.removeItem('scamguard-recent'); renderShell() })
  root.querySelector<HTMLButtonElement>('[data-action="home"]')?.addEventListener('click', () => { lastResult = undefined; renderShell() })
  root.querySelector<HTMLButtonElement>('[data-action="how"]')?.addEventListener('click', () => toast('We check format, public HTTP signals, and known red-flag patterns — never private wallet data.'))
}

renderShell()

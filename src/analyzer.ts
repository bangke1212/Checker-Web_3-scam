export type TargetKind = 'token' | 'address' | 'website' | 'unknown'
export type RiskLevel = 'Low' | 'Medium' | 'High'
export type FlagSeverity = 'critical' | 'warning' | 'positive' | 'info'

export interface RiskFlag {
  severity: FlagSeverity
  title: string
  detail: string
  evidence: string
  action: string
}

export interface Analysis {
  input: string
  normalized: string
  kind: TargetKind
  label: string
  score: number
  level: RiskLevel
  summary: string
  flags: RiskFlag[]
  checks: number
  source: 'heuristic' | 'heuristic+http'
  checkedAt: string
  latencyMs: number
  limitations: string[]
}

export interface AnalyzeOptions {
  fetcher?: typeof fetch
  now?: () => Date
}

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/
const SOLANA_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/
const URL_RE = /^https?:\/\//i
const SUSPICIOUS_NAME_RE = /(airdrop|claim|presale|100x|guaranteed|free|mint|bonus|profit|yield)/i
const SUSPICIOUS_PAGE_RE = /(seed phrase|secret phrase|private key|connect wallet|100x|guaranteed returns|claim now|send funds)/i
const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'click', 'top', 'support', 'quest', 'live', 'buzz', 'gq', 'country'])

const asRiskLevel = (score: number): RiskLevel => score <= 28 ? 'Low' : score <= 58 ? 'Medium' : 'High'

function isPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/[\[\]]/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host === 'metadata.google.internal') return true
  if (/^(127|0|10)\./.test(host) || /^169\.254\./.test(host) || /^192\.168\./.test(host)) return true
  const match = host.match(/^172\.(\d{1,3})\./)
  return Boolean(match && Number(match[1]) >= 16 && Number(match[1]) <= 31) || host === '::1'
}

function isSafePublicUrl(value: string): URL | null {
  try {
    const url = new URL(value)
    if (!['http:', 'https:'].includes(url.protocol) || isPrivateHost(url.hostname)) return null
    return url
  } catch {
    return null
  }
}

function pushFlag(flags: RiskFlag[], severity: FlagSeverity, title: string, detail: string, evidence: string, action: string): void {
  flags.push({ severity, title, detail, evidence, action })
}

function scoreFlags(kind: TargetKind, flags: RiskFlag[]): number {
  const base = kind === 'website' ? 10 : kind === 'address' ? 14 : kind === 'unknown' ? 32 : 18
  const total = flags.reduce((sum, flag) => {
    if (flag.severity === 'critical') return sum + 38
    if (flag.severity === 'warning') return sum + 19
    if (flag.severity === 'positive') return sum - 8
    return sum + 6
  }, base)
  return Math.max(0, Math.min(100, Math.round(total)))
}

function summaryFor(level: RiskLevel, kind: TargetKind, flags: RiskFlag[]): string {
  const critical = flags.filter(flag => flag.severity === 'critical').length
  const warnings = flags.filter(flag => flag.severity === 'warning').length
  if (level === 'High') return `${critical ? `${critical} critical signal${critical > 1 ? 's' : ''} and ` : ''}${warnings} warning${warnings === 1 ? '' : 's'} need attention before you interact.`
  if (level === 'Medium') return `Some signals are inconclusive for this ${kind}; verify the project from independent sources before signing.`
  return `No major heuristic red flags were found, but a clean screen is not proof of safety.`
}

function analyzeToken(input: string, flags: RiskFlag[]): void {
  const compact = input.replace(/\s+/g, ' ').trim()
  if (SUSPICIOUS_NAME_RE.test(compact)) {
    pushFlag(flags, 'warning', 'Hype-led wording detected', 'The name contains language commonly used by speculative promotions and urgency campaigns.', `Matched phrase in input: “${compact.slice(0, 80)}”`, 'Find the official contract address from a verified project channel before doing anything else.')
  } else {
    pushFlag(flags, 'info', 'Name-only lookup', 'A token name is not unique enough to identify one asset or contract.', 'No canonical address was supplied.', 'Use the exact contract address on the correct chain for a more useful review.')
  }
  pushFlag(flags, 'warning', 'No on-chain permissions checked', 'This screen cannot verify owner powers, blacklist logic, transfer taxes, liquidity locks, holder concentration, or trading activity without a chain data provider.', 'Provider status: not configured', 'Review verified source code and independent on-chain data before connecting a wallet.')
}

function analyzeAddress(input: string, flags: RiskFlag[]): void {
  const isEvm = ADDRESS_RE.test(input)
  const isSolana = SOLANA_RE.test(input) && !/^0x/i.test(input)
  if (!isEvm && !isSolana) {
    pushFlag(flags, 'critical', 'Address format not recognized', 'The value does not match a standard EVM or Solana-style address shape.', `Input length: ${input.length} characters`, 'Copy the address directly from a trusted chain explorer and check the selected network.')
    return
  }
  pushFlag(flags, 'positive', `${isEvm ? 'EVM' : 'Solana'} address shape recognized`, 'The value matches a known public-address format. This only validates shape, not ownership or behavior.', `Pattern check passed for ${isEvm ? '0x + 40 hexadecimal characters' : 'base58 address'}`, 'Confirm the chain and contract page independently before signing.')
  if (isEvm) {
    const body = input.slice(2)
    if (/^(.)\1+$/.test(body)) pushFlag(flags, 'critical', 'Repeating-address pattern', 'The address is made from one repeated hexadecimal character and is unlikely to be a normal deployed contract.', `Address body pattern: ${body.slice(0, 8)}…`, 'Do not send funds; re-check the copied address.')
    if (input === '0x0000000000000000000000000000000000000000') pushFlag(flags, 'critical', 'Zero address', 'This is the canonical EVM zero address, which is not a normal destination for a token purchase.', 'Exact zero address match', 'Stop and confirm the address from the official project source.')
    if (input === input.toLowerCase() || input === input.toUpperCase()) pushFlag(flags, 'info', 'Checksum not present', 'All-lowercase and all-uppercase EVM addresses can still be valid, but checksum casing helps catch copy errors.', 'EIP-55 checksum casing was not supplied', 'Compare against an explorer and the project documentation.')
  }
  pushFlag(flags, 'warning', 'Behavior not inspected', 'An address alone cannot reveal contract source, proxy implementation, admin privileges, sell restrictions, taxes, liquidity, or holder distribution.', 'Chain provider status: not configured', 'Inspect verified source and simulation results before approving a transaction.')
}

async function analyzeWebsite(input: string, flags: RiskFlag[], fetcher?: typeof fetch): Promise<'heuristic' | 'heuristic+http'> {
  const url = isSafePublicUrl(input)
  if (!url) {
    pushFlag(flags, 'critical', 'URL is not a safe public URL', 'Only public http:// and https:// URLs are accepted for remote inspection.', 'Protocol or hostname validation failed', 'Use a complete public URL and never paste a wallet seed phrase or private key.')
    return 'heuristic'
  }
  pushFlag(flags, 'positive', 'Public URL accepted', 'The URL uses a supported protocol and passed basic host safety checks.', `${url.protocol}//${url.hostname}`, 'Confirm this domain is the one published by the project you intend to use.')
  const tld = url.hostname.split('.').pop()?.toLowerCase()
  if (tld && SUSPICIOUS_TLDS.has(tld)) pushFlag(flags, 'warning', 'Higher-abuse TLD signal', 'This top-level domain is frequently used in disposable campaigns. It is not proof of fraud, but it deserves extra verification.', `Top-level domain: .${tld}`, 'Prefer a long-standing official domain linked from a trusted project account.')
  if (!fetcher) {
    pushFlag(flags, 'warning', 'Live reachability not checked', 'Local preview cannot safely fetch arbitrary websites from the browser, so HTTP headers and page content were not inspected.', 'Analysis mode: local heuristic fallback', 'Run this scan on the deployed app for server-side HTTP checks.')
    return 'heuristic'
  }
  try {
    const response = await fetcher(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(6500), headers: { accept: 'text/html,application/xhtml+xml' } })
    const finalUrl = isSafePublicUrl(response.url) ? new URL(response.url) : url
    if (response.status >= 400) pushFlag(flags, 'warning', 'Website returned an error', 'The target responded, but the HTTP status indicates an error or unavailable page.', `HTTP status: ${response.status}`, 'Do not trust a broken or redirected page until the official domain is confirmed.')
    else pushFlag(flags, 'positive', 'Website responded', 'The public endpoint returned a successful HTTP response.', `HTTP status: ${response.status}`, 'A reachable website can still host malicious content; continue reviewing the warnings.')
    if (finalUrl.protocol !== 'https:') pushFlag(flags, 'critical', 'Connection is not HTTPS', 'The final response URL does not use transport encryption.', `Final URL: ${finalUrl.protocol}//${finalUrl.hostname}`, 'Do not enter credentials or connect a wallet over plain HTTP.')
    if (!response.headers.get('strict-transport-security')) pushFlag(flags, 'warning', 'HSTS header missing', 'The site does not advertise strict transport security to browsers.', 'Strict-Transport-Security: missing', 'Treat unexpected redirects and lookalike domains with extra caution.')
    if (!response.headers.get('content-security-policy')) pushFlag(flags, 'info', 'CSP header not observed', 'A Content-Security-Policy header was not present in the response metadata.', 'Content-Security-Policy: missing', 'This is a hardening gap, not proof that the site is malicious.')
    const contentType = response.headers.get('content-type') ?? 'unknown'
    const body = contentType.includes('text/html') ? (await response.text()).slice(0, 50000) : ''
    if (body && SUSPICIOUS_PAGE_RE.test(body)) pushFlag(flags, 'critical', 'Sensitive-wallet language found', 'The page contains language that may pressure visitors to reveal secrets or approve a risky action.', `Matched page content in ${contentType}`, 'Never share a seed phrase or private key; close the page and verify the project elsewhere.')
    if (body && !/<title[^>]*>\s*[^<]{2,}/i.test(body)) pushFlag(flags, 'info', 'Page title is missing', 'A missing title can be a sign of a temporary or unfinished landing page.', 'HTML title element: not observed', 'Verify that the domain is linked from an official, established source.')
    return 'heuristic+http'
  } catch (error) {
    const message = error instanceof DOMException && error.name === 'TimeoutError' ? 'request timed out after 6.5 seconds' : 'request failed or was blocked'
    pushFlag(flags, 'warning', 'Website could not be verified', 'The server could not complete a safe public request to the target.', message, 'Do not interpret an unreachable site as safe; verify the domain independently.')
    return 'heuristic+http'
  }
}

export function detectTarget(raw: string): { kind: TargetKind; normalized: string; label: string } {
  const normalized = raw.trim().replace(/\s+/g, ' ')
  if (!normalized) return { kind: 'unknown', normalized, label: 'Empty input' }
  if (URL_RE.test(normalized) || /^[a-z][a-z\d+.-]*:\/\//i.test(normalized)) return { kind: 'website', normalized, label: 'Website URL' }
  if (ADDRESS_RE.test(normalized) || SOLANA_RE.test(normalized)) return { kind: 'address', normalized, label: 'Contract / wallet address' }
  return { kind: 'token', normalized, label: 'Token or project name' }
}

export async function analyzeTarget(raw: string, options: AnalyzeOptions = {}): Promise<Analysis> {
  const started = Date.now()
  const now = options.now ?? (() => new Date())
  const detected = detectTarget(raw)
  const flags: RiskFlag[] = []
  let source: Analysis['source'] = 'heuristic'
  if (!detected.normalized) {
    pushFlag(flags, 'critical', 'Nothing to analyze', 'Paste a token name, contract address, or website URL to start a screening.', 'Input was empty', 'Enter a value above and run the scan again.')
  } else if (detected.kind === 'token') analyzeToken(detected.normalized, flags)
  else if (detected.kind === 'address') analyzeAddress(detected.normalized, flags)
  else source = await analyzeWebsite(detected.normalized, flags, options.fetcher)
  const score = scoreFlags(detected.kind, flags)
  const level = asRiskLevel(score)
  return {
    input: raw,
    normalized: detected.normalized,
    kind: detected.kind,
    label: detected.label,
    score,
    level,
    summary: summaryFor(level, detected.kind, flags),
    flags,
    checks: flags.length,
    source,
    checkedAt: now().toISOString(),
    latencyMs: Math.max(1, Date.now() - started),
    limitations: [
      'Heuristics are a first pass, not a security audit or financial advice.',
      'No ownership, liquidity, holder, proxy, tax, blacklist, or transaction simulation data is claimed without a configured chain provider.',
      'Always verify the official domain and contract on an independent explorer before signing.',
    ],
  }
}

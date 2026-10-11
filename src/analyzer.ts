import { isValidChainId } from './chains'

export type TargetKind = 'token' | 'address' | 'website' | 'unknown'
export type RiskLevel = 'Low' | 'Medium' | 'High'
export type FlagSeverity = 'critical' | 'warning' | 'positive' | 'info'
export type IntelStatus = 'live' | 'partial' | 'unavailable'
export type IntelRisk = 'Low' | 'Medium' | 'High' | 'Unknown'

export interface RiskFlag {
  severity: FlagSeverity
  title: string
  detail: string
  evidence: string
  action: string
}

export interface ThreatIntelConfig {
  chainId: string
  goPlusAccessToken?: string
  etherscanApiKey?: string
  fetcher?: typeof fetch
}

export interface ThreatIntelSnapshot {
  status: IntelStatus
  chainId: string
  providers: string[]
  developerRisk: IntelRisk
  rugPullRisk: IntelRisk
  tokenSecurityFound: boolean
  contractVerified?: boolean
  creatorAddress?: string
  creatorPercent?: number
  ownerPercent?: number
  holderCount?: number
  liquidityUsd?: number
  unlockedLiquidityPercent?: number
  buyTaxPercent?: number
  sellTaxPercent?: number
  checkedAt: string
}

export interface Analysis {
  input: string
  normalized: string
  kind: TargetKind
  label: string
  chainId?: string
  score: number
  level: RiskLevel
  summary: string
  flags: RiskFlag[]
  checks: number
  source: 'heuristic' | 'heuristic+http' | 'live-intel' | 'live-intel+http'
  threatIntel?: ThreatIntelSnapshot
  checkedAt: string
  latencyMs: number
  limitations: string[]
}

export interface AnalyzeOptions {
  fetcher?: typeof fetch
  now?: () => Date
  chainId?: string
  threatIntel?: ThreatIntelConfig
}

type JsonRecord = Record<string, unknown>

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/
const SOLANA_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/
const URL_RE = /^https?:\/\//i
const SUSPICIOUS_NAME_RE = /(airdrop|claim|presale|100x|guaranteed|free|mint|bonus|profit|yield)/i
const SUSPICIOUS_PAGE_RE = /(seed phrase|secret phrase|private key|connect wallet|100x|guaranteed returns|claim now|send funds)/i
const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'click', 'top', 'support', 'quest', 'live', 'buzz', 'gq', 'country'])

const asRiskLevel = (score: number): RiskLevel => score <= 28 ? 'Low' : score <= 58 ? 'Medium' : 'High'
const asIntelRisk = (score: number): IntelRisk => score >= 60 ? 'High' : score >= 25 ? 'Medium' : 'Low'

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

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' || typeof value === 'number' ? String(value) : undefined
}

function numericValue(value: unknown): number | undefined {
  const parsed = typeof value === 'number' ? value : typeof value === 'string' && value.trim() !== '' ? Number(value) : NaN
  return Number.isFinite(parsed) ? parsed : undefined
}

function truthySignal(value: unknown): boolean {
  return value === '1' || value === 1 || value === true
}

function fractionToPercent(value: unknown): number | undefined {
  const parsed = numericValue(value)
  if (parsed === undefined) return undefined
  return Math.round((parsed <= 1 ? parsed * 100 : parsed) * 100) / 100
}

function formatPercent(value: number | undefined): string {
  return value === undefined ? 'unknown' : `${value.toFixed(value % 1 === 0 ? 0 : 1)}%`
}

function findGoPlusResult(payload: unknown, address: string): JsonRecord | undefined {
  if (!isRecord(payload)) return undefined
  const result = payload.result
  if (!isRecord(result)) return undefined
  const lower = address.toLowerCase()
  const keyed = Object.entries(result).find(([key]) => key.toLowerCase() === lower)?.[1]
  if (isRecord(keyed)) return keyed
  if (Object.keys(result).some(key => key.startsWith('is_') || key.endsWith('_tax') || key.includes('owner'))) return result
  return undefined
}

function findGoPlusArrayResult(payload: unknown, address: string): JsonRecord | undefined {
  if (!isRecord(payload)) return undefined
  const result = payload.result
  if (!isRecord(result)) return undefined
  const lower = address.toLowerCase()
  const keyed = Object.entries(result).find(([key]) => key.toLowerCase() === lower)?.[1]
  if (isRecord(keyed)) return keyed
  return result
}

function riskFlagForBinary(flags: RiskFlag[], value: unknown, title: string, detail: string, action: string, severity: FlagSeverity = 'warning'): void {
  if (truthySignal(value)) pushFlag(flags, severity, title, detail, 'GoPlus live signal: 1 / true', action)
}

async function getJson(fetcher: typeof fetch, url: string, headers: Record<string, string> = {}): Promise<unknown> {
  const response = await fetcher(url, { method: 'GET', headers: { accept: 'application/json', ...headers }, signal: AbortSignal.timeout(7500) })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

function inspectGoPlusToken(data: JsonRecord, flags: RiskFlag[]): { snapshot: Partial<ThreatIntelSnapshot>; risk: number; rugRisk: number } {
  let risk = 0
  let rugRisk = 0
  const snapshot: Partial<ThreatIntelSnapshot> = { tokenSecurityFound: true }
  if (truthySignal(data.is_honeypot)) { pushFlag(flags, 'critical', 'Honeypot behavior detected', 'GoPlus reports that the token may block selling or contain malicious trading logic.', 'GoPlus is_honeypot: 1', 'Do not buy, approve, or connect a wallet to this token.'); risk += 70; rugRisk += 55 }
  if (truthySignal(data.cannot_buy)) { pushFlag(flags, 'critical', 'Token cannot be bought', 'The live simulation reports that this token cannot be bought normally.', 'GoPlus cannot_buy: 1', 'Do not route a swap through this token.'); risk += 55 }
  if (truthySignal(data.cannot_sell_all)) { pushFlag(flags, 'critical', 'Selling is restricted', 'The contract may prevent holders from selling their full position.', 'GoPlus cannot_sell_all: 1', 'Treat the token as a potential honeypot and avoid approvals.'); risk += 55; rugRisk += 30 }
  const buyTax = fractionToPercent(data.buy_tax)
  const sellTax = fractionToPercent(data.sell_tax)
  snapshot.buyTaxPercent = buyTax
  snapshot.sellTaxPercent = sellTax
  if (buyTax !== undefined && buyTax >= 50) { pushFlag(flags, 'critical', 'Extreme buy tax', `The live buy tax is ${formatPercent(buyTax)}, which can make a purchase uneconomical or impossible.`, `GoPlus buy_tax: ${String(data.buy_tax)}`, 'Do not trade unless the tax is independently expected and verified.'); risk += 45 }
  else if (buyTax !== undefined && buyTax >= 10) { pushFlag(flags, 'warning', 'High buy tax', `The live buy tax is ${formatPercent(buyTax)}.`, `GoPlus buy_tax: ${String(data.buy_tax)}`, 'Check the exact received amount and verify the project documentation.'); risk += 20 }
  if (sellTax !== undefined && sellTax >= 50) { pushFlag(flags, 'critical', 'Extreme sell tax', `The live sell tax is ${formatPercent(sellTax)}, which can trap value in the contract.`, `GoPlus sell_tax: ${String(data.sell_tax)}`, 'Do not buy this token.'); risk += 55; rugRisk += 35 }
  else if (sellTax !== undefined && sellTax >= 10) { pushFlag(flags, 'warning', 'High sell tax', `The live sell tax is ${formatPercent(sellTax)}.`, `GoPlus sell_tax: ${String(data.sell_tax)}`, 'Confirm the tax is intentional and stable before considering any trade.'); risk += 20; rugRisk += 10 }
  if (data.is_open_source !== undefined && !truthySignal(data.is_open_source)) { pushFlag(flags, 'warning', 'Contract source is not verified', 'GoPlus reports that the token contract is closed source or not verified, limiting independent review.', `GoPlus is_open_source: ${String(data.is_open_source)}`, 'Prefer a verified contract and inspect it on an independent explorer.'); risk += 24; rugRisk += 15 }
  if (truthySignal(data.is_proxy)) { pushFlag(flags, 'warning', 'Proxy contract detected', 'The implementation may be upgradeable by an administrator, so behavior can change after launch.', 'GoPlus is_proxy: 1', 'Identify the proxy admin and verify its permissions before signing.'); risk += 16; rugRisk += 20 }
  riskFlagForBinary(flags, data.hidden_owner, 'Hidden owner signal', 'GoPlus found evidence that ownership may remain controllable after apparent renouncement.', 'Review ownership and admin privileges on-chain before interacting.', 'critical'); if (truthySignal(data.hidden_owner)) { risk += 35; rugRisk += 45 }
  riskFlagForBinary(flags, data.can_take_back_ownership, 'Ownership can be reclaimed', 'The developer may be able to reclaim ownership and restore privileged controls.', 'Confirm ownership is permanently renounced using independent transaction history.', 'critical'); if (truthySignal(data.can_take_back_ownership)) { risk += 35; rugRisk += 45 }
  riskFlagForBinary(flags, data.owner_change_balance, 'Owner can change balances', 'The owner may be able to alter holder balances, creating a direct dump or confiscation risk.', 'Do not buy while this privilege exists.', 'critical'); if (truthySignal(data.owner_change_balance)) { risk += 50; rugRisk += 60 }
  riskFlagForBinary(flags, data.is_mintable, 'Mint function detected', 'The contract can potentially create new tokens and dilute or dump against holders.', 'Confirm the mint authority, cap, and whether it is permanently disabled.', 'warning'); if (truthySignal(data.is_mintable)) { risk += 18; rugRisk += 25 }
  riskFlagForBinary(flags, data.slippage_modifiable, 'Tax is modifiable', 'An owner-controlled tax can be raised after users enter the token.', 'Verify the setter permissions and current limits.', 'warning'); if (truthySignal(data.slippage_modifiable)) { risk += 24; rugRisk += 25 }
  riskFlagForBinary(flags, data.personal_slippage_modifiable, 'Per-wallet tax is modifiable', 'The owner may assign punitive tax rates to selected addresses.', 'Avoid signing until this privilege is removed or proven safe.', 'warning'); if (truthySignal(data.personal_slippage_modifiable)) { risk += 28; rugRisk += 30 }
  riskFlagForBinary(flags, data.transfer_pausable, 'Transfers can be paused', 'An administrator may be able to suspend transfers or selling.', 'Confirm who can pause transfers and whether the role is timelocked or renounced.', 'warning'); if (truthySignal(data.transfer_pausable)) { risk += 18; rugRisk += 20 }
  riskFlagForBinary(flags, data.is_blacklisted, 'Blacklist capability detected', 'The contract may block selected addresses from trading.', 'Review blacklist authority and current blacklist state.', 'warning'); if (truthySignal(data.is_blacklisted)) { risk += 18; rugRisk += 18 }
  riskFlagForBinary(flags, data.is_whitelisted, 'Whitelist capability detected', 'Some addresses may receive privileged trading conditions or bypass restrictions.', 'Review whitelist authority and distribution before trading.', 'warning'); if (truthySignal(data.is_whitelisted)) { risk += 10; rugRisk += 10 }
  const creatorPercent = fractionToPercent(data.creator_percent)
  const ownerPercent = fractionToPercent(data.owner_percent)
  snapshot.creatorPercent = creatorPercent
  snapshot.ownerPercent = ownerPercent
  if (creatorPercent !== undefined || ownerPercent !== undefined) {
    const largest = Math.max(creatorPercent ?? 0, ownerPercent ?? 0)
    if (largest >= 50) { pushFlag(flags, 'critical', 'Developer concentration is extreme', `The creator/owner controls approximately ${formatPercent(largest)} of token supply according to the live feed.`, `GoPlus creator_percent: ${formatPercent(creatorPercent)} · owner_percent: ${formatPercent(ownerPercent)}`, 'Treat a developer sell-off as a credible rug-pull scenario; do not buy without a verified lock or vesting plan.'); risk += 45; rugRisk += 60 }
    else if (largest >= 10) { pushFlag(flags, 'warning', 'Developer concentration is elevated', `The creator/owner controls approximately ${formatPercent(largest)} of token supply according to the live feed.`, `GoPlus creator_percent: ${formatPercent(creatorPercent)} · owner_percent: ${formatPercent(ownerPercent)}`, 'Check vesting, lockups, and the developer wallet’s transfer history before interacting.'); risk += 22; rugRisk += 35 }
    else pushFlag(flags, 'positive', 'Developer concentration is not elevated', `The live feed reports creator/owner exposure below 10% of supply.`, `GoPlus creator_percent: ${formatPercent(creatorPercent)} · owner_percent: ${formatPercent(ownerPercent)}`, 'Still inspect liquidity locks and contract privileges.')
  }
  const holderCount = numericValue(data.holder_count)
  if (holderCount !== undefined) snapshot.holderCount = holderCount
  const dex = Array.isArray(data.dex) ? data.dex : []
  const liquidity = dex.reduce((sum, item) => sum + (isRecord(item) ? (numericValue(item.liquidity) ?? 0) : 0), 0)
  if (liquidity > 0) snapshot.liquidityUsd = Math.round(liquidity)
  const lpHolders = Array.isArray(data.lp_holders) ? data.lp_holders.filter(isRecord) : []
  const unlockedLiquidity = lpHolders.reduce((sum, holder) => truthySignal(holder.is_locked) ? sum : sum + (fractionToPercent(holder.percent) ?? 0), 0)
  if (lpHolders.length) snapshot.unlockedLiquidityPercent = Math.round(unlockedLiquidity * 100) / 100
  if (unlockedLiquidity >= 50) { pushFlag(flags, 'critical', 'Liquidity is largely unlocked', `The live LP-holder snapshot shows approximately ${formatPercent(unlockedLiquidity)} unlocked liquidity.`, `GoPlus LP holders unlocked: ${formatPercent(unlockedLiquidity)}`, 'Treat liquidity removal as a credible rug-pull path; look for a verifiable lock or burn.'); risk += 38; rugRisk += 60 }
  else if (unlockedLiquidity >= 20) { pushFlag(flags, 'warning', 'Liquidity lock coverage is limited', `The live LP-holder snapshot shows approximately ${formatPercent(unlockedLiquidity)} unlocked liquidity.`, `GoPlus LP holders unlocked: ${formatPercent(unlockedLiquidity)}`, 'Verify the lock contract, expiry, and controller before trading.'); risk += 20; rugRisk += 35 }
  const otherRisk = stringValue(data.other_potential_risks)
  if (otherRisk) { pushFlag(flags, 'warning', 'GoPlus reported an additional risk', otherRisk, 'GoPlus other_potential_risks', 'Read the specific contract permission and verify it independently.'); risk += 20; rugRisk += 20 }
  return { snapshot, risk: Math.min(100, risk), rugRisk: Math.min(100, rugRisk) }
}

async function fetchThreatIntel(address: string, config: ThreatIntelConfig, flags: RiskFlag[], now: () => Date): Promise<ThreatIntelSnapshot> {
  const fetcher = config.fetcher ?? fetch
  const chainId = isValidChainId(config.chainId) ? config.chainId : '1'
  const providers: string[] = []
  let goPlusData: JsonRecord | undefined
  let goPlusRugData: JsonRecord | undefined
  let etherscanSource: JsonRecord | undefined
  let etherscanCreator: JsonRecord | undefined
  const goHeaders: Record<string, string> = config.goPlusAccessToken ? { Authorization: `Bearer ${config.goPlusAccessToken}` } : {}
  const tasks: Promise<void>[] = [
    getJson(fetcher, `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${encodeURIComponent(address)}`, goHeaders).then(payload => { goPlusData = findGoPlusResult(payload, address); if (goPlusData) providers.push('GoPlus Token Security') }).catch(() => undefined),
    getJson(fetcher, `https://api.gopluslabs.io/api/v1/rugpull_detecting/${chainId}?contract_addresses=${encodeURIComponent(address)}`, goHeaders).then(payload => { goPlusRugData = findGoPlusArrayResult(payload, address); if (goPlusRugData) providers.push('GoPlus Rug Pull Beta') }).catch(() => undefined),
  ]
  if (config.etherscanApiKey) {
    const base = 'https://api.etherscan.io/v2/api'
    const sourceUrl = `${base}?chainid=${chainId}&module=contract&action=getsourcecode&address=${encodeURIComponent(address)}&apikey=${encodeURIComponent(config.etherscanApiKey)}`
    const creatorUrl = `${base}?chainid=${chainId}&module=contract&action=getcontractcreation&contractaddresses=${encodeURIComponent(address)}&apikey=${encodeURIComponent(config.etherscanApiKey)}`
    tasks.push(getJson(fetcher, sourceUrl).then(payload => { const record = isRecord(payload) && Array.isArray(payload.result) && isRecord(payload.result[0]) ? payload.result[0] : undefined; if (record) { etherscanSource = record; providers.push('Etherscan Source') } }).catch(() => undefined))
    tasks.push(getJson(fetcher, creatorUrl).then(payload => { const record = isRecord(payload) && Array.isArray(payload.result) && isRecord(payload.result[0]) ? payload.result[0] : undefined; if (record) { etherscanCreator = record; providers.push('Etherscan Creator') } }).catch(() => undefined))
  }
  await Promise.all(tasks)
  const riskFlagsBefore = flags.length
  let risk = 0
  let rugRisk = 0
  const snapshot: ThreatIntelSnapshot = { status: providers.length >= 2 ? 'live' : providers.length ? 'partial' : 'unavailable', chainId, providers, developerRisk: 'Unknown', rugPullRisk: 'Unknown', tokenSecurityFound: Boolean(goPlusData), checkedAt: now().toISOString() }
  if (goPlusData) {
    const inspected = inspectGoPlusToken(goPlusData, flags)
    Object.assign(snapshot, inspected.snapshot)
    risk += inspected.risk
    rugRisk += inspected.rugRisk
  }
  if (goPlusRugData) {
    const riskValue = stringValue(goPlusRugData.risk) ?? stringValue(goPlusRugData.risk_level) ?? stringValue(goPlusRugData.is_rug_pull)
    if (riskValue && /high|danger|1|true/i.test(riskValue)) { pushFlag(flags, 'critical', 'GoPlus rug-pull signal', `The GoPlus rug-pull beta feed returned: ${riskValue}.`, 'GoPlus Rug Pull Detection API Beta', 'Do not trade until liquidity ownership and developer wallet history are independently verified.'); risk += 45; rugRisk += 65 }
    else if (riskValue && /medium|warning/i.test(riskValue)) { pushFlag(flags, 'warning', 'GoPlus rug-pull caution', `The GoPlus rug-pull beta feed returned: ${riskValue}.`, 'GoPlus Rug Pull Detection API Beta', 'Check developer wallet activity and liquidity lock status before interacting.'); risk += 22; rugRisk += 35 }
  }
  if (etherscanSource) {
    const verified = Boolean(stringValue(etherscanSource.SourceCode)?.trim())
    snapshot.contractVerified = verified
    if (verified) pushFlag(flags, 'positive', 'Etherscan source verified', 'Etherscan returned verified contract source for this chain and address.', `Contract: ${stringValue(etherscanSource.ContractName) ?? 'verified source'}`, 'Still review privileged roles and upgradeability; verified source is not a safety guarantee.')
    else { pushFlag(flags, 'warning', 'Etherscan source not verified', 'Etherscan did not return verified contract source for this address.', 'Etherscan SourceCode: empty', 'Prefer a verified contract before signing or trading.'); risk += 22; rugRisk += 15 }
    if (truthySignal(etherscanSource.Proxy)) { pushFlag(flags, 'warning', 'Etherscan proxy flag', 'Etherscan identifies this contract as a proxy, so implementation behavior may be changeable.', `Etherscan Proxy: ${String(etherscanSource.Proxy)}`, 'Identify the proxy admin and implementation contract.'); risk += 15; rugRisk += 20 }
  }
  if (etherscanCreator) {
    snapshot.creatorAddress = stringValue(etherscanCreator.contractCreator)
    if (snapshot.creatorAddress) pushFlag(flags, 'info', 'Developer wallet identified', 'Etherscan returned the contract creator address so its transaction history can be reviewed.', `Creator: ${snapshot.creatorAddress}`, 'Inspect transfers from the creator and linked wallets; an address alone does not prove intent.')
  }
  if (snapshot.creatorPercent !== undefined || snapshot.ownerPercent !== undefined) {
    const largest = Math.max(snapshot.creatorPercent ?? 0, snapshot.ownerPercent ?? 0)
    snapshot.developerRisk = asIntelRisk(largest >= 50 ? 80 : largest >= 10 ? 40 : 10)
  } else if (rugRisk >= 45) snapshot.developerRisk = 'High'
  else if (riskFlagsBefore < flags.length && providers.length) snapshot.developerRisk = 'Medium'
  if (rugRisk >= 60) snapshot.rugPullRisk = 'High'
  else if (rugRisk >= 25) snapshot.rugPullRisk = 'Medium'
  else if (providers.length) snapshot.rugPullRisk = 'Low'
  if (providers.length) pushFlag(flags, 'positive', 'Live threat intelligence attached', `This report used ${providers.join(', ')} for chain ${chainId}.`, `Providers: ${providers.join(' · ')}`, 'Re-check before a transaction because token state and developer behavior can change.')
  else pushFlag(flags, 'info', 'Live threat intelligence unavailable', 'No configured provider returned data. The report remains heuristic-only.', 'GoPlus/Etherscan response unavailable or credentials not configured', 'Configure GOPLUS_ACCESS_TOKEN and/or ETHERSCAN_API_KEY on the server for live chain checks.')
  return snapshot
}

function analyzeToken(input: string, flags: RiskFlag[]): void {
  const compact = input.replace(/\s+/g, ' ').trim()
  if (SUSPICIOUS_NAME_RE.test(compact)) pushFlag(flags, 'warning', 'Hype-led wording detected', 'The name contains language commonly used by speculative promotions and urgency campaigns.', `Matched phrase in input: “${compact.slice(0, 80)}”`, 'Find the official contract address from a verified project channel before doing anything else.')
  else pushFlag(flags, 'info', 'Name-only lookup', 'A token name is not unique enough to identify one asset or contract.', 'No canonical address was supplied.', 'Use the exact contract address on the correct chain for a more useful review.')
  pushFlag(flags, 'warning', 'No on-chain permissions checked', 'This screen cannot verify owner powers, blacklist logic, transfer taxes, liquidity locks, holder concentration, or trading activity without a chain data provider.', 'Provider status: not configured', 'Review verified source code and independent on-chain data before connecting a wallet.')
}

async function analyzeAddress(input: string, flags: RiskFlag[], options: AnalyzeOptions, now: () => Date): Promise<ThreatIntelSnapshot | undefined> {
  const isEvm = ADDRESS_RE.test(input)
  const isSolana = SOLANA_RE.test(input) && !/^0x/i.test(input)
  if (!isEvm && !isSolana) {
    pushFlag(flags, 'critical', 'Address format not recognized', 'The value does not match a standard EVM or Solana-style address shape.', `Input length: ${input.length} characters`, 'Copy the address directly from a trusted chain explorer and check the selected network.')
    return undefined
  }
  pushFlag(flags, 'positive', `${isEvm ? 'EVM' : 'Solana'} address shape recognized`, 'The value matches a known public-address format. This only validates shape, not ownership or behavior.', `Pattern check passed for ${isEvm ? '0x + 40 hexadecimal characters' : 'base58 address'}`, 'Confirm the chain and contract page independently before signing.')
  if (isEvm) {
    const body = input.slice(2)
    if (/^(.)\1+$/.test(body)) pushFlag(flags, 'critical', 'Repeating-address pattern', 'The address is made from one repeated hexadecimal character and is unlikely to be a normal deployed contract.', `Address body pattern: ${body.slice(0, 8)}…`, 'Do not send funds; re-check the copied address.')
    if (input === '0x0000000000000000000000000000000000000000') pushFlag(flags, 'critical', 'Zero address', 'This is the canonical EVM zero address, which is not a normal destination for a token purchase.', 'Exact zero address match', 'Stop and confirm the address from the official project source.')
    if (input === input.toLowerCase() || input === input.toUpperCase()) pushFlag(flags, 'info', 'Checksum not present', 'All-lowercase and all-uppercase EVM addresses can still be valid, but checksum casing helps catch copy errors.', 'EIP-55 checksum casing was not supplied', 'Compare against an explorer and the project documentation.')
    if (options.threatIntel) return fetchThreatIntel(input, options.threatIntel, flags, now)
  }
  pushFlag(flags, 'warning', 'Behavior not inspected', 'An address alone cannot reveal contract source, proxy implementation, admin privileges, sell restrictions, taxes, liquidity, or holder distribution.', 'Chain provider status: not configured', 'Inspect verified source and simulation results before approving a transaction.')
  return undefined
}

async function analyzeWebsite(input: string, flags: RiskFlag[], fetcher?: typeof fetch): Promise<'heuristic' | 'heuristic+http'> {
  const url = isSafePublicUrl(input)
  if (!url) { pushFlag(flags, 'critical', 'URL is not a safe public URL', 'Only public http:// and https:// URLs are accepted for remote inspection.', 'Protocol or hostname validation failed', 'Use a complete public URL and never paste a wallet seed phrase or private key.'); return 'heuristic' }
  pushFlag(flags, 'positive', 'Public URL accepted', 'The URL uses a supported protocol and passed basic host safety checks.', `${url.protocol}//${url.hostname}`, 'Confirm this domain is the one published by the project you intend to use.')
  const tld = url.hostname.split('.').pop()?.toLowerCase()
  if (tld && SUSPICIOUS_TLDS.has(tld)) pushFlag(flags, 'warning', 'Higher-abuse TLD signal', 'This top-level domain is frequently used in disposable campaigns. It is not proof of fraud, but it deserves extra verification.', `Top-level domain: .${tld}`, 'Prefer a long-standing official domain linked from a trusted project account.')
  if (!fetcher) { pushFlag(flags, 'warning', 'Live reachability not checked', 'Local preview cannot safely fetch arbitrary websites from the browser, so HTTP headers and page content were not inspected.', 'Analysis mode: local heuristic fallback', 'Run this scan on the deployed app for server-side HTTP checks.'); return 'heuristic' }
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
  if (/^0x/i.test(normalized) || ADDRESS_RE.test(normalized) || SOLANA_RE.test(normalized)) return { kind: 'address', normalized, label: 'Contract / wallet address' }
  return { kind: 'token', normalized, label: 'Token or project name' }
}

export async function analyzeTarget(raw: string, options: AnalyzeOptions = {}): Promise<Analysis> {
  const started = Date.now()
  const now = options.now ?? (() => new Date())
  const detected = detectTarget(raw)
  const flags: RiskFlag[] = []
  let source: Analysis['source'] = 'heuristic'
  let threatIntel: ThreatIntelSnapshot | undefined
  let chainId: string | undefined = options.chainId ?? options.threatIntel?.chainId
  if (!detected.normalized) pushFlag(flags, 'critical', 'Nothing to analyze', 'Paste a token name, contract address, or website URL to start a screening.', 'Input was empty', 'Enter a value above and run the scan again.')
  else if (detected.kind === 'token') analyzeToken(detected.normalized, flags)
  else if (detected.kind === 'address') {
    threatIntel = await analyzeAddress(detected.normalized, flags, options, now)
    chainId = threatIntel?.chainId ?? chainId
    if (threatIntel && threatIntel.status !== 'unavailable') source = 'live-intel'
  } else source = await analyzeWebsite(detected.normalized, flags, options.fetcher)
  const score = scoreFlags(detected.kind, flags)
  const level = asRiskLevel(score)
  return {
    input: raw,
    normalized: detected.normalized,
    kind: detected.kind,
    label: detected.label,
    chainId,
    score,
    level,
    summary: summaryFor(level, detected.kind, flags),
    flags,
    checks: flags.length,
    source,
    threatIntel,
    checkedAt: now().toISOString(),
    latencyMs: Math.max(1, Date.now() - started),
    limitations: [
      'Heuristics and third-party feeds are a first pass, not a smart-contract audit or financial advice.',
      'Live feeds can be delayed, incomplete, or wrong; developer concentration does not prove malicious intent.',
      'Always simulate and verify the exact transaction, chain, contract, liquidity lock, and admin permissions before signing.',
    ],
  }
}

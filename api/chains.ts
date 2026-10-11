import { FALLBACK_CHAINS, mergeChains, type ChainDefinition } from '../src/chains.js'

type ResponseLike = { status: (code: number) => ResponseLike; json: (value: unknown) => void; setHeader?: (name: string, value: string) => void }

type EtherscanChain = { chainname?: string; chainid?: string; blockexplorer?: string; status?: number }

export default async function handler(_req: unknown, res: ResponseLike): Promise<void> {
  res.setHeader?.('Cache-Control', 's-maxage=3600, stale-while-revalidate=86400')
  res.setHeader?.('Access-Control-Allow-Origin', '*')
  const apiKey = process.env.ETHERSCAN_API_KEY
  if (!apiKey) {
    res.status(200).json({ source: 'curated-fallback', chains: FALLBACK_CHAINS })
    return
  }
  try {
    const response = await fetch(`https://api.etherscan.io/v2/chainlist?apikey=${encodeURIComponent(apiKey)}`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(6500) })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const payload = await response.json() as { result?: EtherscanChain[] }
    const remote: ChainDefinition[] = Array.isArray(payload.result)
      ? payload.result.filter(item => item.status === undefined || item.status === 1).map(item => ({ id: item.chainid ?? '', label: item.chainname ?? '', explorer: item.blockexplorer, status: item.status }))
      : []
    res.status(200).json({ source: 'etherscan-chainlist', chains: mergeChains(remote) })
  } catch {
    res.status(200).json({ source: 'curated-fallback', chains: FALLBACK_CHAINS })
  }
}

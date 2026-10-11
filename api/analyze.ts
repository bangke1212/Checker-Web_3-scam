import { analyzeTarget, type AnalyzeOptions } from '../src/analyzer.js'

type RequestLike = { method?: string; body?: unknown }
type ResponseLike = { status: (code: number) => ResponseLike; json: (value: unknown) => void; setHeader?: (name: string, value: string) => void }
const SUPPORTED_CHAIN_IDS = new Set(['1', '56', '137', '42161', '8453', '10', '43114', '250', '324', '59144', '5000', '534352'])

export default async function handler(req: RequestLike, res: ResponseLike): Promise<void> {
  res.setHeader?.('Cache-Control', 'no-store')
  res.setHeader?.('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') {
    res.status(204).json({})
    return
  }
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed. Use POST /api/analyze.' })
    return
  }
  let body: unknown = req.body
  if (typeof req.body === 'string') {
    try { body = JSON.parse(req.body) } catch { res.status(400).json({ error: 'Request body must be valid JSON.' }); return }
  }
  const input = body && typeof body === 'object' && 'input' in body && typeof body.input === 'string' ? body.input.trim() : ''
  const requestedChainId = body && typeof body === 'object' && 'chainId' in body && typeof body.chainId === 'string' ? body.chainId : ''
  const chainId = SUPPORTED_CHAIN_IDS.has(requestedChainId) ? requestedChainId : process.env.SCAMGUARD_CHAIN_ID && SUPPORTED_CHAIN_IDS.has(process.env.SCAMGUARD_CHAIN_ID) ? process.env.SCAMGUARD_CHAIN_ID : '1'
  if (!input || input.length > 300) {
    res.status(400).json({ error: 'Provide a non-empty input up to 300 characters.' })
    return
  }
  try {
    const analysisOptions: AnalyzeOptions = { fetcher: fetch }
    if (process.env.GOPLUS_ACCESS_TOKEN || process.env.ETHERSCAN_API_KEY) analysisOptions.threatIntel = { chainId, goPlusAccessToken: process.env.GOPLUS_ACCESS_TOKEN, etherscanApiKey: process.env.ETHERSCAN_API_KEY, fetcher: fetch }
    const result = await analyzeTarget(input, analysisOptions)
    res.status(200).json(result)
  } catch {
    res.status(500).json({ error: 'Analysis failed safely. Try again with a public URL, token name, or address.' })
  }
}

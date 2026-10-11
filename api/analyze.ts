import { analyzeTarget } from '../src/analyzer'

type RequestLike = { method?: string; body?: unknown }
type ResponseLike = { status: (code: number) => ResponseLike; json: (value: unknown) => void; setHeader?: (name: string, value: string) => void }

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
  if (!input || input.length > 300) {
    res.status(400).json({ error: 'Provide a non-empty input up to 300 characters.' })
    return
  }
  try {
    const result = await analyzeTarget(input, { fetcher: fetch })
    res.status(200).json(result)
  } catch {
    res.status(500).json({ error: 'Analysis failed safely. Try again with a public URL, token name, or address.' })
  }
}

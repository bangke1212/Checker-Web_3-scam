import { describe, expect, it } from 'vitest'
import handler from '../api/analyze'
import chainsHandler from '../api/chains'

type TestResponse = { code?: number; value?: unknown; status: (code: number) => TestResponse; json: (value: unknown) => void; setHeader: () => void }
const response = (): TestResponse => ({ status(code) { this.code = code; return this }, json(value) { this.value = value }, setHeader() {} })

describe('POST /api/analyze', () => {
  it('rejects unsupported methods', async () => {
    const res = response()
    await handler({ method: 'GET' }, res)
    expect(res.code).toBe(405)
  })

  it('rejects malformed JSON bodies', async () => {
    const res = response()
    await handler({ method: 'POST', body: '{' }, res)
    expect(res.code).toBe(400)
  })

  it('returns a structured heuristic result', async () => {
    const res = response()
    await handler({ method: 'POST', body: { input: '0x0000000000000000000000000000000000000000' } }, res)
    const value = res.value as { level: string; kind: string; flags: unknown[] }
    expect(res.code).toBe(200)
    expect(value.kind).toBe('address')
    expect(value.level).toBe('High')
    expect(value.flags.length).toBeGreaterThan(0)
  })
})

describe('GET /api/chains', () => {
  it('returns a chain registry with Robinhood fallback', async () => {
    const res = response()
    await chainsHandler({}, res)
    const value = res.value as { chains: Array<{ id: string; label: string }> }
    expect(res.code).toBe(200)
    expect(value.chains.some(chain => chain.id === '4663' && chain.label === 'Robinhood Chain')).toBe(true)
  })
})

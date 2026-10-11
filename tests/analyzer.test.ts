import { describe, expect, it } from 'vitest'
import { analyzeTarget, detectTarget } from '../src/analyzer'

describe('detectTarget', () => {
  it('classifies public URLs', () => expect(detectTarget('https://example.com').kind).toBe('website'))
  it('classifies EVM addresses', () => expect(detectTarget('0x0000000000000000000000000000000000000000').kind).toBe('address'))
  it('keeps names as token inputs', () => expect(detectTarget('Moon Airdrop').kind).toBe('token'))
})

describe('analyzeTarget', () => {
  it('flags an empty input', async () => {
    const result = await analyzeTarget('  ', { now: () => new Date('2026-10-12T00:00:00Z') })
    expect(result.level).toBe('High')
    expect(result.flags[0].title).toBe('Nothing to analyze')
  })

  it('flags the zero address as critical', async () => {
    const result = await analyzeTarget('0x0000000000000000000000000000000000000000')
    expect(result.kind).toBe('address')
    expect(result.flags.some(flag => flag.title === 'Zero address')).toBe(true)
    expect(result.level).toBe('High')
  })

  it('keeps name-only limitations explicit', async () => {
    const result = await analyzeTarget('Blue Harbor')
    expect(result.kind).toBe('token')
    expect(result.flags.some(flag => flag.title === 'Name-only lookup')).toBe(true)
    expect(result.flags.some(flag => flag.title === 'No on-chain permissions checked')).toBe(true)
  })

  it('reads safe website response headers and content', async () => {
    const fakeFetcher: typeof fetch = async () => {
      const response = new Response('<html><body>Connect wallet and enter your seed phrase</body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html' },
      })
      Object.defineProperty(response, 'url', { value: 'https://example.com' })
      return response
    }
    const result = await analyzeTarget('https://example.com', { fetcher: fakeFetcher })
    expect(result.source).toBe('heuristic+http')
    expect(result.flags.some(flag => flag.title === 'Sensitive-wallet language found')).toBe(true)
    expect(result.flags.some(flag => flag.title === 'HSTS header missing')).toBe(true)
  })

  it('rejects private website hosts without making a request', async () => {
    let called = false
    const result = await analyzeTarget('http://127.0.0.1:3000', { fetcher: async () => { called = true; return new Response() } })
    expect(called).toBe(false)
    expect(result.flags.some(flag => flag.title === 'URL is not a safe public URL')).toBe(true)
  })

  it('keeps unsupported protocols in the website validation path', async () => {
    const result = await analyzeTarget('ftp://example.com')
    expect(result.kind).toBe('website')
    expect(result.flags.some(flag => flag.title === 'URL is not a safe public URL')).toBe(true)
  })
})

import { describe, expect, it } from 'vitest'
import { analyzeTarget, detectTarget } from '../src/analyzer'

describe('detectTarget', () => {
  it('classifies public URLs', () => expect(detectTarget('https://example.com').kind).toBe('website'))
  it('classifies EVM addresses', () => expect(detectTarget('0x0000000000000000000000000000000000000000').kind).toBe('address'))
  it('keeps malformed 0x values in address validation', () => expect(detectTarget('0xd17b7e4aab4b34e04632acf85ca4a969cd800ce').kind).toBe('address'))
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

  it('does not silently repair an invalid address', async () => {
    const result = await analyzeTarget('0xd17b7e4aab4b34e04632acf85ca4a969cd800ce', { chainId: '4663' })
    expect(result.chainId).toBe('4663')
    expect(result.flags.some(flag => flag.title === 'Address format not recognized')).toBe(true)
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

  it('merges live GoPlus and Etherscan signals into rug-pull scoring', async () => {
    const address = '0x1111111111111111111111111111111111111111'
    const fakeFetcher: typeof fetch = async (request) => {
      const url = new URL(String(request))
      const action = url.searchParams.get('action')
      if (url.hostname === 'api.gopluslabs.io' && url.pathname.includes('token_security')) {
        return new Response(JSON.stringify({ result: { [address.toLowerCase()]: { is_honeypot: '1', creator_percent: '0.6', owner_percent: '0.6', sell_tax: '0.8', is_open_source: '0', can_take_back_ownership: '1' } } }), { status: 200 })
      }
      if (url.hostname === 'api.gopluslabs.io' && url.pathname.includes('rugpull_detecting')) {
        return new Response(JSON.stringify({ result: { [address.toLowerCase()]: { is_rug_pull: '1' } } }), { status: 200 })
      }
      if (action === 'getsourcecode') return new Response(JSON.stringify({ status: '1', result: [{ SourceCode: 'contract Safe {}', ContractName: 'Safe' }] }), { status: 200 })
      if (action === 'getcontractcreation') return new Response(JSON.stringify({ status: '1', result: [{ contractCreator: '0x2222222222222222222222222222222222222222' }] }), { status: 200 })
      return new Response('{}', { status: 404 })
    }
    const result = await analyzeTarget(address, { threatIntel: { chainId: '1', goPlusAccessToken: 'test', etherscanApiKey: 'test', fetcher: fakeFetcher } })
    expect(result.source).toBe('live-intel')
    expect(result.threatIntel?.providers).toContain('GoPlus Token Security')
    expect(result.threatIntel?.rugPullRisk).toBe('High')
    expect(result.flags.some(flag => flag.title === 'Honeypot behavior detected')).toBe(true)
    expect(result.flags.some(flag => flag.title === 'Developer concentration is extreme')).toBe(true)
    expect(result.flags.some(flag => flag.title === 'GoPlus rug-pull signal')).toBe(true)
    expect(result.level).toBe('High')
  })
})

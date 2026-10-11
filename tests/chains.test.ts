import { describe, expect, it } from 'vitest'
import { FALLBACK_CHAINS, isValidChainId, mergeChains } from '../src/chains'

describe('chain registry', () => {
  it('includes Robinhood mainnet and testnet', () => {
    expect(FALLBACK_CHAINS.find(chain => chain.id === '4663')?.label).toBe('Robinhood Chain')
    expect(FALLBACK_CHAINS.find(chain => chain.id === '46630')?.label).toContain('Testnet')
  })

  it('validates numeric EVM chain IDs without a hard-coded allowlist', () => {
    expect(isValidChainId('4663')).toBe(true)
    expect(isValidChainId('999999999999')).toBe(true)
    expect(isValidChainId('not-a-chain')).toBe(false)
  })

  it('merges remote Etherscan chains with curated fallback', () => {
    const chains = mergeChains([{ id: '999', label: 'Example Chain', explorer: 'https://example.invalid' }])
    expect(chains.some(chain => chain.id === '999')).toBe(true)
    expect(chains.some(chain => chain.id === '4663')).toBe(true)
  })
})

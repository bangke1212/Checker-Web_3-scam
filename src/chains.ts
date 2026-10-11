export interface ChainDefinition {
  id: string
  label: string
  explorer?: string
  status?: number
}

// Fallback keeps the selector useful even when Etherscan's chainlist is not configured.
// The API can merge the full official Etherscan V2 chainlist at runtime.
export const FALLBACK_CHAINS: ChainDefinition[] = [
  { id: '1', label: 'Ethereum', explorer: 'https://etherscan.io' },
  { id: '56', label: 'BNB Chain', explorer: 'https://bscscan.com' },
  { id: '137', label: 'Polygon', explorer: 'https://polygonscan.com' },
  { id: '42161', label: 'Arbitrum One', explorer: 'https://arbiscan.io' },
  { id: '8453', label: 'Base', explorer: 'https://basescan.org' },
  { id: '10', label: 'Optimism', explorer: 'https://optimistic.etherscan.io' },
  { id: '43114', label: 'Avalanche C-Chain', explorer: 'https://snowtrace.io' },
  { id: '250', label: 'Fantom', explorer: 'https://ftmscan.com' },
  { id: '100', label: 'Gnosis', explorer: 'https://gnosisscan.io' },
  { id: '25', label: 'Cronos', explorer: 'https://cronoscan.com' },
  { id: '42220', label: 'Celo', explorer: 'https://celoscan.io' },
  { id: '1284', label: 'Moonbeam', explorer: 'https://moonbeam.moonscan.io' },
  { id: '1285', label: 'Moonriver', explorer: 'https://moonriver.moonscan.io' },
  { id: '1088', label: 'Metis', explorer: 'https://andromeda-explorer.metis.io' },
  { id: '324', label: 'zkSync Era', explorer: 'https://era.zksync.network' },
  { id: '59144', label: 'Linea', explorer: 'https://lineascan.build' },
  { id: '534352', label: 'Scroll', explorer: 'https://scrollscan.com' },
  { id: '5000', label: 'Mantle', explorer: 'https://mantlescan.xyz' },
  { id: '81457', label: 'Blast', explorer: 'https://blastscan.io' },
  { id: '7777777', label: 'Zora', explorer: 'https://explorer.zora.energy' },
  { id: '34443', label: 'Mode', explorer: 'https://explorer.mode.network' },
  { id: '80094', label: 'Berachain', explorer: 'https://berascan.com' },
  { id: '204', label: 'opBNB', explorer: 'https://opbnbscan.com' },
  { id: '59141', label: 'Linea Sepolia', explorer: 'https://sepolia.lineascan.build' },
  { id: '11155111', label: 'Sepolia', explorer: 'https://sepolia.etherscan.io' },
  { id: '4663', label: 'Robinhood Chain', explorer: 'https://robinhoodchain.blockscout.com' },
  { id: '46630', label: 'Robinhood Chain Testnet', explorer: 'https://explorer.testnet.chain.robinhood.com' },
]

export function isValidChainId(value: string): boolean {
  return /^\d{1,12}$/.test(value) && Number(value) > 0
}

export function mergeChains(remote: ChainDefinition[]): ChainDefinition[] {
  const byId = new Map<string, ChainDefinition>()
  for (const chain of [...FALLBACK_CHAINS, ...remote]) {
    if (isValidChainId(chain.id) && chain.label.trim()) byId.set(chain.id, { ...chain, id: String(chain.id) })
  }
  return [...byId.values()].sort((a, b) => a.label.localeCompare(b.label))
}

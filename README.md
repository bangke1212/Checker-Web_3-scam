# ScamGuard — Web3 Risk Intelligence

ScamGuard is a calm second opinion for token names, contract addresses, and public websites. It combines transparent heuristics with optional server-side HTTP metadata checks and clearly labels what it cannot prove.

## Run locally

```bash
pnpm install
pnpm dev
```

The local UI uses a transparent client-side fallback because Vite does not run the Vercel function. Production requests use `POST /api/analyze` with `{ "input": "...", "chainId": "4663" }`.

## All-chain registry and Robinhood Chain

The chain selector is now data-driven. `GET /api/chains` merges a curated fallback with the official Etherscan V2 chainlist when an Etherscan key is configured, so the UI can expose all Etherscan-supported EVM networks instead of a short hard-coded list. Robinhood Chain mainnet (`4663`) and testnet (`46630`) are included in the fallback registry, with the official Blockscout explorers.

Robinhood Chain uses chain ID `4663`. The tool accepts any numeric EVM chain ID and routes it to providers; a provider may still return no data when that chain is outside its coverage. This is labeled as partial/unavailable rather than treated as safe.

The supplied `0xd17b7e4aab4b34e04632acf85ca4a969cd800ce` example contains **39 hexadecimal characters after `0x`**, while an EVM address requires 40. ScamGuard now classifies it as an address and reports the format error without silently adding or removing a digit. Use the verified 40-character contract address for a live GOATONFONE analysis; the UI includes a name-only `GOATONFONE` preset on chain `4663` as a safe starting point.

## Live threat intelligence

The serverless API supports live EVM checks when these **server-only** environment variables are configured in Vercel:

```bash
GOPLUS_ACCESS_TOKEN=...
ETHERSCAN_API_KEY=...
SCAMGUARD_CHAIN_ID=1
```

GoPlus supplies token-security, honeypot, tax, owner privilege, creator concentration, liquidity-lock, and rug-pull beta signals. Etherscan adds verified-source, proxy, creator-wallet metadata, and the dynamic chain registry. The UI lets the user choose the chain; Ethereum (`1`) is the default. Keys are never sent to the browser.

The score is a conservative signal aggregation, not a verdict. A high developer/rug-pull signal can reflect concentrated ownership or unlocked liquidity without proving intent; users should still inspect the exact transaction and permissions.

## Validate and build

```bash
pnpm typecheck
pnpm test
pnpm build
pnpm smoke
```

## Deploy to Vercel

Import `bangke1212/Checker-Web_3-scam` into Vercel. Use the default Vite/Other framework detection, build command `pnpm build`, and output directory `dist`. The `api/analyze.ts` serverless function is included in the repository and performs safe public URL checks with a timeout.

This is an educational screening tool, not a smart-contract audit, investment recommendation, or guarantee of safety. Never paste a seed phrase or private key into any checker.

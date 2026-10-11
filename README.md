# ScamGuard — Web3 Risk Intelligence

ScamGuard is a calm second opinion for token names, contract addresses, and public websites. It combines transparent heuristics with optional server-side HTTP metadata checks and clearly labels what it cannot prove.

## Run locally

```bash
pnpm install
pnpm dev
```

The local UI uses a transparent client-side fallback because Vite does not run the Vercel function. Production requests use `POST /api/analyze` with `{ "input": "..." }`.

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

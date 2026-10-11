# ScamGuard — Implementation & Design Plan

## Product approach

ScamGuard is an educational Web3 risk-screening dashboard. Users submit a token name, contract address, or website URL. The frontend calls a Vercel serverless endpoint at `/api/analyze`; both layers share the same transparent heuristic engine so local preview remains useful without pretending to have live chain data. Website inputs are fetched server-side only when safely validated, with a short timeout and public-URL restrictions. The UI always labels the result as a screening signal, not a guarantee or financial advice.

## Design direction

- **Design movement:** security operations console meets a calm fintech audit report.
- **Core principles:** signal over decoration; show evidence beside conclusions; make uncertainty explicit; keep the next action obvious.
- **Color philosophy:** near-black background and deep navy cards create a serious audit surface; mint green is reserved for healthy signals and verified progress; danger red is used sparingly for actionable warnings.
- **Layout paradigm:** single-column scan-to-report flow with a persistent top bar and a results report that unfolds from the input card; desktop uses a narrow companion rail only after results exist.
- **Signature elements:** a green “signal rail” on cards, compact monospace evidence labels, and a radar-dot mark that turns the brand into a recognizable trust signal.
- **Interaction philosophy:** one primary action, preset examples to reduce friction, progressive disclosure for evidence, and no fear-based copy that outruns the data.
- **Animation:** short 160–220ms transitions; a scanning sweep during analysis; score ring fills once; warnings enter with a subtle vertical stagger; respect reduced-motion preferences.
- **Typography:** Inter/system sans for explanations and controls; Roboto Mono/monospace for addresses, timestamps, scores, and technical evidence.
- **Brand essence:** “A calm second opinion before you connect.” Personality: precise, candid, protective.
- **Brand voice:** direct and non-alarmist. Examples: “Start with the address, not the hype.” and “No signal is a guarantee. Verify before you sign.”
- **Wordmark & logo:** SCAMGUARD in a compact uppercase wordmark paired with a four-dot radar mark, suggesting detection without implying omniscience.
- **Signature brand color:** `#00C897`, used only for positive signals and the scan action.

## Implementation structure

- `src/analyzer.ts`: pure target detection, transparent heuristic scoring, and safe website signal extraction.
- `src/main.ts`: single-page UI, form state, local history, API request/fallback behavior, and results rendering.
- `src/styles.css`: responsive console-style visual system using the requested palette.
- `api/analyze.ts`: Vercel serverless POST endpoint with method/input validation and the shared analyzer.
- `tests/analyzer.test.ts`: deterministic checks for input classification, risk scoring, and website response parsing.
- `scripts/smoke.mjs`: browser smoke test for the scan flow and mobile layout.
- `vercel.json`: SPA fallback plus serverless API routing defaults.
- `public/manus-routes.json`: declared page route manifest.

## Technical constraints

- No database or credentials are required for the baseline product.
- No live blockchain claim is made unless a configured public fetch actually provides a signal; current scope is deterministic screening heuristics and website HTTP metadata.
- User input is escaped before rendering.
- Website fetches reject non-HTTP(S), loopback, private, link-local, and metadata hostnames; response reads are bounded.

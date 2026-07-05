# Break It Before Users Do — MultiHopper Agentic Flow: Bugs & Fixes

A black-box security assessment of the **MultiHopper** agentic flow on **devnet**
(`https://devnet.multihopper.com`), submitted for the Superteam Earn bounty
*"Break It Before Users Do."* Every finding ships with a self-contained,
re-runnable proof-of-concept.

- **Full write-up:** [`report/findings.md`](report/findings.md)
- **How the flow works & what was probed:** [`report/agentic-flow-analysis.md`](report/agentic-flow-analysis.md)
- **PoCs:** [`pocs/`](pocs/)

## Findings

| ID | Severity | Title | PoC |
|----|----------|-------|-----|
| **F-01** | **High** | Protocol fee tier is set from an unvalidated client `tokenPriceUsd` → ~10× fee bypass (even for SOL) | `pocs/01-fee-tier-bypass.mjs` |
| **F-02** | **High** | Webhook registration has no URL scheme/host validation → SSRF (cloud metadata, loopback, `gopher://`, `file://`) | `pocs/02-webhook-ssrf.mjs` |
| **F-03** | **Medium** | Working API credentials issued for an integration that never completed on-chain registration | `pocs/03-apikey-without-onchain-registration.mjs` |
| **F-04** | **Medium** | `amountRaw` has no u64 upper bound → HTTP 500 leaking internal SQL/schema | `pocs/04-amountraw-u64-overflow-and-schema-leak.mjs` |
| **F-05** | **Low** | Sign-In-With-Solana challenge is not phishing-resistant (no domain/address binding) | `pocs/05-siws-message-not-phishing-resistant.mjs` |

Plus four lower-severity observations (O-1…O-4) and a list of controls that were
tested and found **solid** — see `report/findings.md`.

## Scope & ethics

- **Devnet only** (`devnet.multihopper.com`), free devnet SOL, non-custodial.
- **API-layer only** — no value-moving transfer transactions were signed or
  broadcast. Findings are demonstrated up to the request/response and
  quote-creation layer.
- **No DoS / no flooding** — documented rate limits were respected (rate limiting
  itself was verified working, not stressed).
- Only test-owned data was manipulated; all test webhooks created during probing
  were deleted. No other integrator's data was accessed.

## Running the PoCs

Requires Node 18+ (uses native `fetch`).

```bash
cd pocs
npm install
```

Each PoC prints its request/response evidence and a `VULNERABLE / OK` verdict, and
exits `0` when the finding reproduces. Provide a devnet key, or let the PoC
self-provision one:

```bash
# Option A — use your own devnet key from https://devnet.multihopper.com/developer/dashboard
MH_API_KEY=mh_test_xxx node 01-fee-tier-bypass.mjs

# Option B — no key: the PoC self-provisions a devnet key (no SOL needed; this is
# exactly F-03, the onboarding-gate bypass, used as the bootstrap)
node 01-fee-tier-bypass.mjs

# Option C — drive auth with a specific wallet
MH_WALLET_SECRET='[1,2,3,...]'  node 03-apikey-without-onchain-registration.mjs   # JSON array
MH_WALLET_SECRET='base64secret' node 05-siws-message-not-phishing-resistant.mjs   # or base64
```

Run everything:

```bash
for f in pocs/0*.mjs; do echo "== $f =="; node "$f"; echo; done
```

`pocs/_lib.mjs` is the shared client (tRPC + REST helpers, SIWS auth, key
provisioning). `.env.example` documents the env vars. Captured raw evidence is in
[`evidence/`](evidence/).

## Repo layout

```
README.md
report/
  findings.md                 # detailed findings: severity, repro, impact, root cause, fix
  agentic-flow-analysis.md    # flow + invariant map that guided the hunt
pocs/
  _lib.mjs                    # shared tRPC/REST client, SIWS auth, key provisioning
  01..05-*.mjs                # one runnable reproducer per finding
  package.json
evidence/
  u64-overflow-500.json       # raw 500 response leaking SQL/schema (F-04)
.env.example
```

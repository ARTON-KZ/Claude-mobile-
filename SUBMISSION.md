# Bounty Submission — Break It Before Users Do: MultiHopper Agentic Flow

**What this is:** a black-box security assessment of the MultiHopper agentic flow on
**devnet**, with **5 reproducible findings**, root-cause analysis, and concrete fixes.
**Scope:** API-layer only — no value-moving transfers were signed or broadcast; devnet
only; all test data (webhooks) cleaned up.

- **Repo:** https://github.com/ARTON-KZ/Claude-mobile-
- **PR (full diff):** https://github.com/ARTON-KZ/Claude-mobile-/pull/1
- **Detailed write-up:** [`report/findings.md`](report/findings.md) · **Flow analysis:** [`report/agentic-flow-analysis.md`](report/agentic-flow-analysis.md) · **PoCs:** [`pocs/`](pocs/)

## Findings at a glance

| ID | Sev | Finding | Impact | PoC |
|----|-----|---------|--------|-----|
| **F-01** | **High** | Fee tier derived from unvalidated client `tokenPriceUsd` | ~10× protocol-fee underpayment on any transfer — **incl. native SOL** despite documented oracle pricing | `pocs/01-fee-tier-bypass.mjs` |
| **F-02** | **High** | Webhook registration has no URL scheme/host validation | SSRF to cloud metadata (`169.254.169.254`), loopback, RFC1918; `gopher://` / `file://` accepted | `pocs/02-webhook-ssrf.mjs` |
| **F-03** | **Medium** | API key issued for an integration that never completed on-chain registration | `status:active` + working key while `providerStatus≠registered`; onboarding/economic gate bypass | `pocs/03-apikey-without-onchain-registration.mjs` |
| **F-04** | **Medium** | `amountRaw` has no u64 upper bound | HTTP 500 leaking internal SQL + `orchestrator_steps` schema; possible partial-insert state | `pocs/04-amountraw-u64-overflow-and-schema-leak.mjs` |
| **F-05** | **Low** | SIWS challenge not phishing-resistant | Signed message has no domain/address/EIP-4361 binding | `pocs/05-siws-message-not-phishing-resistant.mjs` |

Plus 4 hardening observations (O-1…O-4) with fixes.

## Headline: F-01 (fee bypass), reproduced end-to-end

Identical 100 SOL transfer; only the client-supplied `tokenPriceUsd` differs:

```
honest  price=$200     -> tier=premium   feeBps=50  feeRaw=497512437
spoofed price=$0.0001  -> tier=standard  feeBps=5   feeRaw= 49975012   (10x less fee, persisted at create)
```

## What was tested and found solid (coverage, not just hits)

IDOR scoping on `/transfers/{id}` (404, no leak) · idempotency (MH_070/071/072) ·
admin authorization (403) · recovery phase-gating (MH_080) · rate limiting (MH_004 +
Retry-After) · SIWS nonce lifecycle (single-use, server-tracked) ·
`confirmRegistration` on-chain verification. The defects cluster where a server-side
source of truth was replaced by a client value or a skipped step.

## Reproduce in ~1 minute (no setup, no SOL)

```bash
cd pocs && npm install
for f in 0*.mjs; do echo "== $f =="; node "$f"; done
# each prints request/response evidence + a VULNERABLE/OK verdict and exits 0 on repro.
# PoCs self-provision a devnet key (that path is F-03); or bring your own:
#   MH_API_KEY=mh_test_xxx node 01-fee-tier-bypass.mjs
```

Every claim above is backed by a script a judge can run directly against
`https://devnet.multihopper.com`.

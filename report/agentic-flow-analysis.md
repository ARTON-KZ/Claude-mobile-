# MultiHopper Agentic Flow — Architecture & Invariant Analysis

This is the reasoning map that drove the hunt: how the agent-facing flow works,
which invariants it depends on, and where each was probed. Reconstructed purely
from the public devnet surface (REST API, OpenAPI, docs, and the dashboard SPA's
own tRPC calls).

## Two surfaces

1. **REST agentic API** — `https://devnet.multihopper.com/api/v1/*`, `x-api-key:
   mh_test_…`. This is what an AI agent / integrator drives. Documented as MCP
   tools (`estimate_transfer`, `create_transfer`, `prepare_transfer`,
   `confirm_broadcast`, `get_transfer`, `list_transfers`, `prepare_rescue`,
   `confirm_rescue`).
2. **tRPC control plane** — `https://devnet.multihopper.com/trpc/*`. Backs the
   developer dashboard: SIWS auth (`auth.*`), provider onboarding
   (`integrations.provider.*`), API-key management (`integrations.createApiKey`,
   `revealDeliveredApiKey`, `revokeApiKey`), reporting (`dashboard.*`), and the
   on-chain builders (`contract.*`, `routes.*`, `orchestrator.*`). No transformer;
   input is sent raw, results are `result.data`.

## Onboarding → key issuance (control plane)

```
auth.createMessage {address}            -> {nonce, message}     (nonce server-tracked, single-use)
  sign(message) with wallet
auth.verifyUserWithSignature {nonce,address,signature} -> JWT (HS256, {userId,role:"user"})
integrations.provider.startSignup {name, providerWallet}
      -> {integrationId, providerPda, transactionBase64 (unsigned devnet reg tx)}
  [intended] sign+broadcast reg tx  (fee payer = providerWallet; creates provider PDA; costs rent)
integrations.provider.confirmRegistration {integrationId, signature}
      -> verifies the tx landed on-chain
integrations.createApiKey {mode:"test"|"live"} -> mh_test_… / mh_live_…
```

**Invariants examined**
- *Nonce is single-use & server-issued* — HOLDS (replay & self-chosen nonce rejected).
- *Signed message binds the session* — WEAK: message carries only the nonce, no
  domain/address (**F-05**).
- *confirmRegistration proves on-chain registration* — HOLDS (fabricated /
  unbroadcast signatures rejected).
- *Key issuance requires completed registration* — **BROKEN (F-03):** integration is
  `active` and `createApiKey` succeeds while `providerStatus ∈ {pending,failed}` and
  `registerSignature = null`.
- *Admin surface is privileged* — HOLDS (`dashboard.admin*` → 403).
- *Reporting is tenant-scoped* — HOLDS (`dashboard.*` ignore attacker `integrationId`).

## The 7-step transfer flow (REST agentic API)

```
1. estimate_transfer   POST /transfers/estimate     fee/SOL quote
2. create_transfer     POST /transfers              -> transfer {id (int, sequential), status:"quote"}
3. prepare_transfer    POST /transfers/:id/prepare  -> unsigned base64 tx groups
4. sign keeperFundingTx; broadcast; confirm-broadcast FIRST   (anti "double-fund on resume")
5. sign+broadcast routeInit[] -> orchestratorInit -> sessionInit[] (strict order, delays)
6. confirm_broadcast   POST /transfers/:id/confirm-broadcast  (remaining signatures)
7. poll get_transfer   GET /transfers/:id  until completed|failed|expired
   recovery: rescue/{prepare,confirm}, reclaim-rent/{prepare,confirm}  (phase-gated)
```

**Invariants examined**
- *Amount validation* — integer-string enforced, `>0`, decimals 0–18, hops 3–10 all
  hold; **but no upper bound** → **F-04** (u64 overflow → 500 + SQL leak).
- *Fee integrity* — **BROKEN (F-01):** tier derived from client `tokenPriceUsd`,
  even for SOL; ~10× underpayment, persisted at `create`.
- *Object authorization on `:id`* — HOLDS: sequential int ids, but non-owned → 404.
- *Idempotency* — HOLDS (MH_070/071/072 all correct).
- *Recovery phase-gating* — HOLDS (rescue/reclaim on `quote` → MH_080).
- *Rate limiting* — HOLDS (MH_004 + Retry-After).
- *Webhook egress safety* — **BROKEN (F-02):** no URL scheme/host validation → SSRF.

## Where the value is

The economically/operationally significant defects cluster at **trust boundaries
where a server-side source of truth was replaced by a client-supplied value or a
skipped step**:
- price → fee tier (F-01),
- "registered on-chain" → "has a DB row" (F-03),
- "public webhook URL" → "any URI" (F-02),
- "amount fits u64" → "is an integer string" (F-04).

Cryptographic/stateful controls that were implemented explicitly (nonce lifecycle,
idempotency, phase gating, tenant scoping, admin gating, on-chain confirmation of
registration) were consistently correct.

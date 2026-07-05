// F-04 — `amountRaw` has no upper bound. A value larger than u64 passes the
// estimate/create request validation, then fails deep in route creation with an
// HTTP 500 that leaks the raw SQL query and internal DB schema.
//
// /transfers/estimate happily computes fees for an 80-digit amount; POST
// /transfers accepts a >u64 amountRaw and throws MH_031 with a verbose error
// containing the full `insert into "orchestrator_steps" (...)` statement and
// column names. Two defects: (1) missing max/u64 validation on amountRaw, and
// (2) unhandled DB exception surfaced verbatim to the API caller (info leak;
// possible partial/inconsistent route rows).
//
// Run:  MH_API_KEY=mh_test_... node 04-amountraw-u64-overflow-and-schema-leak.mjs
import { rest, provisionApiKey, section, line, verdict, short } from "./_lib.mjs";

const { key } = await provisionApiKey();
const SOL = "So11111111111111111111111111111111111111112";
const ME = "Do9uGrChvHDH2xfvsFNF1MNHGMnMRhiX5g5mpyHoQLLr";
const RECIP = "Vote111111111111111111111111111111111111111";
const u = () => "u64-" + Math.random().toString(36).slice(2) + Date.now();

section("1. estimate accepts an 80-digit amount (no upper bound)");
const est = await rest("/transfers/estimate", { method: "POST", apiKey: key, idem: u(),
  body: { tokenMint: SOL, amountRaw: "9".repeat(80), tokenDecimals: 9, tokenPriceUsd: 1 } });
line("estimate ->", est.status, "tier=", est.body?.tier, "feeRaw(len)=", String(est.body?.tokens?.feeRaw || "").length, "digits");

section("2. create with amountRaw > u64::MAX");
const cr = await rest("/transfers", { method: "POST", apiKey: key, idem: u(), body: {
  tokenMint: SOL, tokenSymbol: "SOL", tokenDecimals: 9,
  amountRaw: "99999999999999999999999999", amountTokens: "9e16",
  sourceOwner: ME, recipientWallet: RECIP, hops: 3, tokenPriceUsd: 1 } });
const msg = cr.body?.error?.message || "";
line("create ->", cr.status, cr.body?.error?.code);
line("leaked error head:", short(msg, 300));

const leaks = /insert into\s+"?orchestrator_steps"?/i.test(msg) || /Failed query/i.test(msg);
const vuln = cr.status >= 500 && leaks;
section("VERDICT");
verdict(vuln, "amountRaw>u64 -> HTTP " + cr.status + " leaking internal SQL/schema (orchestrator_steps)");
process.exit(vuln ? 0 : 1);

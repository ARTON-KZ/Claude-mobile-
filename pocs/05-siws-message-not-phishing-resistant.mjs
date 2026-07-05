// F-05 (Low) — The Sign-In-With-Solana challenge message is not phishing
// resistant. The text a user signs is a generic:
//   "Welcome to the application. Sign this message to prove you own this
//    address: <nonce>"
// It contains no domain, no application name, no wallet address, no statement of
// intent, no issued-at/expiry — none of the EIP-4361 / SIWx binding fields.
//
// Nonce handling itself is correct (single-use + server-tracked; verified below),
// so this is a hardening finding: because the signed text is generic and does not
// name MultiHopper or the signing address, a user can be induced on any site to
// sign a message that is indistinguishable from this login challenge, and the
// captured signature (for a live nonce) authenticates them here.
//
// Run:  node 05-siws-message-not-phishing-resistant.mjs   (no key needed)
import nacl from "tweetnacl";
import { trpc, bs58enc, section, line, verdict } from "./_lib.mjs";

const raw = nacl.sign.keyPair();
const kp = { secret: Buffer.from(raw.secretKey), address: bs58enc(raw.publicKey) };
const sign = (m) => bs58enc(nacl.sign.detached(new TextEncoder().encode(m), kp.secret));

section("1. Inspect the challenge message");
const cm = await trpc("auth.createMessage", { address: kp.address });
const { nonce, message } = cm.data;
line("message:", JSON.stringify(message));
const bindsDomain = /multihopper/i.test(message);
const bindsAddress = message.includes(kp.address);
line("binds app/domain name?", bindsDomain, "| binds signing address?", bindsAddress);

section("2. Confirm nonce IS single-use (the part that IS done right)");
await trpc("auth.verifyUserWithSignature", { nonce, address: kp.address, signature: sign(message), isHardwareWallet: false });
const replay = await trpc("auth.verifyUserWithSignature", { nonce, address: kp.address, signature: sign(message), isHardwareWallet: false });
line("replay of consumed nonce ->", replay.status, replay.error?.message || "(token re-issued!)");

const weak = !bindsDomain && !bindsAddress;
section("VERDICT");
verdict(weak, "login challenge omits domain + address + EIP-4361 binding fields (not phishing-resistant)");
process.exit(weak ? 0 : 1);

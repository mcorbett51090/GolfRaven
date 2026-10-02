#!/usr/bin/env node
// tools/apple/check-siwa-secret-expiry.mjs
//
// Build plan §4.8: "a monthly check that FAILS if the Apple client secret expires within 30 days."
//
// The secret checked here is the one an operator pasted into Supabase Auth's Apple provider settings (a JWT signed with the Sign in
// with Apple `.p8`, valid for at most six months): the server's own per-request secrets are 10 minutes long and cannot expire on
// anyone. Nothing in this repo can read that dashboard setting, so the check takes the JWT as input.
//
//   APPLE_SIWA_CLIENT_SECRET_JWT=<jwt> node tools/apple/check-siwa-secret-expiry.mjs [--warn-days 30]
//   printf '%s' "$JWT" | node tools/apple/check-siwa-secret-expiry.mjs
//
// Exit 0: more than --warn-days left.  Exit 1: expired, expiring within --warn-days, malformed, or no `exp` (it never passes by
// default).  Exit 2: no input at all.  The JWT is a secret: it is read, never printed, and never written anywhere.
// Run it monthly from a scheduler that holds the JWT as a secret (a calendar reminder to re-mint is the other half). Plain Node, no
// dependencies, so it runs anywhere; the decision logic mirrors supabase/functions/_shared/signin/secret-expiry.ts, and a unit test
// runs both against the same fixtures.

import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const wi = args.indexOf("--warn-days");
const warnDays = wi >= 0 ? Number(args[wi + 1]) : 30;
if (!Number.isFinite(warnDays) || warnDays < 0) {
  console.error("check-siwa-secret-expiry: --warn-days must be a non-negative number");
  process.exit(2);
}

let jwt = (process.env.APPLE_SIWA_CLIENT_SECRET_JWT ?? "").trim();
if (jwt === "") {
  try {
    jwt = readFileSync(0, "utf8").trim();
  } catch {
    jwt = "";
  }
}
if (jwt === "") {
  console.error("check-siwa-secret-expiry: no JWT given (set APPLE_SIWA_CLIENT_SECRET_JWT or pipe it on stdin)");
  process.exit(2);
}

function expOf(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(Buffer.from(b64 + "=".repeat((4 - (b64.length % 4)) % 4), "base64").toString("utf8"));
    return typeof payload === "object" && payload !== null && typeof payload.exp === "number" && Number.isFinite(payload.exp) ? payload.exp : undefined;
  } catch {
    return null;
  }
}

const exp = expOf(jwt);
if (exp === null) {
  console.error("check-siwa-secret-expiry: FAIL: the value is not a JWT");
  process.exit(1);
}
if (exp === undefined) {
  console.error("check-siwa-secret-expiry: FAIL: the JWT has no numeric exp claim");
  process.exit(1);
}
const daysLeft = (exp * 1000 - Date.now()) / 86_400_000;
const when = new Date(exp * 1000).toISOString();
if (daysLeft <= 0) {
  console.error(`check-siwa-secret-expiry: FAIL: the Apple client secret EXPIRED at ${when}. Re-mint it and update Supabase Auth's Apple provider settings.`);
  process.exit(1);
}
if (daysLeft < warnDays) {
  console.error(`check-siwa-secret-expiry: FAIL: the Apple client secret expires at ${when} (${daysLeft.toFixed(1)} days, under the ${warnDays}-day threshold). Re-mint it and update Supabase Auth's Apple provider settings.`);
  process.exit(1);
}
console.log(`check-siwa-secret-expiry: ok: the Apple client secret expires at ${when} (${daysLeft.toFixed(1)} days left)`);

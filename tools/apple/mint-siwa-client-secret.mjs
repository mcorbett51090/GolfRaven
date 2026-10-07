#!/usr/bin/env node
// tools/apple/mint-siwa-client-secret.mjs
//
// Operator tool, the sibling of check-siwa-secret-expiry.mjs: mints the LONG-LIVED Sign in with Apple client secret that Supabase Auth's own Apple
// provider setting needs (docs/security/p3-money-path-requirements.md, "Sign in with Apple, server side"; docs/owner/apple-setup-runbook.md, Step 2.4).
// It is NOT the server's own per-request secret (that one is 10 minutes long and minted inside the Edge Function).
//
//   node tools/apple/mint-siwa-client-secret.mjs --team-id <TEAM_ID> --key-id <KEY_ID> --client-id <CLIENT_ID> [--lifetime-days 150] --key-file <path-to-AuthKey.p8>
//   cat AuthKey.p8 | node tools/apple/mint-siwa-client-secret.mjs --team-id ... --key-id ... --client-id ... --key-file -
//
// The JWT is printed to STDOUT and nothing else is (messages go to stderr), so it can be piped straight to a clipboard tool or pasted. It is a SECRET.
//
// Safety rules this tool keeps (each is pinned by supabase/tests/unit/mint-siwa-client-secret.test.ts):
//   * The private key is read ONLY from a file path or from stdin (`--key-file -`). There is no option that takes the key's text: a key on the command
//     line is visible in `ps`, shell history and CI logs. An argument that looks like a PEM block is refused outright.
//   * It NEVER writes anything to disk (it only reads one file) and never prints, logs or echoes the key; error messages carry no key material.
//   * The lifetime is CAPPED: Apple's maximum is six months `[unverified — training knowledge on the exact figure]`, so this tool accepts at most
//     180 days (15,552,000 s, under both "6 months" readings) and REFUSES a larger value instead of clamping it silently. Default 150 days.
//   * It signs with the SAME exported function the server uses (`mintAppleClientSecret`, supabase/functions/_shared/signin/apple-client-secret.ts), so the
//     claims (iss = team id, sub = client id, aud = https://appleid.apple.com, kid = key id, ES256) cannot drift from what the server sends to Apple.
//     That module is TypeScript: this needs Node 24 or newer (native type stripping); an older Node stops with a clear message.
//
// Exit codes: 0 minted; 1 the key is unusable (not a PKCS#8 P-256 private key); 2 bad usage (missing/invalid options, a key on the command line, a lifetime over the cap, no key input).

import { readFileSync } from "node:fs";

const MAX_LIFETIME_DAYS = 180;
const DEFAULT_LIFETIME_DAYS = 150;
const USAGE =
  "usage: mint-siwa-client-secret.mjs --team-id <id> --key-id <id> --client-id <id> [--lifetime-days <1-180>] --key-file <path|->  (the key is read from that file, or from stdin with `-`)";

function fail(code, msg) {
  console.error(`mint-siwa-client-secret: ${msg}`);
  process.exit(code);
}

const looksLikeKey = (a) => /PRIVATE KEY|BEGIN [A-Z ]*KEY/.test(a);
const args = process.argv.slice(2);
const opts = {};
const KNOWN = new Set(["--team-id", "--key-id", "--client-id", "--lifetime-days", "--key-file"]);
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  // Refuse key material on the command line before anything else (the option names AND their values, `--key-file <value>` included): it would
  // already be in `ps` and the shell history, so say so and stop.
  if (args.some(looksLikeKey)) fail(2, "an argument looks like a private key. The key must never be passed on the command line: use --key-file <path> or --key-file - (stdin). " + USAGE);
  const eq = a.indexOf("=");
  const name = eq > 0 ? a.slice(0, eq) : a;
  if (!KNOWN.has(name)) fail(2, `unknown option ${name.slice(0, 40)}. ${USAGE}`);
  const value = eq > 0 ? a.slice(eq + 1) : args[++i];
  if (value === undefined || value === "" || (eq < 0 && value.startsWith("--") && name !== "--key-file")) fail(2, `${name} needs a value. ${USAGE}`);
  if (name in opts) fail(2, `${name} was given twice. ${USAGE}`);
  opts[name] = value;
}

for (const required of ["--team-id", "--key-id", "--client-id", "--key-file"]) if (!(required in opts)) fail(2, `${required} is required. ${USAGE}`);
for (const id of ["--team-id", "--key-id", "--client-id"]) {
  if (/\s/.test(opts[id].trim()) || opts[id].trim() === "") fail(2, `${id} must be a non-empty value with no whitespace`);
  opts[id] = opts[id].trim();
}

const lifetimeDays = "--lifetime-days" in opts ? Number(opts["--lifetime-days"]) : DEFAULT_LIFETIME_DAYS;
if (!Number.isFinite(lifetimeDays) || lifetimeDays <= 0) fail(2, "--lifetime-days must be a positive number");
if (lifetimeDays > MAX_LIFETIME_DAYS) fail(2, `--lifetime-days ${lifetimeDays} is over the ${MAX_LIFETIME_DAYS}-day cap (Apple's limit is about six months); not clamped, choose a smaller value`);

let privateKeyPem;
try {
  if (opts["--key-file"] === "-") {
    if (process.stdin.isTTY) fail(2, "--key-file - reads the key from stdin, but stdin is a terminal. Pipe the .p8 file in (cat AuthKey.p8 | ...), or pass --key-file <path>");
    privateKeyPem = readFileSync(0, "utf8");
  } else {
    privateKeyPem = readFileSync(opts["--key-file"], "utf8");
  }
} catch {
  // Deliberately no `e.message`: for a path it is harmless, but nothing read from the key may ever reach an error.
  fail(2, "could not read the key (check the --key-file path, or pipe the key on stdin with --key-file -)");
}
if (privateKeyPem.trim() === "") fail(2, "the key input is empty");

let mint;
try {
  ({ mintAppleClientSecret: mint } = await import(new URL("../../supabase/functions/_shared/signin/apple-client-secret.ts", import.meta.url).href));
} catch {
  fail(2, "could not load the signing module. This tool needs Node 24 or newer (it imports the server's TypeScript signer directly) and a full checkout of the repo");
}

const nowSec = Math.floor(Date.now() / 1000);
const ttlSeconds = Math.floor(lifetimeDays * 86_400);
let jwt;
try {
  jwt = await mint({ teamId: opts["--team-id"], clientId: opts["--client-id"], keyId: opts["--key-id"], privateKeyPem }, nowSec, ttlSeconds);
} catch {
  fail(1, "the key is not usable: it must be one PKCS#8 'PRIVATE KEY' block holding an EC P-256 key (the .p8 Apple gives you). Nothing was minted");
}

process.stdout.write(`${jwt}\n`);
console.error(`mint-siwa-client-secret: minted a secret valid for ${lifetimeDays} day(s), expiring ${new Date((nowSec + ttlSeconds) * 1000).toISOString()}. It is a SECRET: paste it into Supabase Auth's Apple provider settings, keep one copy in your vault, never commit it.`);

// supabase/functions/_shared/catalog/webhook-auth.ts
//
// The `import-catalog` Edge Function's ONLY authentication mechanism
// (build plan §3.3: "POSTing a signed, secret-free webhook"; task
// instruction: "triggerable only by an authenticated system caller: the
// deploy webhook with an HMAC/shared secret, plus the hourly backstop —
// anonymous and player JWTs get 401/403"). There is deliberately NO
// Supabase-JWT code path here at all (unlike every other Edge Function in
// this tree, which calls `privileged.ts#getActorFromRequest`) — this is
// the "explicit system-actor path rather than faking a user" the task
// asks for: import-catalog is not a user, has no `auth.users` row, and
// writes only to tables that carry no `user_id` at all
// (`app.catalog_version`, `app.catalog_id_ledger`) plus a narrow,
// server-computed UPDATE of `app.evidence.status` for draining (never
// scoped by "whoever the caller claims to be" — every row it touches is
// found by its OWN age/status, not by an actor id). A JWT presented here
// simply has no header this module recognizes, so it is rejected the same
// way a request with no header at all is — 401, not a distinct code path
// that might accidentally trust it.
//
// Scheme (Stripe-webhook-shaped, well-understood): a header value
// `t=<unix-seconds>,v1=<lowercase-hex-hmac-sha256>` where the HMAC covers
// `${t}.${rawBodyBytes}` under a shared secret BOTH the deploy webhook
// (a GitHub Actions secret, held by CI — build plan §3.3: "no DB secret
// in CI", this is a NARROW, single-purpose signing secret, never
// service_role) and the hourly cron backstop (also holds this same
// secret, e.g. via `pg_cron`/`net.http_post` or an external scheduler)
// present identically. Binding the timestamp into the signed bytes (not
// just checking it separately) closes a length-extension-adjacent replay
// class: a captured, valid signature cannot be replayed outside its own
// tolerance window, because a DIFFERENT `t` produces a DIFFERENT MAC over
// DIFFERENT bytes, not merely a "stale timestamp" a checker might forget
// to verify.
//
// Pure and dependency-free beyond Web Crypto (`crypto.subtle`, already
// used unmodified by catalog/signature.ts under both Deno and this
// repo's own vitest/Node run — see that module's own header) — the
// secret itself is read from env ONLY inside privileged.ts (the sole
// allow-listed `Deno.env.get` site for a non-public key,
// tools/service-role-lint's own rule) and passed in here as a plain
// string, so this module needs no env access and is unit-testable with a
// literal secret.

const HEADER_RE = /^t=(\d+),v1=([0-9a-f]+)$/;

export interface WebhookAuthResult {
  ok: boolean;
  reason?: "weak_secret" | "missing_header" | "malformed_header" | "clock_skew" | "signature_mismatch";
}

/** Minimum secret length in BYTES (P3e round 2 gate, LOW: "reject an
 * HMAC secret that is empty, whitespace-only or shorter than 32
 * bytes"). 32 bytes = the SHA-256 block-output size; anything shorter
 * gives the MAC less entropy than the hash it keys. */
export const MIN_WEBHOOK_SECRET_BYTES = 32;

export function isAcceptableWebhookSecret(secret: string): boolean {
  if (secret.trim().length === 0) return false;
  return new TextEncoder().encode(secret).length >= MIN_WEBHOOK_SECRET_BYTES;
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSha256Hex(secret: string, message: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret).slice().buffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, message.slice().buffer);
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface VerifyWebhookSignatureInput {
  secret: string;
  headerValue: string | null;
  rawBody: Uint8Array;
  now: Date;
  /** Default 300s (±5 min) — generous enough for real clock drift between
   * this project's Edge Runtime and CI/the scheduler, tight enough that a
   * captured signature is useless well before an attacker could act on
   * it manually. */
  toleranceSeconds?: number;
}

/** Never throws — every rejection path (missing secret input handled by
 * the caller before this is even invoked, missing/malformed header, a
 * timestamp outside tolerance, a MAC mismatch) resolves to `{ok: false}`
 * with a `reason` the caller logs server-side only (same "never leak
 * internals to the caller" discipline http.ts's own `Errors` already
 * follows — this endpoint returns a generic 401, not which check
 * failed). */
export async function verifyWebhookSignature(input: VerifyWebhookSignatureInput): Promise<WebhookAuthResult> {
  // Fail closed on a weak/blank secret BEFORE looking at the header — a
  // short secret is a misconfiguration, never something to authenticate
  // against (even with an otherwise-correct signature).
  if (!isAcceptableWebhookSecret(input.secret)) return { ok: false, reason: "weak_secret" };
  if (!input.headerValue) return { ok: false, reason: "missing_header" };
  const m = HEADER_RE.exec(input.headerValue);
  if (!m) return { ok: false, reason: "malformed_header" };
  const t = Number(m[1]);
  const givenMac = m[2]!;
  if (!Number.isFinite(t)) return { ok: false, reason: "malformed_header" };
  const toleranceSeconds = input.toleranceSeconds ?? 300;
  const nowSeconds = Math.floor(input.now.getTime() / 1000);
  if (Math.abs(nowSeconds - t) > toleranceSeconds) return { ok: false, reason: "clock_skew" };

  const signedBytes = new Uint8Array(new TextEncoder().encode(`${m[1]}.`).length + input.rawBody.length);
  signedBytes.set(new TextEncoder().encode(`${m[1]}.`), 0);
  signedBytes.set(input.rawBody, new TextEncoder().encode(`${m[1]}.`).length);
  const expectedMac = await hmacSha256Hex(input.secret, signedBytes);
  if (!timingSafeEqualHex(expectedMac, givenMac)) return { ok: false, reason: "signature_mismatch" };
  return { ok: true };
}

/** Builds the header value a caller (CI, the hourly scheduler, or a test)
 * would send — the exact inverse of what `verifyWebhookSignature` checks.
 * Exported so the Deno integration test and a future real caller (the
 * `deploy-site.yml` webhook step, the cron backstop) construct the SAME
 * header this module verifies, with no risk of the two silently
 * diverging. */
export async function buildWebhookSignatureHeader(secret: string, rawBody: Uint8Array, now: Date): Promise<string> {
  const t = Math.floor(now.getTime() / 1000);
  const prefix = new TextEncoder().encode(`${t}.`);
  const signedBytes = new Uint8Array(prefix.length + rawBody.length);
  signedBytes.set(prefix, 0);
  signedBytes.set(rawBody, prefix.length);
  const mac = await hmacSha256Hex(secret, signedBytes);
  return `t=${t},v1=${mac}`;
}

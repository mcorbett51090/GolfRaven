// supabase/functions/_shared/signin/revocation.ts
//
// Revoking a sign-in provider grant at the provider, from the durable queue (private.signin_revocation_queue, 0035).
//
// Build plan §7.8 / Apple 5.1.1(v): account deletion "revokes the Sign in with Apple grant through Apple's token-revocation
// endpoint and the Google grant through Google's revocation endpoint, using the signin_provider_token row ... A revocation that
// fails is retried for 72 h and logged, and never blocks the deletion."
//
// The shape that makes that true:
//   1. the grant is ENQUEUED (copied, still encrypted, into the queue; no user id) in its own transaction BEFORE anything is
//      deleted, so the token cannot be lost between "the row is gone" and "the provider was told";
//   2. THIS runner claims the queued rows (leasing them so two workers never revoke the same one), decrypts each envelope with
//      the Vault KEK, calls the provider, and records the outcome in a separate short transaction. No vendor call is made while a
//      database transaction is open;
//   3. a failure of any kind (provider down, our key unconfigured, the KEK missing, a decrypt failure) is recorded as a short
//      machine code, the row stays pending with a backed-off next attempt, and the NEXT run (the drain function, or the next
//      request that happens to run one) tries again until the row is 72 h old, when the database marks it expired and logs it;
//   4. this runner NEVER throws to its caller in the best-effort entry point: a deletion must not fail because Apple is down.
//
// Idempotent at the provider by construction (apple-client.ts / google-client.ts treat "already not valid" as success), so a
// crash between the provider call and the bookkeeping only costs a harmless repeat.

import { decryptToken, type Kek } from "./envelope.ts";
import { EnvelopeError, NotConfiguredError, VendorUnavailableError } from "./errors.ts";
import type { AppleSigninPort, ClaimedRevocation, GoogleRevokePort, RevocationDb, RevocationJob } from "./types.ts";

export type RevocationStatus = "revoked" | "queued_for_retry";

export interface RevocationOutcome {
  queueId: string;
  provider: string;
  status: RevocationStatus;
  /** Present when status is queued_for_retry: the short machine code of the last failure. */
  error?: string;
}

export interface RevocationDeps {
  db: RevocationDb;
  apple: Pick<AppleSigninPort, "revokeRefreshToken"> | null;
  google: GoogleRevokePort | null;
  log(event: Record<string, unknown>): void;
}

/** A claim leases the row for this long; a worker that dies mid-attempt frees the row after it. */
export const REVOCATION_LEASE_SECONDS = 120;
export const MAX_BACKOFF_SECONDS = 6 * 60 * 60;

/** 1 min, 2, 4, ... capped at 6 h: about a dozen attempts in 72 h, front-loaded for a transient outage. */
export function backoffSeconds(attemptsSoFar: number): number {
  return Math.min(MAX_BACKOFF_SECONDS, 60 * 2 ** Math.min(Math.max(attemptsSoFar, 0), 12));
}

/** Reduces anything to the alphabet the queue's last_error CHECK allows. Never carries free text from a provider. */
export function toErrorCode(e: unknown): string {
  let raw: string;
  if (e instanceof VendorUnavailableError) raw = e.code;
  else if (e instanceof NotConfiguredError) raw = `not_configured_${e.code}`;
  else if (e instanceof EnvelopeError) raw = `envelope_${e.code}`;
  else raw = "unexpected";
  const cleaned = raw.toLowerCase().replace(/[^a-z0-9_:.-]/g, "_").slice(0, 64);
  return cleaned.length > 0 ? cleaned : "unexpected";
}

async function revokeOne(job: ClaimedRevocation, deps: RevocationDeps, keks: Map<string, Promise<Kek>>): Promise<{ ok: true } | { ok: false; code: string }> {
  try {
    let kekP = keks.get(job.envelope.kekId);
    if (!kekP) {
      kekP = deps.db.kekById(job.envelope.kekId);
      keks.set(job.envelope.kekId, kekP);
    }
    const token = await decryptToken(job.envelope, job.provider, await kekP);
    if (job.provider === "apple") {
      if (!deps.apple) return { ok: false, code: "not_configured_apple" };
      await deps.apple.revokeRefreshToken(token);
    } else if (job.provider === "google") {
      if (!deps.google) return { ok: false, code: "not_configured_google" };
      await deps.google.revokeToken(token);
    } else {
      return { ok: false, code: "unknown_provider" };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, code: toErrorCode(e) };
  }
}

/** Claims and attempts due rows (all of them, or just `ids`). Throws only if the CLAIM itself fails (a database error): per-row
 * failures are recorded and reported, never thrown. */
export async function runRevocations(deps: RevocationDeps, opts: { ids?: string[]; limit?: number } = {}): Promise<RevocationOutcome[]> {
  const claimed = await deps.db.claim(opts.ids ?? null, opts.limit ?? 25, REVOCATION_LEASE_SECONDS);
  const keks = new Map<string, Promise<Kek>>();
  return Promise.all(
    claimed.map(async (job): Promise<RevocationOutcome> => {
      const result = await revokeOne(job, deps, keks);
      const code = result.ok ? null : result.code;
      let finalStatus: RevocationStatus = result.ok ? "revoked" : "queued_for_retry";
      try {
        const state = await deps.db.complete(job.id, result.ok ? "revoked" : "retry", code, backoffSeconds(job.attempts));
        if (state === "revoked") finalStatus = "revoked";
      } catch {
        // The bookkeeping failed (the database is unwell). The row is still pending and leased; a later run repeats the
        // attempt, which is idempotent at the provider. The outcome we report is the truthful "not recorded as done".
        finalStatus = "queued_for_retry";
      }
      deps.log({
        event: "signin_revocation",
        queueId: job.id,
        provider: job.provider,
        outcome: result.ok ? "revoked" : "retry",
        attempts: job.attempts + 1,
        ...(code ? { error: code } : {}),
      });
      return { queueId: job.id, provider: job.provider, status: finalStatus, ...(code ? { error: code } : {}) };
    }),
  );
}

/** The entry point DELETE /v1/me and unlink use: attempt exactly these freshly-queued jobs now and NEVER throw. A job that could
 * not even be claimed (the database failed, or another worker holds its lease) is reported as queued_for_retry: it IS queued. */
export async function runRevocationsBestEffort(deps: RevocationDeps, jobs: RevocationJob[]): Promise<RevocationOutcome[]> {
  if (jobs.length === 0) return [];
  let done: RevocationOutcome[] = [];
  try {
    done = await runRevocations(deps, { ids: jobs.map((j) => j.queueId), limit: Math.min(jobs.length, 100) });
  } catch (e) {
    deps.log({ event: "signin_revocation", outcome: "claim_failed", error: toErrorCode(e), jobs: jobs.length });
  }
  const seen = new Set(done.map((o) => o.queueId));
  const rest: RevocationOutcome[] = jobs.filter((j) => !seen.has(j.queueId)).map((j) => ({ queueId: j.queueId, provider: j.provider, status: "queued_for_retry", error: "not_attempted" }));
  return [...done, ...rest];
}

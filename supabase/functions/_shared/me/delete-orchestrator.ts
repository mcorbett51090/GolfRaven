// supabase/functions/_shared/me/delete-orchestrator.ts
//
// DELETE /v1/me with provider-grant revocation (build plan §7.8, Apple 5.1.1(v); the P3d gate "provider revocation before
// deletion" accepted follow-up 1, closed here for Apple and, in the same shape, Google).
//
// The order is the whole design:
//   1. ENQUEUE (own transaction, committed): every sign-in grant of the caller is copied, still encrypted and without a user id,
//      into private.signin_revocation_queue. From here on the token cannot be lost, whatever happens next.
//   2. REVOKE at the providers (no transaction open), BEFORE the provider rows are deleted: each queued grant is decrypted with
//      the Vault KEK and revoked at Apple / Google. Any failure (provider down, our key unconfigured, KEK missing) is recorded on
//      the queue row and the row stays pending: the drain retries it for 72 h and logs it (revocation.ts). This step NEVER throws.
//   3. DELETE (own transaction): first a SECOND enqueue, then `handleMeDelete` -> private.delete_my_data, unchanged. The second enqueue
//      takes the per-account advisory lock (the one link / unlink take) and holds it until this transaction commits, and it copies any
//      grant stored since step 1 (a `link` that ran while step 2 was talking to Apple) into the queue in the SAME transaction that deletes
//      the rows. So no grant can be stored between "queued" and "deleted", and none is deleted unqueued (security gate F6). Those late
//      grants are revoked right after the commit (step 4), best effort, from the same durable queue. It runs whatever step 2 returned: a
//      failed revocation never blocks the deletion.
//   4. REVOKE the late grants (no transaction open), merged into the reported outcomes.
// The Supabase Auth user (and its identities) is deleted by the entrypoint after this returns, as before.
//
// Idempotent end to end: a retry after any partial failure re-enqueues nothing new (the queue is idempotent on the grant's
// ciphertext), re-attempts only what is still pending, and `delete_my_data` is a no-op on a deleted account.

import type { Repo } from "../types.ts";
import { runRevocationsBestEffort, type RevocationDeps, type RevocationOutcome } from "../signin/revocation.ts";
import { handleMeDelete, type DeleteMyDataOutcome } from "./delete-handler.ts";

export interface DeleteDeps {
  /** Runs `op` in ONE transaction scoped to the authenticated caller (privileged.ts#withOwnership). */
  withRepo<T>(op: (repo: Repo) => Promise<T>): Promise<T>;
  revocation: RevocationDeps;
}

export async function orchestrateMeDelete(deps: DeleteDeps): Promise<DeleteMyDataOutcome> {
  const jobs = await deps.withRepo((repo) => repo.signin.enqueueRevocations());
  const outcomes: RevocationOutcome[] = await runRevocationsBestEffort(deps.revocation, jobs);
  const { result, late } = await deps.withRepo(async (repo) => {
    // Under the account lock, in the transaction that deletes: whatever was stored since step 1 is queued before its rows go.
    const again = await repo.signin.enqueueRevocations();
    const seen = new Set(jobs.map((j) => j.queueId));
    return { result: await handleMeDelete(repo, outcomes), late: again.filter((j) => !seen.has(j.queueId)) };
  });
  if (late.length === 0) return result;
  const lateOutcomes = await runRevocationsBestEffort(deps.revocation, late);
  return { ...result, signinProvidersRevoked: [...result.signinProvidersRevoked, ...lateOutcomes] };
}

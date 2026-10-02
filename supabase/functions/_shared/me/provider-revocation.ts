// supabase/functions/_shared/me/provider-revocation.ts
//
// DELETE /v1/me, AT 6 (docs/golf-trails/02-build-plan.md:2759): "revokes
// connectors and deletes push tokens." This module is the CLEARLY MARKED
// SEAM the task instruction asked for — task instruction: "Apple/Google
// revocation is P4 (AT 19). Leave a clearly marked seam."
//
// Two distinct provider families were in scope for "revokes connectors":
//   - `app.signin_provider_token` (O12: Apple/Google SIGN-IN grants,
//     build plan line 857) — NO LONGER a seam: its revocation is built
//     (migration 0035, `_shared/signin/revocation.ts`, orchestrated by
//     `delete-orchestrator.ts`: queue, revoke at the provider, then delete;
//     a failure is retried for 72 h and never blocks the deletion). Only
//     `revokeConnectors` below remains a deferral.
//   - `app.connector_account` (P8: GHIN/Arccos/Garmin golf-app
//     CONNECTORS, build plan line 856) — P8 is conditional, un-built
//     work; there is no real connector integration anywhere in this repo
//     yet, so there is no real endpoint to call at all.
//
// In BOTH cases, `private.delete_my_data` (0015) already deletes the
// LOCAL grant row (`signin_provider_token`/`connector_account` are both
// `delete_row` policy rows, 0014_hardening.sql) — so the account's own
// record of having granted access is gone regardless of whether this
// module's functions do anything. What is NOT yet done is telling the
// UPSTREAM provider (Apple/Google/GHIN/Arccos/Garmin) that the grant is
// revoked, which matters because a stale token sitting at that provider
// (if it were ever leaked or misused before this round's row deletion)
// remains usable there until ITS OWN expiry, independent of anything
// this repo's database does. That gap is the seam: real per-provider
// revocation calls are P4 AT 19 (sign-in) and a P8 conditional
// (connectors), never invented here ahead of either.
//
// `handleMeDelete` (delete-handler.ts) calls `revokeConnectors` below with
// the provider names read BEFORE `repo.me.deleteMyData()` removes the
// rows (see that file's own doc for why the read has to happen first).

export interface ProviderRevocationOutcome {
  provider: string;
  revoked: boolean;
  deferred: true;
  reason: string;
}

const CONNECTOR_DEFERRAL_REASON =
  "golf-app connector revocation (GHIN/Arccos/Garmin) is P8, a conditional phase with no real connector integration built in this repo yet — there is no real endpoint to call. The LOCAL connector_account row is deleted by private.delete_my_data regardless.";

/** The P8 seam: one explicitly deferred outcome per connector provider the caller had a grant under, so the response shows which
 * providers still need real revocation once P8 ships, rather than the seam being invisible. */
export function revokeConnectors(providers: string[]): ProviderRevocationOutcome[] {
  return providers.map((provider) => ({ provider, revoked: false, deferred: true, reason: CONNECTOR_DEFERRAL_REASON }));
}

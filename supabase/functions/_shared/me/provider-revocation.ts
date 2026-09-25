// supabase/functions/_shared/me/provider-revocation.ts
//
// DELETE /v1/me, AT 6 (docs/golf-trails/02-build-plan.md:2759): "revokes
// connectors and deletes push tokens." This module is the CLEARLY MARKED
// SEAM the task instruction asked for — task instruction: "Apple/Google
// revocation is P4 (AT 19). Leave a clearly marked seam."
//
// Two distinct provider families are in scope for "revokes connectors":
//   - `app.signin_provider_token` (O12: Apple/Google SIGN-IN grants,
//     build plan line 857) — its own revocation (calling Apple's/
//     Google's token-revocation endpoint) is explicitly build-plan P4,
//     AT 19: "DELETE /v1/me... calls both revocation endpoints (asserted
//     against recorded requests in staging)... and still completes when
//     a revocation call fails (retried and logged)." Not this round.
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
// `handleMeDelete` (delete-handler.ts) calls both functions below with
// the provider names read BEFORE `repo.me.deleteMyData()` removes the
// rows (see that file's own doc for why the read has to happen first).

export interface ProviderRevocationOutcome {
  provider: string;
  revoked: boolean;
  deferred: true;
  reason: string;
}

const SIGNIN_PROVIDER_DEFERRAL_REASON =
  "signin-provider grant revocation (calling Apple's/Google's own token-revocation endpoint) is build plan AT 19 / O12, shipped in P4 alongside native sign-in — not built this round. The LOCAL signin_provider_token row is deleted by private.delete_my_data regardless.";

const CONNECTOR_DEFERRAL_REASON =
  "golf-app connector revocation (GHIN/Arccos/Garmin) is P8, a conditional phase with no real connector integration built in this repo yet — there is no real endpoint to call. The LOCAL connector_account row is deleted by private.delete_my_data regardless.";

/** The P4 AT 19 seam. Never calls a real Apple/Google endpoint — there
 * isn't one wired into this repo yet (P4 is a later phase). Returns one
 * deferred outcome per provider the caller actually had a grant under,
 * so the caller (`me-delete`'s response) can see explicitly which
 * providers still need real revocation once P4 ships, rather than the
 * seam being invisible. */
export function revokeSigninProviders(providers: string[]): ProviderRevocationOutcome[] {
  return providers.map((provider) => ({ provider, revoked: false, deferred: true, reason: SIGNIN_PROVIDER_DEFERRAL_REASON }));
}

/** The P8 seam — same shape and reasoning as `revokeSigninProviders`
 * above, for `app.connector_account`'s own providers instead. */
export function revokeConnectors(providers: string[]): ProviderRevocationOutcome[] {
  return providers.map((provider) => ({ provider, revoked: false, deferred: true, reason: CONNECTOR_DEFERRAL_REASON }));
}

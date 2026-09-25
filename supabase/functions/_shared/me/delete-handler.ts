// supabase/functions/_shared/me/delete-handler.ts
//
// Pure, DI'd core of the `me-delete` Edge Function (`DELETE /v1/me`,
// build plan §4.7.1a inventory: "me-delete"; AT 6,
// docs/golf-trails/02-build-plan.md:2759): "DELETE /v1/me removes all
// personal rows (asserted by query), revokes connectors and deletes push
// tokens; an unredeemed special-marker entitlement or stock voucher is
// voided at once, and no address exists to retain (O9/O10)."
//
// Scope note (task instruction): this module calls the EXISTING,
// gate-passed `private.delete_my_data` (0015) through the established
// privileged path (`Repo#me.deleteMyData`) — it never reimplements
// deletion. `private.delete_my_data` already covers, checked against its
// own source this round before writing this file:
//   - push tokens: `app.push_token.user_id` is a `delete_row` policy row
//     (0014_hardening.sql) — deleted by the generic pass.
//   - unredeemed entitlements/stock vouchers: the bespoke block "Then,
//     per line 2759 / O9-O10: void any UNREDEEMED entitlement or stock
//     voucher" already sets `state = 'void'` for
//     `kind = 'special_marker'` rows in states
//     `earned/held_review/redeemable/vouchered` (0015). A stock VOUCHER
//     is `entitlement.state = 'vouchered'` per §4.4's own state machine
//     (`redeemable -> redeemed | vouchered`), so it is already covered —
//     no separate stock-voucher handling was needed here.
// Both were confirmed present BEFORE this file was written (see this
// round's report for the file:line citations) — nothing here duplicates
// them.
//
// What THIS module adds, beyond calling `deleteMyData()`:
//   - the provider-revocation SEAM (AT 6's "revokes connectors";
//     provider-revocation.ts, clearly marked, P4/P8 as directed) — reads
//     the caller's own provider rows BEFORE they are deleted, since
//     `deleteMyData()` removes `signin_provider_token`/`connector_account`
//     rows unconditionally and there is no other chance to see them.
//   - nothing else: Auth-user deletion (`deleteAuthUser`,
//     `_shared/privileged.ts`) is deliberately NOT called from here — it
//     is an HTTP call to Supabase Auth, not a Postgres statement, so it
//     cannot run inside the SAME transaction this module's caller
//     (`withOwnership`) wraps; `me-delete/index.ts` calls it AFTER this
//     handler's `withOwnership` call has committed (see that file's own
//     comment for the ordering and `deleteAuthUser`'s own doc for its
//     idempotency).
//
// Idempotency (task instruction: "a retry after partial failure
// completes"). The one genuinely partial-failure shape this round
// produces is: the DB transaction (this handler) commits successfully,
// then the Auth-user deletion (index.ts, after this handler returns)
// fails. A retry of the WHOLE request then calls this handler again:
//   - `repo.me.listSigninProviders()`/`listConnectorProviders()` return
//     empty arrays (the rows are already gone) — the revocation seam
//     simply has nothing to report the second time, not an error.
//   - `repo.me.deleteMyData()` calls `private.delete_my_data` again;
//     0015's own generic pass affects 0 rows for a target with nothing
//     left to delete (every `DELETE ... WHERE user_id = $1` and
//     `UPDATE ... WHERE user_id = $1` is naturally a no-op against an
//     empty match set — Postgres does not error on a 0-row DML), and its
//     `SELECT ... INTO v_handle/v_email` lookups return NULL rather than
//     raising when the row is already gone (0015's own `COALESCE`
//     handling). The function returns the SAME `{user_id, deleted_at}`
//     shape either way — `deleted_at` simply reflects the retry's own
//     timestamp, not the original one, which is correct: the caller
//     asked "is my data gone" and the honest answer is "yes, as of now."
// So a retry of this handler is safe to call again in full, with no
// special-cased "already deleted" branch needed on this module's own
// side — the DB function's own idempotency (proven by its 09_delete_my_
// data.sql pgTAP suite) already carries it.

import type { Repo } from "../types.ts";
import { revokeConnectors, revokeSigninProviders, type ProviderRevocationOutcome } from "./provider-revocation.ts";

export interface DeleteMyDataOutcome {
  userId: string;
  deletedAt: string;
  signinProvidersRevoked: ProviderRevocationOutcome[];
  connectorsRevoked: ProviderRevocationOutcome[];
}

export async function handleMeDelete(repo: Repo): Promise<DeleteMyDataOutcome> {
  // Read BEFORE deleteMyData() removes the rows — see this file's own
  // header for why this ordering is required, not incidental.
  const [signinProviders, connectorProviders] = await Promise.all([repo.me.listSigninProviders(), repo.me.listConnectorProviders()]);

  const signinProvidersRevoked = revokeSigninProviders(signinProviders);
  const connectorsRevoked = revokeConnectors(connectorProviders);

  const result = await repo.me.deleteMyData();

  return {
    userId: result.userId,
    deletedAt: result.deletedAt,
    signinProvidersRevoked,
    connectorsRevoked,
  };
}

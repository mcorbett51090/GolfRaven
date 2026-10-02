# Edge Function NOBYPASSRLS role: design, as built (PR1, database only)

Accepted follow-up 6 of the P3c gate (`docs/security/p3-money-path-requirements.md`, "Updated Accepted follow-ups"):
before the first real deploy, the Edge Function connection moves from a blanket `service_role` (BYPASSRLS)
to a dedicated NOBYPASSRLS login role with actor-scoped policies or SECURITY DEFINER functions.

This document started as the design written against `02a422e` and is now updated to what PR1 built. PR1 is the
database side only: migrations `0030_edge_role_core.sql` and `0031_edge_role_policies.sql`, the provisioning script,
the inventory checks 9-12 and the pgTAP file `supabase/tests/matrix/16_edge_role.sql`. **Nothing in the TypeScript
uses any of it yet** (PR2-PR4). `service_role`, `anon` and `authenticated` are untouched, so nothing that works
today stops working. Items marked `[unverified]` were not checked against a real Supabase project.

Numbering note: the migrations are 0030 and 0031 because 0029 is the P3f follow-up that domain-separates the tombstone
pseudonym (`private.account_pseudonyms` now hashes `'install_link_account:' || user_id`, prefers the newest vault key by
`created_at`, and `private_definer` holds `SELECT (created_at)` on `vault.decrypted_secrets`). 0029 uses `CREATE OR REPLACE`
with the same signature, so the EXECUTE grant and the `install_link_account` policies here are unaffected; this PR was
re-verified on top of it (file 16 and check 12 pass unchanged).

## 1. The problem

- Every Edge transaction runs `set local role service_role` (`privileged.ts`: `withOwnership`,
  `withOwnershipBatch`, `withSystemCatalogImport`, `hitRateLimitForActor`, `hitSystemRateLimit`). `service_role` is
  BYPASSRLS, so FORCE RLS is inert for the Edge path and ownership is only the `user_id = ${uid}` filter in each
  Repo method. One missing filter is a cross-user read or write with no database backstop.
- The system path (drain, rescore) fabricates actors from cross-user reads (`drain-orchestrator.ts`,
  `rescore-orchestrator.ts`).
- `private.delete_my_data(uuid)`, `export_my_data(uuid)` and `hit_rate_limit(key)` accept an arbitrary id or key.
- Two invoker-rights triggers run as the writing role and touch tables an unprivileged role must not reach:
  `app.checkin_challenge_tombstone_nonce` (writes `private.consumed_nonce`) and the held-review cascade (updates
  `offer_code` / `entitlement`). Under RLS an UPDATE with no matching policy affects 0 rows and raises nothing. That
  silent no-op is the main breakage risk of this whole change, so every UPDATE cell in the tests asserts a row count.

## 2. Role model (as built)

| Role | Login | Purpose | Notes |
|---|---|---|---|
| `edge_gateway` | yes, but only after `tools/db/provision-edge-login.sh` | the Edge connection | NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION. No grants of its own, no USAGE on `app` or `private`. Member of `edge_actor` and `edge_system` `WITH INHERIT FALSE, SET TRUE`. |
| `edge_actor` | no | per-user work | NOINHERIT NOBYPASSRLS. Every policy that applies to it is keyed on `private.actor_uid()`; nothing else is an identity source. |
| `edge_system` | no | catalog import only | NOINHERIT NOBYPASSRLS. No policy and no privilege on any table that holds personal data. |

Every Edge transaction is `SET LOCAL ROLE edge_actor | edge_system`, with the existing `current_user` assertion kept.
`SET ROLE service_role | postgres | authenticated | anon | private_definer | supabase_admin` fails: `SET ROLE` is
authorised against the session user's memberships, and `edge_gateway` has none of those.

- **Provisioning.** The migration creates `edge_gateway` NOLOGIN. LOGIN and the password come only from
  `tools/db/provision-edge-login.sh` (idempotent `ALTER ROLE edge_gateway LOGIN PASSWORD ...`). The password is read
  from an environment variable or from stdin and is sent to `psql` on stdin; there is no argument that takes it.
  It refuses an empty or multi-line password and re-checks the role afterwards. `[unverified]` `ALTER ROLE ...
  PASSWORD` can appear in server logs under `log_statement = 'ddl'` or `'all'`; run it on a connection with that
  off, or pre-hash the password (SCRAM) before sending it.
- **No `migration_owner`.** The migrations never name it; `CURRENT_USER` is used wherever the migrating role is
  meant. HARNESS_MODE=restricted runs both migrations as a NOSUPERUSER CREATEROLE role, which is the proof that
  creating the roles needs no superuser. A non-superuser cannot even re-assert `NOSUPERUSER`/`NOBYPASSRLS`, so the
  migration fixes them at `CREATE ROLE` and check 9 fails the build if any of the three ever holds one.
- **Not `authenticated` + `request.jwt.claims`.** The connecting role could forge the claims GUC.

## 3. Actor binding (no GUC)

`private.actor_binding` is an UNLOGGED table `(backend_pid PK, xact xid8, actor_uid, kind, bound_at)`, FORCE RLS, no
edge grant at all. Each `private_definer` policy on it admits only the current backend's own row.

- `private.bind_actor(uid)` (edge_actor only): raises if this transaction already has a binding (`42501`), if the
  uid is NULL (`22023`) or not in `auth.users` (`P0002`); otherwise upserts the row on `backend_pid`.
- `private.actor_uid()` (STABLE, PARALLEL UNSAFE, SECURITY DEFINER): returns the uid only when the stored `xact`
  equals `pg_current_xact_id_if_assigned()`, else NULL. A binding left by an earlier transaction on a pooled
  connection, or undone by a rolled-back savepoint, fails closed: every `user_id = (select private.actor_uid())`
  is NULL and the policy admits nothing. (Tested: after a real COMMIT, on an autocommit statement, after
  `ROLLBACK TO SAVEPOINT`.)
- **Delegates (edge_system only):** `bind_delegate_for_queued_evidence(evidence_id)` binds the owner of one
  evidence row that is still `queued_catalog`; `bind_delegate_for_rescore(backlog_id, play_id)` binds the owner of one
  play at the course of an open backlog row. They bind with `kind = 'system_delegate'`. The caller then does
  `SET LOCAL ROLE edge_actor` in the same transaction and acts as that user. A delegate-bound transaction cannot be
  re-bound, cannot call `delete_my_data_for_actor` or `export_my_data_for_actor`, and edge_actor cannot call the
  binders.
- **Honest limit (the authenticator trust model).** A fully compromised Edge runtime can still bind any uid, so it
  can act as any user. What the binding buys: the identity is an in-database fact the connection cannot forge by
  setting a session variable; a forgotten bind fails closed; and every cross-user path is a named, reviewed
  function. An optional follow-up, not built: verify the JWT in the database (HS256 via Vault only) `[inferred]`.

## 4. Table to mechanism matrix (as built)

`P` = `user_id = (select private.actor_uid())`. Grants are column-level wherever a table has columns the Edge code
must not write. FORCE RLS stays on every table; nothing was removed or broadened.

### edge_actor

| Table | Read | Write (policy / columns) |
|---|---|---|
| `device` | own | INSERT own (id, user_id, platform); UPDATE own (attest_counter, devicecheck_token_hash, integrity_last, last_seen, install_link_hash). Not attest_key_id / attest_public_key / fraud_voided_at |
| `evidence` | own | INSERT own; UPDATE own (course_id, facility_id, summary, integrity, attestation_grade, catalog_version, status, claimed_*, queued_input) |
| `play` | own | INSERT own; UPDATE own (score columns, course_id, course_disambiguated_by, held_review, status ...). The held-review cascade fires from this UPDATE |
| `play_evidence` | own | INSERT with own play AND own evidence |
| `fraud_signal` | own, columns id/user_id/kind/detail/created_at/cleared_at (not cleared_by) | INSERT own |
| `checkin_challenge` | own | INSERT own with `staff_user_id IS NULL`; UPDATE own (used_at only) |
| `checkin_token` | own | INSERT own; UPDATE own (consumed_at only) |
| `push_token` | own | INSERT own; UPDATE own (expo_token, updated_at) |
| `signin_provider_token`, `connector_account` | own, columns user_id and provider only (never the ciphertext) | none |
| `app_review_demo_account` | own | none |
| `device_reward_ledger` | own | INSERT own on the actor's own device |
| `offer_code`, `entitlement` | own (SELECT *) | UPDATE own (state, reserved_amount, activated_device_id, devicecheck_token_hash, activated_at, hold_detail; entitlement has no reserved_amount). No INSERT, no DELETE |
| `offer` | an offer on which the actor holds a code | UPDATE budget_reserved only, same predicate (residual R1) |
| `review_item` | the actor's own budget-unreserved items (columns kind, subject_table, subject_id, resolved_at) | INSERT: subject_table = offer_code, the two budget-unreserved kinds, own code |
| `audit_log` | own `play.repick` rows | INSERT own `play.repick` rows |
| `install_link_account` (P3f round 3) | rows whose `account_pseudonym` is one of the actor's own (columns install_link_hash, account_pseudonym) | INSERT for the actor's own pseudonym. No UPDATE, no DELETE |
| `catalog_version`, `catalog_id_ledger`, `catalog_facility`, `catalog_course`, `catalog_hole` | `USING (true)` (new policies; 0008's name `authenticated` and are untouched) | none |
| `catalog_signing_key`, `catalog_kid_revocation`, `catalog_rescore_backlog` | `USING (true)`, columns only: (kid, public_key_b64url, revoked_at), (kid, recorded_at), (course_id, done_at) | none |

No DELETE or TRUNCATE on any table. Account deletion is `private.delete_my_data_for_actor()`.

### edge_system

| Table | Access |
|---|---|
| `catalog_version`, `catalog_kid_revocation` | SELECT, INSERT (append-only: no UPDATE) |
| `catalog_signing_key` | SELECT (kid, public_key_b64url, revoked_at) |
| `catalog_id_ledger` | SELECT, INSERT, UPDATE (status, verified_in_version, tombstoned_at, merged_into, split_from) |
| `catalog_trail`, `catalog_designer`, `catalog_facility`, `catalog_hole` | SELECT, INSERT, UPDATE (non-id columns) |
| `catalog_course` | SELECT, INSERT and UPDATE of the importer's columns; never the geometry columns |
| `catalog_roster_version`, `catalog_roster_member` | SELECT, INSERT |
| `catalog_rescore_backlog` | SELECT, INSERT (course_id, reason, catalog_version), UPDATE (cursor_*, done_at, finished_at, swept) |

Everything else, including every PII-registered table, is denied. Cross-user work goes through the definers below.

### Functions

| Function | Callable by | What it does |
|---|---|---|
| `private.actor_uid()`, `private.bind_actor(uid)` | edge_actor | the binding (section 3) |
| `private.bind_delegate_for_queued_evidence(uuid)`, `private.bind_delegate_for_rescore(bigint, uuid)` | edge_system | delegate binders; return the bound uid |
| `private.bind_actor_internal(uuid, text)` | nobody | the shared core of the three binders |
| `private.hit_actor_rate_limit(key, window, max)` | edge_actor | builds `<uid>:<key>` in the database (the exact format the 0022 purge matches); window 1s..1 day, max 1..1,000,000; never raises over the cap |
| `private.hit_system_rate_limit(key, window, max)` | edge_system | builds `system:<key>` |
| `private.delete_my_data_for_actor()`, `private.export_my_data_for_actor()` | edge_actor | the 0015/0022/0021 functions for the BOUND `kind = user` actor; no uid argument |
| `private.record_consumed_nonce(hash, expires_at)` | edge_actor, service_role | the nonce tombstone insert (section 5) |
| `private.device_link_signals_for_actor(device)` | edge_actor | `app.device_link_signals` across accounts for the actor's own device (live devices and the tombstone) |
| `private.list_queued_catalog(limit)` | edge_system | queued rows and their owners; **no `queued_input`** |
| `private.list_rescore_plays(course, after_created_at, after_id, limit)` | edge_system | the keyset page of plays at a course with an open backlog row |
| `private.purge_fix_coords(retention_days, limit)` | edge_system | the fix-coordinate retention purge across users; retention pinned to 1..30 days |
| `app.activate_offer_code`, `app.activate_entitlement`, `app.reserve_offer_for_code`, `app.release_offer_budget`, `app.release_account_reservations`, `app.record_install_link` | edge_actor | the P3f invoker-rights functions, unchanged; `p_user_id` is data, not authority (the own-row policies make another user's id a `P0002`) |
| `private.account_pseudonyms(uuid)`, `private.validate_and_register_pseudonym_hmac_id(uuid)` | edge_actor (and service_role as before) | run by the tombstone policy / trigger as the writing role (residual R3) |

Not granted to any edge role: `resolve_held_*`, `mark_account_devices_fraud_voided` (admin paths),
`reserve_offer_budget` / `consume_offer_budget`, `dedupe_receipt_fingerprint`, `app.device_link_signals` (it would
silently undercount under own-row policies), `private.hit_rate_limit`, `private.delete_my_data`,
`private.export_my_data`, the purge functions.

Every new function is SECURITY DEFINER, owned by `private_definer`, `search_path = ''`, inside the 0020/0022
ownership bracket, in `private.function_inventory` (with the new `expected_edge_actor` / `expected_edge_system`
columns), and has must-fail cells in `16_edge_role.sql`.

## 5. Triggers, and why the held-review cascade is NOT redefined

- **Held-review cascade** (`app.play_held_review_cascade`, 0017; P3f round 3 only reordered its locks). It stays an
  invoker-rights trigger. It is safe under edge_actor because (1) the play, its codes and its entitlements belong to
  one user (the composite FKs force `play.user_id = code.user_id`), (2) edge_actor has UPDATE on exactly the columns
  the cascade writes under the same own-row policy, and `SELECT ... FOR UPDATE` on `offer_code`, `offer` and
  `entitlement` (the round-3 lock order) needs only those UPDATE grants and policies, and (3) the P3f reservation
  trigger that the state change fires runs as the same role and is covered by the `offer` / `review_item` policies.
  A later change to the cascade body therefore needs nothing from this work, and there is no cascade block to
  re-derive on a rebase. Proven in `16_edge_role.sql` section 10a (rows move, budget reserved, expiry paused,
  deferred guards accept the result).
- **Nonce tombstone** (`app.checkin_challenge_tombstone_nonce`, 0017): redefined in 0031, the one trigger function
  that had to change. It now calls `private.record_consumed_nonce`, which inserts and turns the unique violation
  into the same `23514` error. A nonce recorded once can never be recorded again, row or no row, across commits
  (tested). The `app.attestation` twin is a partner path and is untouched.

## 6. Checks and tests

- `tools/db/verify-function-inventory.mjs` and `supabase/tests/matrix/10_function_inventory.sql`:
  - check 2 now also compares `expected_edge_actor` / `expected_edge_system` with the real EXECUTE grants;
  - **9** the membership closure of the three edge roles reaches no role outside them; none holds SUPERUSER,
    BYPASSRLS, CREATEROLE, CREATEDB, REPLICATION or INHERIT; only `edge_gateway` can log in; nobody else can
    `SET ROLE` to one; `edge_gateway` is a SET TRUE / INHERIT FALSE member of the other two;
  - **10** every policy that applies to edge_actor or edge_system (directly or through PUBLIC) equals a row of
    `private.edge_policy_allowlist` (role, command, deparsed text), and every row names a live policy, both
    directions. A checked-in fixture `supabase/tests/fixtures/edge_policy_exprs.txt` makes a self-consistent
    policy+row edit show as a diff, like `definer_policy_exprs.txt`;
  - **11** edge policies read no identity source but `private.actor_uid()` (no `auth.uid()`/jwt/GUC/`session_user`/
    `current_user`; the only function dependencies allowed are `actor_uid` and, for the pseudonym-keyed tombstone,
    `account_pseudonyms`); an actor-scope policy must contain it; an open-read policy must be `SELECT USING (true)`;
  - **12** no edge_system policy or privilege on any PII-registered table (retention or export registry); no edge
    role holds a privilege outside schema `app`, or on an `app` table without FORCE RLS.
  Each has a must-fail fixture in the matrix (a planted policy, grant, membership or attribute) proving it fires.
  Check 6 and the new fixture read through `psqlJsonRows`: a deparsed sub-select policy contains real newlines, which
  the tab/newline `psql()` helper would split into bogus rows.
- `supabase/tests/matrix/16_edge_role.sql` runs as a real `edge_gateway` connection (it reconnects with `\c`; see
  its header). It covers: no role, SET ROLE escalation (from edge_gateway and from inside each role), the roles
  cannot rewrite their own boundary, unbound sees nothing on every table, forged session variables are ignored, the
  binding rules (double bind, savepoint rollback, after COMMIT), the own-row matrix (select, update by row count,
  insert) for A against B on every table with a control on each, column and privilege limits, no `private.*`
  access, the edge_system importer statements and definers, the delegate binders and their misuse, and the
  must-pass flows (cascade, activation including the budget-held path, nonce tombstone across a COMMIT, rate-limit
  increments committing, the purge keeping the `me-delete` bucket, delete and export, PostGIS, the cross-account
  link signal, the install-link tombstone). Phase 0 seeds three throw-away users (committed), phase 2 removes
  them with `private.delete_my_data`.

## 7. Deviations from the original design, and why

1. **Migration numbers 0030/0031**, not "the next numbers after 0027" (0029 is the P3f pseudonym domain-separation migration).
2. **No grant of `edge_gateway` to `CURRENT_USER` for the harness.** The harness reconnects as `edge_gateway`
   instead, because `SET ROLE` escalation can only be tested from a connection whose session user is
   `edge_gateway`.
3. **`fraud_signal` is not insert-only.** P3f reads the actor's own open `attestation_failed` and once-keyed
   signals (columns exclude `cleared_by`).
4. **The held-review cascade is not redefined and gets no definer** (section 5). The design planned
   `private.cascade_play_held_review` with the GUC pattern; it turned out to be unnecessary.
5. **The shared offer budget row is written under a policy, not a definer wrapper** (R1): a wrapper would mean
   redefining P3f's functions.
6. **Tables the design only gestured at**: `offer`, `offer_code`, `entitlement`, `device_reward_ledger`,
   `review_item`, `audit_log`, `app_review_demo_account`, `install_link_account`, and their column grants.
7. **Three definers the design did not list**: `device_link_signals_for_actor` (the P3f function under edge_actor
   silently undercounts and fails open), `purge_fix_coords` (edge_system cannot touch `evidence`), and the
   rate-limit key bounds.
8. **`list_queued_catalog` omits `queued_input`.** The raw coordinates leave the owner's transaction only to the
   owner: the drain re-reads the row after binding the delegate. PR3 must follow.
9. **`pd_fix_coords_read` is a GUC-scoped window**, not row-narrow. An UPDATE re-checks the NEW row against the
   SELECT policy (the 0016 `_r` companion finding), and a purged row no longer carries the key a narrow policy
   would test. The window is opened and closed inside `purge_fix_coords`; the UPDATE policy and the column grant
   do not depend on it.
10. **Check 12 also checks privileges, FORCE RLS and schema reach**, not only policies.
11. **`edge_policy_allowlist` has a checked-in fixture** (the design had the allowlist only).
12. **Test-support changes**: `rewards-isolation.test.ts` now matches function DEFINITIONS (it grepped every
    migration for `app.activate_`, which 0031's GRANTs trip); `verify-function-inventory.mjs` check 6 reads through
    JSON rows; `16_edge_role.sql` has no `finish()` (it counts rows its own ROLLBACKs discard).

## 8. Residual risks

- **R1** edge_actor can UPDATE `offer.budget_reserved` (only that column, only on an offer where it holds a code,
  bounded by the CHECK constraints). The reservation trigger and the P3f functions are invoker-rights and write it
  as the writing role.
- **R2** edge_actor can UPDATE its own `offer_code` / `entitlement` state columns directly, bypassing the activation
  functions' backstops. Same trust boundary as binding any uid. PR5: move activation behind definers.
- **R3** `private.account_pseudonyms(uuid)` accepts any uid, so edge_actor can compute any account's vault-keyed
  pseudonym. No worse than `bind_actor(any uid)`; it reveals only an HMAC.
- **R4** `record_consumed_nonce` can be called directly: it can burn a nonce hash the caller already knows (a DoS of
  one challenge). It cannot un-burn one.
- **R5** a binding row (uid + pid) outlives its transaction until the pid is reused. UNLOGGED, one row per
  backend, dead to `actor_uid()`.
- **R6** the actor can still bind any uid (section 3).
- **R7** PostgreSQL 16+ (`GRANT ... WITH INHERIT FALSE, SET TRUE`, `pg_auth_members.set_option`), `xid8`.
  `[unverified]` on a real Supabase project: `CREATE ROLE`/`ALTER ROLE ... LOGIN PASSWORD` for the project's own
  `postgres`, Supavisor tenant config for the new user, and `pg_hba` limits for it.

## 9. What PR2-PR4 must watch

- **Every Repo statement must stay inside the column grants.** A statement that writes or reads a column outside
  them fails with `42501` at run time, not at deploy time. `SELECT *` is a `42501` on the column-grant tables
  (`fraud_signal`, `signin_provider_token`, `connector_account`, `review_item`, `audit_log`, and the key / revocation /
  backlog tables). `UPDATE ... RETURNING` re-checks the new row against the SELECT policy.
- **Rate-limit keys:** the callers currently pass `<uid>:<key>`; the wrappers add the prefix. Pass the bare key.
  System buckets gain a `system:` prefix.
- **`app.device_link_signals`** is denied to edge_actor: `Repo#rewards.androidInstallSignals` must call
  `private.device_link_signals_for_actor`.
- **Drain / rescore** become: edge_system lists, binds the delegate for ONE row, `SET LOCAL ROLE edge_actor`, works,
  commits. One bind per transaction; a delegate cannot delete or export; `queued_input` is read as the owner.
- **`deleteMyData`** is `app.release_account_reservations(uid)` then `private.delete_my_data_for_actor()` in one
  bound transaction. `deleteAuthUser` uses the admin client, which this work does not touch (PR5).
- **Each transaction pays one more round trip** (the bind). Put it first, before any savepoint, and keep the
  15 s / 12 s time budgets in mind.
- **Run the whole Deno suite in both harness modes against the edge role** (PR2 behind a temporary
  `EDGE_DB_MODE`, default legacy, both modes in CI). PR4 flips the default, deletes the legacy path and adds the
  lint pass (no `service_role` / `set role` literals except the two allowed, no `SUPABASE_DB_URL`, no stray
  `.begin(` / `.savepoint(`, no `set_config(` / `current_setting(` in TypeScript).
- **New GET endpoints:** JWT client plus the `api.my_*` views, not `privileged.ts`.
- **P3 follow-ups that touch the earn path** (`offer_code_enforce_max_redemptions` counts only visible codes under
  edge_actor) need a definer; edge_actor cannot insert `offer_code` today.

## 10. Sequencing

1. **PR1 (this): database only.** 0030 + 0031, provisioning script, checks 9-12, matrix 16.
2. PR2: `privileged.ts` behind a temporary `EDGE_DB_MODE`; startup self-check (session_user = edge_gateway, no
   super / bypassrls in the membership closure); single `openScopedTx(kind, bind, op)`.
3. PR3: the system path (`withDelegatedActor`, the list definers).
4. PR4: flip the default, delete the legacy path, add the lint pass. Gate before the first deploy.
5. PR5 (optional): revoke `service_role` DML on `app.*` and EXECUTE on `private.*`; JWT-verifying binder; activation
   behind definers (R2).

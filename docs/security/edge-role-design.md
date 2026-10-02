# Edge Function NOBYPASSRLS role: design, as built (PR1, PR1b: database; PR2: the TypeScript behind a switch)

Accepted follow-up 6 of the P3c gate (`docs/security/p3-money-path-requirements.md`, "Updated Accepted follow-ups"):
before the first real deploy, the Edge Function connection moves from a blanket `service_role` (BYPASSRLS)
to a dedicated NOBYPASSRLS login role with actor-scoped policies or SECURITY DEFINER functions.

This document started as the design written against `02a422e` and is now updated to what PR1 and PR1b built. They are
the database side only: migrations `0030_edge_role_core.sql` and `0031_edge_role_policies.sql` (PR1, merged) and
`0032_edge_role_hardening.sql` (PR1b, the security-gate findings), the provisioning script, the inventory checks 9-13
and the pgTAP file `supabase/tests/matrix/16_edge_role.sql`. PR2 (section 11) routes the TypeScript through it behind the
temporary `EDGE_DB_MODE` switch (default `legacy`, so nothing that works today changes); PR3-PR4 finish the move. `service_role`, `anon` and `authenticated` are untouched, so nothing that works
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
  from an environment variable or from stdin; there is no argument that takes it. **The plaintext never reaches the
  server (PR1b, finding M1).** The script computes the SCRAM-SHA-256 verifier itself (PBKDF2-HMAC-SHA256, 4096
  rounds, a fresh 16-byte salt, python3 stdlib, the password handed to the child on stdin) and sends
  `PASSWORD 'SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>'`. The earlier form sent the plaintext, and a FAILING
  `ALTER ROLE` is logged in full when `log_min_error_statement` is `error` (the default). It refuses an empty,
  multi-line or non-printable-ASCII password (no SASLprep here; a generated password always qualifies) and re-checks
  the role afterwards. `tools/db/test-provision-edge-login.sh` (run by `test.sh`) proves three things: the verifier
  is valid (a real SCRAM-SHA-256 login with the plaintext through a temporary `pg_hba` rule; a wrong and a missing
  password are refused), a provisioning run that FAILS (as a role without CREATEROLE) leaves no plaintext in the
  server log, and, as the control that makes the second claim meaningful, the old plaintext form does leak into the
  same log. A verifier in a log is only an offline-guess target against 4096 PBKDF2 rounds.
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
  play at the course of an open backlog row. **These preconditions are caller-controllable for edge_system (PR1b,
  L4):** edge_system may INSERT its own `catalog_rescore_backlog` row for any course, which makes "an open backlog
  row at that course" true for it, so it can bind the owner of any play at any course. The same holds for a queued
  evidence row only through edge_actor (edge_system cannot insert evidence). Restricting the backlog INSERT is not
  cheap (the importer writes those rows legitimately), and it is moot under R6: the runtime that holds edge_system
  can already bind any uid with edge_actor. The preconditions bound a BUG in the importer, not a compromised runtime. They bind with `kind = 'system_delegate'`. The caller then does
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
| `device` | own | INSERT own (id, user_id, platform); UPDATE own (attest_counter, devicecheck_token_hash, integrity_last, last_seen, install_link_hash). Not attest_key_id / attest_public_key / fraud_voided_at. `attest_counter` is MONOTONIC (trigger, PR1b M2) |
| `evidence` | own | INSERT own, and `device_id` NULL or the actor's own device (PR1b M3); UPDATE own (course_id, facility_id, summary, integrity, attestation_grade, catalog_version, status, claimed_*, queued_input) |
| `play` | own | INSERT own; UPDATE own (score columns, course_id, course_disambiguated_by, held_review, status ...). The held-review cascade fires from this UPDATE |
| `play_evidence` | own | INSERT with own play AND own evidence |
| `fraud_signal` | own, columns id/user_id/kind/detail/created_at/cleared_at (not cleared_by) | INSERT own |
| `checkin_challenge` | own | INSERT own with `staff_user_id IS NULL` on the actor's own device (PR1b M3); UPDATE own (used_at only; one-way trigger) |
| `checkin_token` | own | INSERT own on the actor's own device AND own challenge (PR1b M3); UPDATE own (consumed_at only; SET-ONCE trigger, PR1b M2: cannot be reset or moved) |
| `push_token` | own | INSERT own on the actor's own device (PR1b M3); UPDATE own (expo_token, updated_at) |
| `signin_provider_token`, `connector_account` | own, columns user_id and provider only (never the ciphertext) | none |
| `app_review_demo_account` | own | none |
| `device_reward_ledger` | own | **none** (PR1b M4: only the activation definers write it) |
| `offer_code`, `entitlement` | own (SELECT *) | **none** (PR1b M4). State, reservation and activation columns move only through `private.activate_*_for_actor` and the cascade definer. `SELECT ... FOR UPDATE` is refused too (it needs UPDATE) |
| `offer` | an offer on which the actor holds a code | **none** (PR1b M4: R1 closed). `budget_reserved` is written only by the P3f functions running as `private_definer` |
| `review_item` | **none** (PR1b L5/M4) | **none**: `reserve_offer_for_code` writes and reads it as `private_definer` |
| `audit_log` | own `play.repick` rows | INSERT own `play.repick` rows whose `subject_id` is one of the actor's own plays (PR1b L5) |
| `install_link_account` (P3f round 3) | rows whose `account_pseudonym` is one of the actor's own (columns install_link_hash, account_pseudonym) | INSERT for the actor's own pseudonym, under the key that produced it, on an install the actor's own device is linked to (PR1b L5). No UPDATE, no DELETE |
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
| `private.delete_my_data_for_actor()`, `private.export_my_data_for_actor()` | edge_actor | the 0015/0022/0021 functions for the BOUND `kind = user` actor; no uid argument. Since PR1b `delete_my_data_for_actor` first calls `app.release_account_reservations(uid)` itself, so the shared offer budget is handed back inside the one call |
| `private.activate_offer_code_for_actor(code, device, token_hash, decision, hold_detail)`, `private.activate_entitlement_for_actor(...)` | edge_actor | PR1b M4. The unchanged P3f `app.activate_*` run as `private_definer` with the BOUND `kind = user` actor's uid (no user argument; a system delegate is refused). `app.activate_*` is no longer callable by edge_actor |
| `private.hold_play_rewards_for_actor(play)` | edge_actor | PR1b M4. The held-review cascade for a HELD play of the bound actor (any binding kind), called by the trigger function; the body is `app.hold_play_rewards(play)` (service_role and `private_definer` only) |
| `private.record_consumed_nonce(hash, expires_at)` | edge_actor, service_role | the nonce tombstone insert (section 5) |
| `private.device_link_signals_for_actor(device)` | edge_actor | `app.device_link_signals` across accounts for the actor's own device (live devices and the tombstone) |
| `private.list_queued_catalog(limit)` | edge_system | queued rows and their owners; **no `queued_input`** |
| `private.list_rescore_plays(course, after_created_at, after_id, limit)` | edge_system | the keyset page of plays at a course with an open backlog row |
| `private.purge_fix_coords(retention_days, limit)` | edge_system | the fix-coordinate retention purge across users; retention pinned to 7..30 days (1..30 in PR1; the importer uses 30) |
| `app.record_install_link` | edge_actor | the P3f invoker-rights tombstone writer, unchanged (its INSERT is held to the actor's own device and key by the L5 policy) |
| `private.account_pseudonyms(uuid)`, `private.validate_and_register_pseudonym_hmac_id(uuid)` | edge_actor (and service_role as before) | run by the tombstone policy / trigger as the writing role (residual R3) |

Not granted to any edge role: `resolve_held_*`, `mark_account_devices_fraud_voided` (admin paths),
`reserve_offer_budget` / `consume_offer_budget`, `dedupe_receipt_fingerprint`, `app.device_link_signals` (it would
silently undercount under own-row policies), `private.hit_rate_limit`, `private.delete_my_data`,
`private.export_my_data`, the purge functions, and (PR1b M4) `app.activate_offer_code`, `app.activate_entitlement`,
`app.reserve_offer_for_code`, `app.release_offer_budget`, `app.release_account_reservations`, `app.hold_play_rewards`.

**What `private_definer` holds for the activation definers (PR1b, all actor-keyed, all in
`private.definer_policy_allowlist` and `definer_policy_exprs.txt`):** SELECT/UPDATE on the bound actor's own
`offer_code` and `entitlement` rows; SELECT on its own `device`, `play`, `fraud_signal`, `device_reward_ledger` rows
and INSERT on its own ledger rows; SELECT on an `offer` the actor holds a code on, plus UPDATE of `budget_reserved`
only (column grant); SELECT/INSERT on `review_item` for the two budget kinds on one of the actor's own codes.
0027's rule "private_definer must not be given a grant on app.offer" protected the DELETE branch of
`app.offer_code_reservation_sync`, which asks `has_table_privilege('app.offer', 'UPDATE')`. That is a TABLE-level
question: a column grant leaves it false, so a bare DELETE still does not release, and
`delete_my_data_for_actor` therefore releases first.

Every new function is SECURITY DEFINER, owned by `private_definer`, `search_path = ''`, inside the 0020/0022
ownership bracket, in `private.function_inventory` (with the new `expected_edge_actor` / `expected_edge_system`
columns), and has must-fail cells in `16_edge_role.sql`.

## 5. Triggers, the held-review cascade, and the one-way columns

- **Held-review cascade** (`app.play_held_review_cascade`, 0017; locks reordered by P3f round 3). PR1 left it an
  invoker-rights trigger because edge_actor could write the reward rows under own-row policies. PR1b (M4) took that
  write away, so the cascade now has two lanes. Its BODY moved, unchanged, into `app.hold_play_rewards(play_id)`.
  The trigger function calls it directly when the invoking role can write the reward rows itself
  (`has_table_privilege('app.offer_code', 'UPDATE')`: service_role, the table owner), exactly as before; otherwise
  (edge_actor) it calls `private.hold_play_rewards_for_actor(play_id)`, which checks that the play is a HELD play of
  the bound actor and runs the same body as `private_definer` under the actor-keyed policies. The P3f reservation
  trigger the state change fires then runs as `private_definer` too. Proven in `16_edge_role.sql` section 10a (rows
  move, budget reserved, expiry paused, deferred guards accept the result; a code not backed by the play is untouched;
  a delegate-bound rescore can hold the owner's play). `15_rewards_activation.sql` N5 now reads the lock order from
  `app.hold_play_rewards`.
- **One-way columns** (PR1b M2, for every role): `app.checkin_token_consumed_at_once` refuses any UPDATE that touches
  `consumed_at` once it is set (no reset to NULL, no move, no identical re-write; modelled on 0017's
  `checkin_challenge_used_at_once`), and `app.device_attest_counter_monotonic` refuses a lower `attest_counter`.
  Both close a replay window edge_actor's column grants had opened.
- **Nonce tombstone** (`app.checkin_challenge_tombstone_nonce`, 0017): redefined in 0031, the one trigger function
  that had to change. It now calls `private.record_consumed_nonce`, which inserts and turns the unique violation
  into the same `23514` error. A nonce recorded once can never be recorded again, row or no row, across commits
  (tested). The `app.attestation` twin is a partner path and is untouched.

## 6. Checks and tests

- `tools/db/verify-function-inventory.mjs` and `supabase/tests/matrix/10_function_inventory.sql`:
  - check 2 now also compares `expected_edge_actor` / `expected_edge_system` with the real EXECUTE grants;
  - **9** the membership closure of the three edge roles reaches no role outside them; none holds SUPERUSER,
    BYPASSRLS, CREATEROLE, CREATEDB, REPLICATION or INHERIT; only `edge_gateway` can log in; nobody else can
    `SET ROLE` to one; `edge_gateway` is a SET TRUE / INHERIT FALSE member of the other two; and (PR1b L2) no
    membership of an edge role carries ADMIN OPTION unless its holder is a superuser or a CREATEROLE role (the
    migrating role);
  - **10** every policy that applies to edge_actor or edge_system (directly or through PUBLIC) equals a row of
    `private.edge_policy_allowlist` (role, command, deparsed text), and every row names a live policy, both
    directions. A checked-in fixture `supabase/tests/fixtures/edge_policy_exprs.txt` makes a self-consistent
    policy+row edit show as a diff, like `definer_policy_exprs.txt`;
  - **11** edge policies read no identity source but `private.actor_uid()` (no `auth.uid()`/jwt/GUC/`session_user`/
    `current_user`; the only function dependencies allowed are `actor_uid` and, for the pseudonym-keyed tombstone,
    `account_pseudonyms`); an actor-scope policy must contain it; an open-read policy must be `SELECT USING (true)`;
  - **12** no edge_system policy or privilege on any PII-registered table (retention or export registry); no edge
    role holds a privilege outside schema `app`, or on an `app` table without FORCE RLS, **in every non-system
    schema** (PR1b L2: not a fixed list; extension-owned relations such as postgis' `spatial_ref_sys` are exempt);
    and no edge role can CREATE in any schema (`has_schema_privilege`);
  - **13** (PR1b L1) no SECURITY DEFINER function in `app` / `api` / `private` reads an UNQUALIFIED `pg_*` relation.
    edge_actor holds TEMP, and `pg_temp` is searched before `pg_catalog` for relations even with `search_path = ''`,
    so a temp table named `pg_constraint` would shadow the catalog under a definer (it failed closed through
    `delete_my_data`'s post-condition, but it should not be shadowable at all). 0032 qualified `delete_my_data`'s four.
    The check scans ALL definers, a superset of "reachable from edge_*"; comments are stripped and a `pg_*` name
    followed by `.` or `(` (a schema qualifier, a function) is not a relation read.
  - **L3** (PR1b) is an asserting DO block at the top of 0032, not a check: it refuses to run if a pre-existing
    edge role holds SUPERUSER / BYPASSRLS / REPLICATION / CREATEROLE / CREATEDB / INHERIT, if edge_actor or
    edge_system can log in, if an edge role is a member of any role but `edge_gateway -> edge_actor | edge_system`,
    or if a role outside the set is a member of an edge role other than a superuser / CREATEROLE role holding it
    without SET or INHERIT. (0030's `CREATE ROLE IF NOT EXISTS` skips a role that already exists, however it is set.)
  Each has a must-fail fixture in the matrix (a planted policy, grant, membership, schema, definer or attribute) proving it fires.
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
  link signal, the install-link tombstone). PR1b added: section 7b (every direct write to the offer budget, a code's
  or entitlement's state, the ledger and the review queue is refused; the invoker-rights P3f functions are not
  callable; the cascade definer refuses a play that is not a held play of the actor), 7c (M2: the legitimate consume
  and counter advance still work, the reset and the rollback are refused), 7d (M3: foreign-device and foreign-challenge
  rows are refused, and the foreign id and a NONEXISTENT id fail with an identical SQLSTATE and message, so the FK
  existence oracle is closed), the activation definers (own code, idempotent replay, foreign code `P0002`, foreign
  device `42501`, unbound and delegate refused), L5 cells, the session-reuse cells for the three GUC windows (10j: a
  window reads empty after a COMMIT, a planted non-uuid value does not raise `22P02` in a definer's read, planted
  windows do not widen an export or a list), and the committed cells (10k: the purge window across a COMMIT; B's
  deletion handing its reservation on a shared offer back, read by D who holds another code on that offer).
  Phase 0 seeds three throw-away users (committed); phase 2 removes them with `private.delete_my_data` and, as the
  table-owning harness role through a temporary CURRENT_USER policy, the entitlement and tombstone rows
  `delete_my_data` keeps by design, so the file is **re-runnable on the same cluster** (verified three times in a
  row in each harness mode).

## 7. Deviations from the original design, and why

1. **Migration numbers 0030/0031**, not "the next numbers after 0027" (0029 is the P3f pseudonym domain-separation migration).
2. **No grant of `edge_gateway` to `CURRENT_USER` for the harness.** The harness reconnects as `edge_gateway`
   instead, because `SET ROLE` escalation can only be tested from a connection whose session user is
   `edge_gateway`.
3. **`fraud_signal` is not insert-only.** P3f reads the actor's own open `attestation_failed` and once-keyed
   signals (columns exclude `cleared_by`).
4. **The held-review cascade** (PR1: not redefined, no definer; PR1b: two lanes, section 5). The design planned
   `private.cascade_play_held_review` with the GUC pattern; PR1b built it differently, with the body extracted into
   `app.hold_play_rewards` and an actor-keyed definer, because the GUC window would not have worked for service_role.
5. **The shared offer budget row** (PR1: written under a policy, residual R1; PR1b: edge_actor has no write on it at
   all). The activation definers do NOT redefine P3f's functions: they call the unchanged `app.activate_*`, which run
   as `private_definer`. That is why PR1b needed no edit to 0027/0029.
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
12. **PR1b names and shapes the gate did not dictate.** The definers are `private.activate_*_for_actor` (no user
    argument; the gate said "keyed to the actor's own code, amount never caller-chosen", which the P3f functions
    already satisfy once the actor is the binding's); `private.delete_my_data_for_actor` now releases the account's
    reservations itself (PR2 no longer calls `app.release_account_reservations`); `purge_fix_coords` requires 7..30
    days; `pd_device_link_read` compares the GUC as text.
13. **The FK existence oracle is closed, not documented** (finding M3). The gate expected the nonexistent-id FK
    error to stay different. RLS `WITH CHECK` runs BEFORE the foreign-key trigger, so with the own-device /
    own-challenge `EXISTS` in the policy both a foreign id and a nonexistent id fail the same WITH CHECK (42501, same
    message); the FK is never reached. Proved by comparing the two error strings in `16_edge_role.sql` 7d.
14. **`SELECT ... FOR UPDATE` on reward rows is gone for edge_actor** (it needs UPDATE). `Repo#rewards.lockOwnReward`
    must drop `FOR UPDATE`; the activation definers take the row lock themselves before deciding.
15. **Test-support changes**: `rewards-isolation.test.ts` now matches function DEFINITIONS (it grepped every
    migration for `app.activate_`, which 0031's GRANTs trip); `verify-function-inventory.mjs` check 6 reads through
    JSON rows; `16_edge_role.sql` has no `finish()` (it counts rows its own ROLLBACKs discard).

## 8. Residual risks

- **R1 (closed in PR1b, M4)** edge_actor could UPDATE `offer.budget_reserved` on an offer it held a code on, anywhere
  in `[0, cap - used]`, and could call `release_offer_budget` with an arbitrary amount. Now: no UPDATE grant, no
  policy, no EXECUTE; the counter moves only inside the P3f functions running as `private_definer`, by the offer's
  `face_value` or the code's own `reserved_amount`, for the bound actor's own codes.
- **R2 (closed in PR1b, M4)** edge_actor could set its own `offer_code` / `entitlement` state directly (`earned` ->
  `issued`). Now: no UPDATE grant at all; state moves only through the activation definers and the cascade definer.
  The gate also asked for `checkin_token.consumed_at` (reset to NULL: presence-token replay) and `device.attest_counter`
  (rolled back 100 -> 1: App Attest anti-replay) to be listed with R2: they are closed too, by the M2 triggers, for every
  role, not merely for edge_actor.
  What remains of its spirit: the scoring columns edge_actor may write on its own `play` (notably `held_review`) feed
  the activation backstops, so an actor with a compromised runtime could un-hold its own play before activating. That
  is inside the R6 trust boundary (the runtime computes the score); a one-way `held_review` would also forbid the
  legitimate re-score that lifts a hold, so it is not done here. It is called out for the PR4 gate.
- **R3** `private.account_pseudonyms(uuid)` accepts any uid, so edge_actor can compute any account's vault-keyed
  pseudonym. No worse than `bind_actor(any uid)`; it reveals only an HMAC.
- **R4** `record_consumed_nonce` can be called directly: it can burn a nonce hash the caller already knows (a DoS of
  one challenge). It cannot un-burn one.
- **R5** a binding row (uid + pid) outlives its transaction until the pid is reused. UNLOGGED, one row per
  backend, dead to `actor_uid()`.
- **R6** the actor can still bind any uid (section 3). Honest corollary for PR1b: M2/M3/M4 stop a BUG or an injected
  statement in an otherwise honest handler from reaching another user's rows, another user's device, the shared budget,
  or a replay window. They do not stop a fully compromised runtime, which can bind any uid and then do whatever that
  user may do, including activating that user's rewards through the definers.
- **R8** `device.install_link_hash` stays writable by edge_actor on its own device (the install-link substitute reads
  it); a user can therefore choose which install their device is linked to. The substitute already treats the hash as an
  unauthenticated hint (0027).
- **R7** PostgreSQL 16+ (`GRANT ... WITH INHERIT FALSE, SET TRUE`, `pg_auth_members.set_option`), `xid8`.
  `[unverified]` on a real Supabase project: `CREATE ROLE`/`ALTER ROLE ... LOGIN PASSWORD` for the project's own
  `postgres`, Supavisor tenant config for the new user, and `pg_hba` limits for it.

## 9. What PR2-PR4 must watch

(PR2 has done the items on rewards, deletion, export, rate-limit keys, `device_link_signals` and `lockOwnReward` below; see section 11.
What it did NOT do and PR3 / PR4 still must: the delegate flow, the importer repo as edge_system, the lint pass, and deleting `legacy`.)

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
- **`deleteMyData`** is just `private.delete_my_data_for_actor()` in one bound transaction (PR1b: it releases the
  account's reservations itself; do NOT call `app.release_account_reservations`, edge_actor cannot). `deleteAuthUser`
  uses the admin client, which this work does not touch (PR5).
- **Rewards (PR1b):** activation is `private.activate_offer_code_for_actor(code, device, token_hash, decision,
  hold_detail)` / `activate_entitlement_for_actor(...)` (no user id; `kind = user` binding only). Drop `FOR UPDATE`
  from `lockOwnReward`. `review_item`, the ledger, `offer_code`/`entitlement` state and `offer` budget are not writable
  or (review_item) readable by edge_actor; the "budget held" review item is written and deduped inside the definer.
  The earn path, when built, needs a definer of its own (it inserts `offer_code` and reserves at earn time).
- **A challenge and its token must be inserted in two statements.** A single-CTE `WITH c AS (INSERT challenge ... RETURNING id) INSERT
  checkin_token ... SELECT id FROM c` is REFUSED under edge_actor: the token's own-challenge `EXISTS` (0032 M3) runs against the
  statement's snapshot, which cannot see the challenge the same statement is inserting. The Repo already uses two statements.
- **App Attest key registration (0034, `devices-attest-key`):** the key columns of `app.device` (`attest_key_id`, `attest_public_key`,
  `attest_registered_at`, `attest_retired_key_hashes`) are written ONLY through `private.register_attest_key_for_actor(device, key_id,
  public_key)` (no user id; `kind = user` bindings only), which runs `app.register_attest_key` as `private_definer` under the actor-keyed
  policy `pd_edge_act_device_update`. `Repo#attestKey.register` calls it in `EDGE_DB_MODE=edge` (and `app.register_attest_key` as
  service_role in legacy mode); both modes run `attest-key.deno.test.ts` in CI. `app.register_attest_key` is not callable by edge_actor. 0034 added no edge_actor policy and no edge_policy_allowlist row.
  The counter trigger now allows exactly one decrease (a replacement by a never-used key, decided by content), so edge_actor's own
  `attest_counter` column grant still cannot lower a counter. Proved in `17_attest_key_registration_edge.sql`.
- **One-way columns (PR1b):** a consume of an already-consumed `checkin_token` and an `attest_counter` decrease are
  `23514`. The verifier's `WHERE attest_counter < $new` and the consume's `WHERE consumed_at IS NULL` already avoid
  both; a retry that re-sets the same value on a consumed token now fails loudly instead of being a no-op.
- **App Attest key re-registration (not built yet) needs a definer.** `device.attest_key_id` / `attest_public_key` are not in
  edge_actor's UPDATE grant, and the monotonic trigger (0032 M2) refuses an `attest_counter` reset, so registering a NEW key for a
  device (which restarts its counter) must be a purpose-built definer that does both, in one place, for the bound actor's own device.
- **Own-device references (PR1b):** inserting `checkin_challenge`, `checkin_token`, `evidence` or `push_token`
  naming a device (or challenge) that is not the actor's own is `42501` whether it exists or not.
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

1. **PR1 (merged): database only.** 0030 + 0031, provisioning script, checks 9-12, matrix 16.
   **PR1b (this): the security-gate findings.** 0032, SCRAM provisioning, checks 9/12 extended and 13, matrix 16/10/15.
2. **PR2 (this): `privileged.ts` behind a temporary `EDGE_DB_MODE`** (section 11); startup self-check (session_user =
   edge_gateway, no super / bypassrls in the membership closure); single `openScopedTx(kind, bind, op)`; migration 0033.
3. PR3: the system path (`withDelegatedActor`, the importer repo as edge_system, the list definers). **Not done in PR2**:
   it is not small (the importer repo's statements, the drain's `queued_input` re-read as the row's owner, new
   orchestrator signatures and their unit tests), so `import-catalog` stays on the legacy pool in `edge` mode.
4. PR4: flip the default, delete the legacy path, add the lint pass. Gate before the first deploy.
5. PR5 (optional): revoke `service_role` DML on `app.*` and EXECUTE on `private.*`; JWT-verifying binder; activation
   behind definers (R2).

## 11. PR2: the TypeScript behind `EDGE_DB_MODE` (as built)

**The switch.** `EDGE_DB_MODE` is `legacy` (the default; today's `service_role` path, byte-for-byte) or `edge`. It, and
`GOLFRAVEN_EDGE_DB_URL`, are read ONLY in `supabase/functions/_shared/privileged.ts` (the lint's allow-listed site); anything but
`legacy` / `edge` is a configuration error, never a silent default. CI runs the whole Deno integration suite in BOTH modes
(`tools/db/test-deno-integration.sh`, called by `tools/db/test.sh`, which clones the database once per mode because the suite is
not re-runnable on one database), in both HARNESS_MODEs.

**`edge` mode.**
- A second pool is opened from `GOLFRAVEN_EDGE_DB_URL` (connecting as `edge_gateway`). The first use of a pool runs the **startup
  self-check** (`assertEdgeConnectionSafe`): `session_user` is `edge_gateway`; nothing in its membership closure is SUPERUSER or
  BYPASSRLS; it is a member of none of `service_role`, `authenticated`, `anon`, `authenticator`, `private_definer`, `supabase_admin`,
  `postgres`. Any failure is a plain `Error` (a 500 from every handler: fail closed) and is **not cached**, so the next request
  re-checks. A success is remembered for the pool's life (one check per pool); the per-transaction assertion below still runs every time.
- **`openScopedTx(kind, bind, op)`** is the one way a transaction is opened: (1) `SET LOCAL ROLE edge_actor | edge_system`; (2) the
  three timeouts (statement, lock, and transaction on PG17+); (3) the bind (`private.bind_actor(uid)` via `userBind(uid)`; the system
  kind binds nothing); (4) an assertion that `current_user` is the expected role, that role is neither SUPERUSER nor BYPASSRLS, and
  `private.actor_uid()` equals the identity the caller MEANT (`bind.expectedUid`). The bind is a separate step from the expectation,
  so a bind that bound somebody else (a bug, a forged value) fails closed before `op` runs. `withOwnership`, `withOwnershipBatch`,
  `hitRateLimitForActor` (`private.hit_actor_rate_limit`, bare key) and `hitSystemRateLimit` (`private.hit_system_rate_limit`) go through it;
  rate limits keep their own short transaction.
- Repo changes, each identical in legacy: `me.deleteMyData` is `private.delete_my_data_for_actor()` (no `release_account_reservations`
  call: the definer releases first), `me.exportMyData` is `export_my_data_for_actor()`, `rewards.applyActivation` is
  `private.activate_*_for_actor`, `rewards.androidInstallSignals` is `private.device_link_signals_for_actor`, and `rewards.lockOwnReward`
  takes its row lock through `private.lock_own_reward_for_actor` (0033).
- **Why the lock stayed.** PR2's first attempt dropped `FOR UPDATE` on the argument that the activation definers lock the row. The
  integration suite refuted it ("two simultaneous activations of one reward issue it once": `["issued", "held_review"]`): the handler
  DECIDES (hold vs issue) from state it read BEFORE those functions lock, so a racing second request that read `earned` saw the first's
  ledger row, decided "repeat user", and held an already-issued code. A definer's `FOR UPDATE` lasts until the transaction ends, so
  `lock_own_reward_for_actor` (0033) gives the Repo exactly the lock it had; the M1 deadlock probe and the delete-vs-activation race
  probe pass unchanged in both modes.
- No `SELECT *`, `RETURNING *` or CTE challenge+token insert exists in `privileged.ts` (the Repo inserts a challenge and its token in
  separate statements); `RETURNING` / `ON CONFLICT` statements run under the SELECT policies (the whole suite passes in edge mode).

**PR3 boundary (what stays legacy).** `withSystemCatalogImport` (the importer repo, the drain's list reads, the fix-coordinate purge, the
tombstone purge) stays on the legacy pool: `import-catalog` in `edge` mode needs BOTH URLs. The drain's and the rescore's per-row USER
transactions are `withOwnership` and so DO run as edge_actor, but they bind the row's owner with `bind_actor` (an edge_actor may bind any uid,
R6), not through the `bind_delegate_*` binders; PR3 replaces that once the importer repo runs as edge_system and re-reads `queued_input`
as the row's owner. The delegate binders and the list definers are still unused by TypeScript.

**Behaviour differences between the modes** (everything else is intended to be identical and is proved by the same suite in both):
1. An actor whose uid is not in `auth.users` is refused in `edge` (`bind_actor: no such user`, a 500) before any statement; in `legacy` the
   same request ran and failed only if a statement hit the FK. A verified JWT always names an existing user, so this affects only synthetic
   test actors (two catalog-promotion tests now create their user).
2. `hitSystemRateLimit` buckets are stored as `system:<key>` in `edge`, bare in `legacy` (separate counters for the same key until PR4).
   `hitRateLimitForActor` buckets are identical (`<uid>:<key>`); the database now bounds the key (<= 128 chars), window (1 s..1 day) and
   max (1..1,000,000), raising 22023, which no caller exceeds.
3. The startup self-check and the per-transaction assertions exist only in `edge`.
4. `edge` needs two URLs when `import-catalog` runs (above).
5. The drain's per-row transactions bind with `bind_actor`, not a delegate (above).
6. Account deletion and export are one definer call in `edge`, two statements (release, then delete) in `legacy`; same result.
7. In both modes (they are database changes): `checkin_token.consumed_at` is set-once, `device.attest_counter` monotonic (0032 M2), and
   a device / challenge reference must be the actor's own (0032 M3), which only edge_actor-limited writers could ever have violated.

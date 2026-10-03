# Edge Function NOBYPASSRLS role: design, as built (PR1, PR1b: database; PR2: the TypeScript behind a switch; PR3: the system path; PR4a: the proof-bound sign-in link; PR4b: edge is the only mode; PR4c: the hygiene purges, bounded sign-in purges and the lint's second pass)

Accepted follow-up 6 of the P3c gate (`docs/security/p3-money-path-requirements.md`, "Updated Accepted follow-ups"):
before the first real deploy, the Edge Function connection moves from a blanket `service_role` (BYPASSRLS)
to a dedicated NOBYPASSRLS login role with actor-scoped policies or SECURITY DEFINER functions.

This document started as the design written against `02a422e` and is now updated to what PR1 and PR1b built. They are
the database side only: migrations `0030_edge_role_core.sql` and `0031_edge_role_policies.sql` (PR1, merged) and
`0032_edge_role_hardening.sql` (PR1b, the security-gate findings), the provisioning script, the inventory checks 9-13
and the pgTAP file `supabase/tests/matrix/16_edge_role.sql`. PR2 (section 11) routes the TypeScript through it behind the
temporary `EDGE_DB_MODE` switch (default `legacy`, so nothing that works today changes); PR3 (section 13) moves the system path (the importer repo and the
drains) onto `edge_system` and the delegate binders; PR4a (section 12.1, migration `0039`) builds the one path PR3 left refused in `edge` mode, the OTP-proven cross-account Sign in with Apple link; **PR4b (section 14) finishes the move: `edge` is the only mode, the `legacy` service_role
path and `EDGE_DB_MODE` are deleted, a lint pass keeps them deleted, retention runs on its own schedule (E5), concurrent drains no longer double-process (PR3 gate P1), and the R2 `held_review` question is ruled. The deploy runbook is section 15. PR4c (section 14.8, migration `0040`) is the gate's follow-up: the two TTL hygiene purges join `retention-purge` (the owner-approved EXECUTE grant), the two sign-in purges become bounded, and the lint pass closes its six known bypass shapes.** The sections below this paragraph that
describe `EDGE_DB_MODE`, `legacy` and "PR4 must" (sections 1, 9, 11, 13) are history: read section 14 for what is true now. `service_role`, `anon` and `authenticated` are untouched in the database (PR5 is where `service_role`'s DML on `app.*` is revoked), but nothing in the Edge runtime connects as or switches to `service_role` any more.
Items marked `[unverified]` were not checked against a real Supabase project.

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
| `private.offline_seed_for_actor(device, rotate)`, `private.offline_code_record_step_for_actor(device, seed_version, step, facility)` | edge_actor | **0045 (P4.2b-3a).** The offline staff code (build plan §7.6). The first returns the TOTP seed of the BOUND `kind = user` actor's own device (zero rows for any other, no error), optionally rotating `app.device.offline_seed_version` first; the seed is DERIVED in the database (HMAC-SHA256 under the Vault key `offline_seed_key`), never stored. The second is the staff lane's atomic replay record (`app.offline_code_step`, `INSERT ... ON CONFLICT DO NOTHING`), refused unless the actor holds a staff or manager scope at the facility, and refused for the actor's own device (22023). Both are bound-actor wrappers with no uid argument |
| `private.offline_seed_derive(user, device, version)` | **nobody** | **0045.** The only reader of `offline_seed_key`; no role holds EXECUTE (the wrappers above and the staff-lane wrapper P5 adds call it as the definer). `edge_actor` cannot read `vault.decrypted_secrets` either |
| `private.activate_offer_code_for_actor(code, device, token_hash, decision, hold_detail)`, `private.activate_entitlement_for_actor(...)` | edge_actor | PR1b M4. The unchanged P3f `app.activate_*` run as `private_definer` with the BOUND `kind = user` actor's uid (no user argument; a system delegate is refused). `app.activate_*` is no longer callable by edge_actor |
| `private.hold_play_rewards_for_actor(play)` | edge_actor | PR1b M4. The held-review cascade for a HELD play of the bound actor (any binding kind), called by the trigger function; the body is `app.hold_play_rewards(play)` (service_role and `private_definer` only) |
| `private.record_consumed_nonce(hash, expires_at)` | edge_actor, service_role | the nonce tombstone insert (section 5) |
| `private.device_link_signals_for_actor(device)` | edge_actor | `app.device_link_signals` across accounts for the actor's own device (live devices and the tombstone) |
| `private.list_queued_catalog(limit)` | edge_system | queued rows and their owners; **no `queued_input`** |
| `private.list_rescore_plays(course, after_created_at, after_id, limit)` | edge_system | the keyset page of plays at a course with an open backlog row |
| `private.purge_fix_coords(retention_days, limit)` | edge_system | the fix-coordinate retention purge across users; retention pinned to 7..30 days (1..30 in PR1; the importer uses 30) |
| `private.purge_consumed_nonce()`, `private.purge_rate_limit_buckets()` | edge_system (and service_role) | **0040 (PR4c, owner decision 2026-10-02)**: the two TTL hygiene purges, 5000 rows per call, run as `retention-purge` steps (section 14.8). The only EXECUTE grant 0040 makes; `edge_actor`, `anon` and `authenticated` are refused |
| `app.record_install_link` | edge_actor | the P3f invoker-rights tombstone writer, unchanged (its INSERT is held to the actor's own device and key by the L5 policy) |
| `private.account_pseudonyms(uuid)`, `private.validate_and_register_pseudonym_hmac_id(uuid)` | edge_actor (and service_role as before) | run by the tombstone policy / trigger as the writing role (residual R3) |

Not granted to any edge role: `resolve_held_*`, `mark_account_devices_fraud_voided` (admin paths),
`reserve_offer_budget` / `consume_offer_budget`, `dedupe_receipt_fingerprint`, `app.device_link_signals` (it would
silently undercount under own-row policies), `private.hit_rate_limit`, `private.delete_my_data`,
`private.export_my_data`, the purge functions (except the ones `edge_system` holds: `purge_fix_coords`, `purge_install_link_tombstones`, the two sign-in purges, and since 0040 `purge_consumed_nonce` / `purge_rate_limit_buckets`), and (PR1b M4) `app.activate_offer_code`, `app.activate_entitlement`,
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
   owner: the drain re-reads the row after binding the delegate. PR3 did (section 13: `Repo#evidence.readQueuedInput`).
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
  legitimate re-score that lifts a hold, so it is not done here. **PR4b ruling (section 14.6): confirmed, with evidence. A legitimate path
  clears `held_review` (the scorer, `Repo#play.upsertFromScore`), so the column stays writable both ways for edge_actor and the residue stays inside R6; it is
  pinned by a Deno cell and a pgTAP cell so a later one-way change fails loudly, and the earn-path definer (E4) must re-decide it.**
- **R3** `private.account_pseudonyms(uuid)` accepts any uid, so edge_actor can compute any account's vault-keyed
  pseudonym. No worse than `bind_actor(any uid)`; it reveals only an HMAC.
- **R4** `record_consumed_nonce` can be called directly: it can burn a nonce hash the caller already knows (a DoS of
  one challenge). It cannot un-burn one.
- **R5** a binding row (uid + pid) outlives its transaction until the pid is reused. UNLOGGED, one row per
  backend, dead to `actor_uid()`.
- **R6** (PR4a adds nothing to it and takes nothing from it: section 12.1, "What a fully compromised runtime can still do") the actor can still bind any uid (section 3). Honest corollary for PR1b: M2/M3/M4 stop a BUG or an injected
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
PR3 did the delegate flow and the importer repo as edge_system (section 13). PR4b did the lint pass and deleted `legacy` (section 14).)

- **Every Repo statement must stay inside the column grants.** A statement that writes or reads a column outside
  them fails with `42501` at run time, not at deploy time. `SELECT *` is a `42501` on the column-grant tables
  (`fraud_signal`, `signin_provider_token`, `connector_account`, `review_item`, `audit_log`, and the key / revocation /
  backlog tables). `UPDATE ... RETURNING` re-checks the new row against the SELECT policy.
- **Rate-limit keys:** the callers currently pass `<uid>:<key>`; the wrappers add the prefix. Pass the bare key.
  System buckets gain a `system:` prefix.
- **`app.device_link_signals`** is denied to edge_actor: `Repo#rewards.androidInstallSignals` must call
  `private.device_link_signals_for_actor`.
- **Drain / rescore** (done in PR3, section 13): edge_system lists, binds the delegate for ONE row, `SET LOCAL ROLE edge_actor`, works,
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
- **Run the whole Deno suite against the edge role** (PR2 ran it behind a temporary `EDGE_DB_MODE`, both modes in CI; **done in PR4b: it runs once, in the only mode, in both HARNESS_MODEs**).
  PR4b also added the lint pass (no `service_role` / `set role` literals except the two edge roles, no `SUPABASE_DB_URL`, no stray
  `.begin(` / `.savepoint(`, no `set_config(` / `current_setting(` in TypeScript, no `EDGE_DB_MODE`; section 14.3).
- **New GET endpoints:** JWT client plus the `api.my_*` views, not `privileged.ts`.
- **P3 follow-ups that touch the earn path** (`offer_code_enforce_max_redemptions` counts only visible codes under
  edge_actor) need a definer; edge_actor cannot insert `offer_code` today.

## 10. Sequencing

1. **PR1 (merged): database only.** 0030 + 0031, provisioning script, checks 9-12, matrix 16.
   **PR1b (this): the security-gate findings.** 0032, SCRAM provisioning, checks 9/12 extended and 13, matrix 16/10/15.
2. **PR2 (this): `privileged.ts` behind a temporary `EDGE_DB_MODE`** (section 11); startup self-check (session_user =
   edge_gateway, no super / bypassrls in the membership closure); single `openScopedTx(kind, bind, op)`; migration 0033.
3. **PR3 (this): the system path** (`withDelegatedActor`, the importer repo as edge_system, the list and purge definers); no migration
   (section 13). Not done in PR2 because it is not small (the importer repo's statements, the drain's `queued_input` re-read as the row's
   owner, new orchestrator signatures and their unit tests); `import-catalog` stayed on the legacy pool in `edge` mode until PR3.
3a. **PR4a: the proof-bound cross-account sign-in link** (migration 0039, section 12.1). The owner decided (2026-10-02) to build it rather than ship the `501` as the production answer; PR4b deletes `legacy`.
4. PR4b (built, section 14): flip the default, delete the legacy path, add the lint pass, schedule retention independently (E5), lock the drain row (PR3 gate P1), rule on R2. **No migration** (the planned `0040` was not needed). Gate before the first deploy.
5. PR5 (optional): revoke `service_role` DML on `app.*` and EXECUTE on `private.*`; JWT-verifying binder; activation
   behind definers (R2).

## 11. PR2: the TypeScript behind `EDGE_DB_MODE` (as built)

> **History (PR4b).** The `EDGE_DB_MODE` switch, the `legacy` mode and everything below that compares the two modes were deleted in PR4b (section 14.1). `edge` is the only mode; this section is kept
> because the `edge` half of it (the self-check, `openScopedTx`, the Repo changes) is exactly what runs.

**The switch.** `EDGE_DB_MODE` is `legacy` (the default; today's `service_role` path; see difference 8 below for the one place it is NOT byte-for-byte what it was before PR2) or `edge`. It, and
`GOLFRAVEN_EDGE_DB_URL`, are read ONLY in `supabase/functions/_shared/privileged.ts` (the lint's allow-listed site); anything but
`legacy` / `edge` is a configuration error, never a silent default. CI runs the whole Deno integration suite in BOTH modes
(`tools/db/test-deno-integration.sh`, called by `tools/db/test.sh`, which clones the database once per mode because the suite is
not re-runnable on one database), in both HARNESS_MODEs.

**`edge` mode.**
- A second pool is opened from `GOLFRAVEN_EDGE_DB_URL` (connecting as `edge_gateway`). The first use of a pool runs the **startup
  self-check** (`assertEdgeConnectionSafe`): `session_user` is `edge_gateway`; nothing in its membership closure is SUPERUSER or
  BYPASSRLS; it is a member of none of `service_role`, `authenticated`, `anon`, `authenticator`, `private_definer`, `supabase_admin`,
  `postgres`. Any failure is a plain `Error` (a 500 from every handler: fail closed) and is **not cached**, so the next request
  re-checks. PR2 remembered a success for the pool's life; **PR3 repeats the check** (section 13: every 5 minutes or 1000 transactions);
  the per-transaction assertion below still runs every time.
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

**PR3 boundary (what stayed legacy in PR2; all of it moved in PR3, section 13).** In PR2 `withSystemCatalogImport` (the importer repo, the drain's
list reads, the fix-coordinate purge, the tombstone purge) stayed on the legacy pool, so `import-catalog` in `edge` mode needed BOTH URLs, and the drains'
per-row USER transactions were `withOwnership`: they ran as edge_actor but bound the row's owner with `bind_actor` (an edge_actor may bind any uid, R6), not
through the `bind_delegate_*` binders. PR3 replaced all of that; the delegate binders and the list definers are now used by the TypeScript.

**Behaviour differences between the modes** (everything else is intended to be identical and is proved by the same suite in both):
1. An actor whose uid is not in `auth.users` is refused in `edge` (`bind_actor: no such user`, a 500) before any statement; in `legacy` the
   same request ran and failed only if a statement hit the FK. A verified JWT always names an existing user, so this affects only synthetic
   test actors (two catalog-promotion tests now create their user).
2. `hitSystemRateLimit` buckets are stored as `system:<key>` in `edge`, bare in `legacy` (separate counters for the same key until PR4).
   `hitRateLimitForActor` buckets are identical (`<uid>:<key>`); the database now bounds the key (<= 128 chars), window (1 s..1 day) and
   max (1..1,000,000), raising 22023, which no caller exceeds.
3. The self-check (startup, and since PR3 periodic) and the per-transaction assertions exist only in `edge`.
4. ~~`edge` needs two URLs when `import-catalog` runs.~~ **Closed in PR3:** `import-catalog` in `edge` mode needs `GOLFRAVEN_EDGE_DB_URL` only.
5. ~~The drain's per-row transactions bind with `bind_actor`, not a delegate.~~ **Closed in PR3:** in `edge` they bind through `bind_delegate_*`; in `legacy` they are
   `withOwnership` (service_role has no binder).
6. Account deletion and export are one definer call in `edge`, two statements (release, then delete) in `legacy`; same result.
7. In both modes (they are database changes): `checkin_token.consumed_at` is set-once, `device.attest_counter` monotonic (0032 M2), and
   a device / challenge reference must be the actor's own (0032 M3), which only edge_actor-limited writers could ever have violated.
8. **The 24-month install-link tombstone purge runs in BOTH modes** (correction, PR3). The first sentence of this section used to call `legacy` "today's
   path, byte-for-byte". It is today's path plus 0033's retention purge: the owner decision of 2026-10-02 (F19) put `private.purge_install_link_tombstones`
   into the drain pass (`drainRescoreBacklog`) for every mode, so a `legacy` deployment also deletes tombstones older than 24 months, with `service_role`
   holding EXECUTE exactly as `edge_system` does. It is not an `edge`-only behaviour and it is not gated by `EDGE_DB_MODE`.
9. (PR3) The queued-catalog list no longer carries `queued_input` in EITHER mode: the drain always re-reads the raw submission inside the row's own transaction
   (`Repo#evidence.readQueuedInput`). In `legacy` this changes where the value is read from, not what the drain decides.

## 12. Addendum: the sign-in definers (migration 0035, O12), and how they run in `edge` mode (PR3 items)

0035 (`docs/security/p3-money-path-requirements.md`, "O12 — Sign in with Apple, server side") adds **no edge policy and no edge table grant**:
`private.edge_policy_allowlist` (check 10) is unchanged, `edge_actor` still reads `app.signin_provider_token (user_id, provider)` only, and the new
`private.signin_revocation_queue` is reachable by `private_definer` alone (checks 11 and 12 see nothing new). Every edge path is a definer:

| Role | Gets | Notes |
|---|---|---|
| `edge_actor` | `signin_methods_for_actor`, `signin_link_identity_for_actor`, `signin_store_token_for_actor`, `signin_unlink_identity_for_actor`, `signin_enqueue_revocations_for_actor` (no uid argument; a `kind = 'user'` binding only, a system delegate is refused); plus `signin_find_account_by_email_for_actor` (F7) and, since 0037 (L1), `peek_signin_otp_failures_for_actor`, `reserve_signin_otp_attempt_for_actor`, `release_signin_otp_attempt_for_actor` (each refuses with 42501 unless a `kind = 'user'` actor is bound in the transaction); plus `get_signin_token_kek`; plus, since 0039 (PR4a), `signin_link_identity_with_proof_for_actor` (a `kind = 'user'` binding; the proof-bound cross-account link, section 12.1) | The cores that take a uid (`signin_methods(uuid)` ...), the unbound email lookup (`signin_find_account_by_email`) and the three OTP-counter cores (`peek_` / `reserve_` / `release_signin_otp_*`) are `service_role` only: `18_signin_providers_edge.sql` proves `edge_actor` cannot call them. (This row said, before 0037, that `edge_actor` held `peek_signin_otp_failures` and a `hit_signin_otp_failure`; the second name never existed, and the first was the unbound-callable defect L1 below.) |
| `edge_system` | `claim_signin_revocations`, `complete_signin_revocation`, `purge_signin_revocation_queue`, `get_signin_token_kek`; since 0039 `purge_signin_email_proofs` (it held `signin_record_email_proof` too from 0039 until **0041 moved that EXECUTE to `edge_signin_minter`**, section 12.1.1) | The drain is system work and acts on no account. `edge_system` has no privilege on the PII-registered grant table (check 12) and, since 0041, cannot mint a proof. |
| `edge_signin_minter` (0041) | `signin_record_email_proof` and nothing else: `USAGE` on schema `private`, no table, column, policy, sequence or other function, a member of no role; `edge_gateway` is its one member (`SET TRUE`, `INHERIT FALSE`) | The only role that can write the email-proof table (through the definer), and only in a transaction with no actor bound. Section 12.1.1. |

**How `privileged.ts` runs the sign-in lane in `edge` mode (PR2, as built).** The `signin:` seam is `buildSigninRepo(trx, uid, mode)`, switched on
`mode` the same way App Attest's `register` is:
- **Per-user operations** (`methods`, `linkIdentity`, `storeToken`, `unlinkIdentity`, `enqueueRevocations`) call the `signin_*_for_actor` definers
  inside the `edge_actor` transaction `withOwnership` opens (the uid is the bound actor, never an argument). In `legacy` they call the cores as
  `service_role` with the uid as an argument. No grant or policy was broadened for this.
- **The OTP attempt counter** (the bucket key is built in the database from a 64-hex email hash; reserve is an atomic cap-check-and-increment taken BEFORE the proof is
  verified) runs in `edge` as the calling actor (`signinOtpFailuresFor(actor)`), not as a system actor, **through the `_for_actor` wrappers since 0037**
  (`buildSigninSystemOps(trx, mode)` picks the cores in `legacy` and the wrappers in `edge`). *Corrected 2026-10-02 (L1): 0035 granted the three cores straight to
  `edge_actor`. They take no user and check no binding, so any `edge_actor` connection, with no Edge code and no actor bound, could call `release` in a loop and reset
  any address's brute-force counter (release is a decrement) or `reserve` to burn another address's five attempts. The cores are now `service_role` only; the wrappers call
  `private.signin_bound_user` first (the F7 shape), so an unbound `edge_actor` and a system delegate are both refused. Must-fail cells: `18_signin_providers_edge.sql`
  (unbound, delegate, core not callable even when bound). **Honest limit:** a BOUND user actor can still `release` / `reserve` for an address of its choosing (the counter is keyed
  by the target address, not the caller), the same standing it has for `signin_find_account_by_email_for_actor`; the binding is the authorization the Edge entrypoint
  established, so this closes "any connection", not "a signed-in caller who goes around the Edge code".* Also 0037 (L2): `reserve` returns the hour window it charged and
  `release` takes that window, so a proof that straddles the top of the hour cannot refund the new window.
- **System operations** (`claim_signin_revocations`, `complete_signin_revocation`, `purge_signin_revocation_queue`, `get_signin_token_kek`) run
  in `edge` as `edge_system` through `openScopedTx("system", { expectedUid: null }, ...)` (`withSigninSystem`), the roles those definers were
  granted to in 0035. They need no `import-catalog`-style legacy pool. In `legacy` they run through `withOwnership` with the nil-uid
  `SIGNIN_SYSTEM_ACTOR` (`service_role`). `me-delete` enqueues as the actor, then revokes through the same `signinRevocationDb`.
- **The proof lane (0039, PR4a; role changed by 0041)**: `signinEmailProofs().record(...)` mints through `openScopedTx("signin_mint")` as **`edge_signin_minter`** (0039 used `edge_system`) in its OWN committed transaction (no actor bound);
  `repo.signin.linkIdentityWithProof(...)` redeems it in the per-user `edge_actor` transaction. `repo.signin.proofBoundLink` is true in `edge`, false in `legacy`; `crossAccountLink` is
  true in both. `linkIdentity` / `storeToken` (the uid-taking direct path) still refuse any account but the caller's in `edge` (`403 cross_account_link_requires_proof`).

**PR3 items (O5 in the money-path doc), recorded, not done:**
1. **The OTP-proven link to ANOTHER account (CLOSED by PR4a, migration 0039; section 12.1).** It was refused in `edge` mode (`501 email_proof_link_unavailable`,
   `repo.signin.crossAccountLink === false`) because a definer that took the target account as an argument is an "attach an identity to any account" primitive. The owner decided on 2026-10-02 to build it.
   The target is now a DATABASE fact, bound to a single-use proof; the `501` is gone in both modes (the handler keeps it only as a guard for a repo that reports `crossAccountLink === false`, which neither
   mode does).
2. `signin_find_account_by_email` is service_role only; an `edge_actor` reaches it through `signin_find_account_by_email_for_actor`, which refuses (42501) unless a kind = `user` actor is bound (an unbound actor or a system delegate learns nothing; must-fail cells in `18_signin_providers_edge.sql`). A bound user can still ask "does an account hold this email" (an id only; no worse than R3).
3. The drain and the KEK reader are `edge_system` already; PR3 only has to move `signin-revocation-drain` onto `withDelegatedActor` if that
   becomes the system path's single entry, and to retire `SIGNIN_SYSTEM_ACTOR` with the legacy path in PR4.

The definers' policies on `app.signin_provider_token` are GUC-windowed
(`app.signin.target_user_id`, text compare, exact check-7 form), not actor-keyed: the core lane has no actor binding (`bind_actor` is `edge_actor`
only and was not broadened), and the wrappers call the same cores after resolving the bound uid. `17_signin_providers.sql` group 6 and
`18_signin_providers_edge.sql` group 4 are the session-reuse cells for that window (P3a follow-up 1).

### 12.1 PR4a: the proof-bound cross-account link (migration 0039, as built)

**What the rule is.** Build plan 3.4 rule 2: an Apple identity whose verified email belongs to ANOTHER account is never auto-linked. The player proves the existing account with an email OTP to that
address, and the identity is linked to the **proven account, never to the caller**. `legacy` does it with `private.signin_link_identity(<proven uid>, ...)` as `service_role`. `edge` has no `service_role`.

**Who vouches for "the OTP verified".** Supabase Auth (GoTrue `verifyOtp`, anon key). The database cannot call GoTrue, so the Edge runtime's word that it verified is unavoidable. The design makes that word
NOT sufficient on its own and makes the link's target a database fact:

| Piece | What it is |
|---|---|
| `private.signin_email_proof` | One row per verified OTP: `caller_user_id` (the session that proved), `target_user_id` (the account whose mailbox was proven), `provider`, `email_hash`, `sub_hash` (sha256 of `provider:subject`, so the Apple `sub` itself is never stored), `created_at`, `expires_at` (the minter sets **5 minutes**; a CHECK caps any row at **10**), `consumed_at`. `caller <> target` is a CHECK. FORCE RLS, no grant to any edge or client role, four `private_definer` policies keyed on GUC windows (check-7 form), `UPDATE` only on `consumed_at`. FKs to `auth.users ON DELETE CASCADE`. |
| `private.signin_record_email_proof(caller, target, email_hash, provider, sub_hash)` **(0039 shape; superseded by 0041, section 12.1.1: raw address and subject, a session id, and `edge_signin_minter` instead of `edge_system`)** | The **only writer**. **`edge_system` EXECUTE only** in 0039 (not `edge_actor`, not `service_role`). Refuses (a) inside ANY transaction that has an actor bound (so `SET ROLE edge_system` inside a per-user transaction is not a way in; a delegate binding counts); (b) unless the proven address hashes to the target's CURRENT `auth.users.email` (the email binding is checked, not asserted); (c) unless the target's `auth.users.last_sign_in_at` is within 60 seconds of now, GoTrue's own record that a `verifyOtp` for that account just happened; (d) unless caller and target exist and differ. It also deletes a bounded batch of proofs an hour past their expiry. |
| `private.signin_link_identity_with_proof_for_actor(proof_id, provider, provider_sub, email, verified, relay, ciphertext, dek_wrapped, kek_id)` | **`edge_actor` EXECUTE only**, `kind = 'user'` binding required (an unbound actor and a system delegate get 42501). Takes the TARGET's per-account advisory lock (the lock link / unlink / store_token / enqueue / delete all take), locks the proof `FOR UPDATE` and refuses unless it is **unconsumed, unexpired (`clock_timestamp()`, not the transaction start), issued to THIS caller, for THIS provider and subject hash, for THIS address hash, and the target's address still hashes to it**; refuses an unverified or private-relay email (rule 3). Marks it consumed, then calls the 0035 cores `signin_link_identity` and `signin_store_token` on **`proof.target_user_id`**: `actor_uid()` appears nowhere below the checks. One definer does the link AND the token store, so the proof is consumed exactly once; any failure (the duplicate-identity `23505`, the one-Apple-per-account `23505`, a bad envelope) rolls the whole thing back and leaves the proof unconsumed. |
| `private.purge_signin_email_proofs()` | System work (`edge_system`, `service_role`): rows an hour past expiry. Run by `signin-revocation-drain` next to the queue purge; `private.delete_my_data` (redefined from 0032's body with exactly one added statement) deletes the account's proofs as caller or target. |
| Registries | `private.pii_retention_policy` (both user-id columns, `delete_row`), `private.pii_export_policy` (`exclude`), `private.definer_policy_allowlist` (four rows) and its fixture, `private.function_inventory` (three rows). `private.edge_policy_allowlist` and its fixture are **unchanged**; checks 9-13 pass untouched. |

**Why `edge_system` mints, and what was considered.**

| Option | Verdict |
|---|---|
| `service_role`-only minter (the suggested shape) | **Impossible in `edge` mode**: the runtime has no `service_role` pool once PR4b deletes `legacy`, and it must not keep one. |
| Option 1: mint through `edge_system`, short TTL, bound to a sub hash | **Chosen as the base.** `edge_system` is the narrowest role the runtime holds that is not the per-user lane; the proof is minted and redeemed in different transactions by different roles. |
| Option 2: make GoTrue's own result the binding, by checking `auth.users` in the database | **Chosen as the second factor, not as the binding.** On its own it cannot bind the Apple `sub`, and it is a coincidence window (anyone who signed in recently looks "proven"). Combined with Option 1 it makes the runtime's claim checkable: the minter refuses unless GoTrue's `last_sign_in_at` for the TARGET agrees, and the proof's email hash must be the target's own. |
| Option 3a: have the database verify the OTP itself from `auth.one_time_tokens` (compare `sha224(email || code)`, consume the row) | Rejected: it depends on GoTrue's internal token table, hash format and token types, none of which are a supported surface or were checked against a real project, and it would bypass GoTrue's own throttling. |
| Option 3b: redeem as the target (a short-lived token for the target's session) | Rejected: it hands the edge runtime a credential for the proven account, which is the capability this design exists not to create. |

**What a fully compromised Edge runtime can still do (R6), stated plainly** *(this is the 0039 text; 0041 moves the minter to its own role and binds the proof to a session, which changes who can mint but not R6: section 12.1.1)*. It holds the `edge_gateway` login, so it can `SET ROLE edge_actor`, `bind_actor(<any uid>)` and call the PRE-EXISTING 0035 wrapper
`signin_link_identity_for_actor` to attach any Apple identity to THAT account, with no proof at all (and `legacy` could do the same with `service_role`); it also holds the GoTrue service key, so it can cause a
`verifyOtp`-style sign-in for any user and therefore satisfy the minter's corroboration. **The proof path adds no capability a compromised runtime lacks and removes none**: it is strictly narrower than
what R6 already allows. What it buys is against the weaker attackers R6 does not describe: a **handler bug**, or an **injected statement inside a per-user (`edge_actor`-bound) transaction**, can no longer reach
another account through this feature. It cannot mint (no EXECUTE; and `SET ROLE edge_system` inside a bound transaction is refused by the minter itself); it can redeem only a proof that exists, that was issued to
THIS caller, for THIS Apple subject and THIS address, that the database checked against the target's own email and GoTrue's sign-in stamp, and that has not been used or expired. A runtime that merely
**forgets to verify the OTP** cannot mint unless the target happened to sign in within the last 60 seconds. Closing R6 itself is PR5 (a JWT-verifying binder), unchanged by this work.

**Honest limits.** (0041 changes the minter role and adds a session binding: read section 12.1.1 first; items below that it supersedes are marked.) (1) The corroboration proves "the target signed in recently", not "this caller's code was the one"; the OTP itself is still GoTrue's word relayed by the runtime, and the 5-per-hour OTP cap (0037) is
unchanged. (2) `last_sign_in_at` is `[unverified]`: GoTrue is believed to stamp it when `verifyOtp` issues its session (recalled from its token issuing path, not read from a live project); where it does not, every mint
refuses (`409 email_proof_refused`), which fails CLOSED and would show at once in the P4 spike. The `GRANT SELECT (last_sign_in_at) ON auth.users` to `private_definer` is asserted in the migration (a refused grant
only warns). (3) The window is 60 seconds either side of the database clock, so a skew between GoTrue and Postgres hosts of that size refuses genuine proofs. (4) *(Closed by 0041, L2: the mint now normalises and hashes in the database, with the redemption's expression.)* `lower()` in the database and `toLowerCase()` in
the Edge code agree for ASCII addresses; a non-ASCII address that hashes differently is refused (fail closed). (5) `private.delete_my_data` is now redefined in 0039: the next change to it must start from 0039's copy,
not 0032's. (6) Proof retention is the minter's own bounded purge, the drain's purge and the account deletion; if nothing is minted and the drain is not scheduled, an hour-stale proof (two user ids and two hashes)
can stay until the next of those.

**Proofs.** `supabase/tests/matrix/19_signin_proof_link.sql` (structure, scoping, constraints, purge, account deletion), `19_signin_proof_link_edge.sql` (the minter and redeemer as the real roles, every refusal, the
committed flow), `tools/db/test-signin-proof-concurrency.sh` (two real sessions), the Deno suite in both modes (`signin-methods.deno.test.ts`), the handler wiring in `signin-methods-handler.test.ts`. Numbers and
mutation results: `docs/security/p3-money-path-requirements.md`, "Edge role PR4a".

### 12.1.1 PR #35: hardening the proof link after the PR #31 gate (migration 0041, as built)

The PR #31 security gate passed 0039 with one LOW (L1), one LOW/NIT (L2) and one NIT (N2). This section is what 0041 does about each, what it does **not** do, and how the trust argument of 12.1 changes.

**L1: any unbound `edge_system` transaction could mint.** `edge_system` is the role of the revocation drain, the queue operations, the catalog importer (which parses publisher input) and `retention-purge`. 0039 let all of them
call the minter, and the only target-specific corroboration was "the target's `last_sign_in_at` is within 60 s", which any ordinary sign-in by the victim satisfies. A statement injected into any of those lanes could mint
(attacker, victim) and then wait for the victim to sign in; redeeming still needs a second statement inside the attacker's own bound per-user transaction.

| | What 0041 builds | Result |
|---|---|---|
| **(a) A dedicated minting role** | `edge_signin_minter`: `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION`, a member of nothing, with `edge_gateway` its one member, **`INHERIT FALSE, SET TRUE`** (exactly 0030's shape for `edge_actor` / `edge_system`). `USAGE` on schema `private` (name resolution) and `EXECUTE` on `signin_record_email_proof` **moved** from `edge_system`; nothing else, ever (asserted at the end of the migration, by check 12 and by matrix 19). `openScopedTx` gained the kind `"signin_mint"` (`SET LOCAL ROLE edge_signin_minter`, the same three timeouts, the same `current_user` / SUPERUSER / BYPASSRLS assertion, and a refusal of any bind); the privileged lint's **`privileged-mint-scope`** rule lets the role name appear only inside `openScopedTx`, the kind only inside `openScopedTx` and `signinEmailProofs`, requires a string-literal kind at every `openScopedTx(` call and refuses an alias of it. | An `edge_system` transaction (drain, queue, import, retention, any statement running as that role) gets `42501 permission denied` on the mint, with perfectly valid arguments (pgTAP `19_..._edge.sql`, Deno `PR35 L1`). The "no actor bound" precondition is unchanged and holds under the new role (a bound `edge_actor`, a system delegate, or `SET ROLE edge_signin_minter` inside a bound transaction are all refused: `42501`). |
| **(b) The proof bound to the session `verifyOtp` created** | The mint takes `p_session_id` and refuses unless `auth.sessions` holds a row with that id **for the target**, created within 60 s (symmetric, like the sign-in stamp). The proof row stores the id under a **UNIQUE** index: one session mints at most one proof. The handler no longer signs the session out inside `verifyOtp`'s wrapper: `EmailOtpResult` carries `sessionId` (the `session_id` claim of the access token) and `closeSession()`; `proveEmail` calls `closeSession()` **after** the mint, in a `finally`, so exactly that session is signed out on every path (a successful mint, a refused mint, an address that changed hands, a response with no session id). `private_definer` gets `SELECT (id, user_id, created_at) ON auth.sessions`, asserted in the migration; no edge role or client role has any privilege on `auth.sessions`. | The mint now needs a value that **no edge role can read**: a live session id of the victim. The minter role cannot read `auth.sessions`; `edge_system` / `edge_actor` cannot; the id is the 122-bit random uuid only the caller of `verifyOtp` holds. |

**What was verified and what was not for (b)** (the columns were the condition for building it). `[unverified: training knowledge of GoTrue]` that `auth.sessions` has `id`, `user_id` and `created_at`; that `verifyOtp` creates a row there; that the access token's **`session_id`** claim is that row's id (GoTrue's own `/logout` identifies the session by that claim, which is why it is believed to be present in every token it issues); and that `GRANT SELECT (id, user_id, created_at) ON auth.sessions TO private_definer` is legal for the migrating role on a hosted project (0039's equivalent grant on `auth.users` is the precedent, and the grant is asserted so a refusal fails the migration, not the first mint). The harness shim reproduces the three columns only (`supabase/tests/shim.sql`). None of this was read from a live project. **If any of it is untrue the failure is closed**: every mint refuses (`409 email_proof_refused`; a token with no `session_id` logs `signin_otp_session_id_missing`), and it would show at once in the P4 spike on a real branch. That spike must confirm, in this order: the `session_id` claim is present; the `auth.sessions` row exists at the moment the mint runs (i.e. `verifyOtp` has committed it before returning); `created_at` is within the 60 s window of the database clock; the grant takes.

**L2: email normalisation.** The address and the Apple subject were hashed in JavaScript for the mint (`trim().toLowerCase()`, `sha256Hex`) and in SQL for the redemption (`lower(btrim())`, `sha256`). Every mismatch failed closed, but two implementations of one rule are the defect, and `lower()` is locale-dependent in PostgreSQL (no JavaScript function can mirror it: `'\u0130'.toLowerCase()` is `i` + U+0307, glibc's `lower` gives `i`, `C` gives the character unchanged). **Now the mint takes the RAW address and the RAW subject** and does `lower(btrim())` and `sha256` itself, with the same expression the redemption uses, on both sides of the comparison with the target's own address; JavaScript hashes neither value for the proof. Proofs: pgTAP (`19_signin_proof_link_edge.sql`, section 6b) and Deno (`PR35 L2`) run spaces, case, TAB, NBSP, EM SPACE, newline, U+0130 and plus-tags through the mint and the redeemer and assert that they agree with the plain SQL expression `lower(btrim(x)) = lower(btrim(target))` **in whatever database they run in** (they do not assert what `lower()` returns). Plus-addressing is a different address on both sides (nothing strips `+tag`); a tab, NBSP or newline is not stripped by `btrim` (it strips spaces only) and is refused at the **mint**, not later at the link.
Two related facts, stated so they are not rediscovered: (1) the Apple identity-token parser (`apple-id-token.ts`) still trims and lower-cases the `email` claim once, at parse time. That is an input normalisation applied before anything reaches the database; every comparison after it (the owner lookup, the mint, the redemption) is the database's, on that one string, so no two implementations ever compare. Removing it would also have to touch the private-relay suffix test and was left alone. (2) **The OTP failure counter** (5 per target per hour) was keyed on a hash of the JavaScript-normalised address, so two spellings the database treats as one mailbox (U+0130, a locale's case mapping) were two buckets, i.e. a spelling could buy five fresh attempts at the same victim. It is now keyed on the **target account the database resolved** (`sha256("signin-otp-target:" || owner uid)`), so every spelling shares one bucket and the bucket still names no address. The counter's columns, caps and functions are unchanged.

**N2: stale proofs visible to any `private_definer` code.** `pd_signin_proof_select` / `_delete` admitted every row an hour past its expiry to any code running as `private_definer`. They now admit stale rows only inside **the purge window**, a transaction-local GUC (`app.signin.proof_purge = 'on'`, the exact check-7 `nullif(current_setting(..., true), '')` form) that `purge_signin_email_proofs` and the mint's own bounded cleanup open and close around their `DELETE` (the `purge_fix_coords` pattern, 0030). `definer_policy_allowlist` rows and the checked-in fixture changed with them; pgTAP asserts that with no window nothing is visible or deletable, that only the exact value `on` opens it, and that a live proof is never reachable through it.

**The grants in 0041, all of them.** `GRANT edge_signin_minter TO edge_gateway WITH INHERIT FALSE, SET TRUE` (membership); `GRANT USAGE ON SCHEMA private TO edge_signin_minter`; `GRANT EXECUTE ON FUNCTION private.signin_record_email_proof(uuid, uuid, text, text, text, uuid) TO edge_signin_minter` (the move; the 0039 five-argument function and its `edge_system` grant are dropped); `GRANT SELECT (id, user_id, created_at) ON auth.sessions TO private_definer`. Nothing is granted to `edge_actor`, `edge_system`, `service_role`, `anon` or `authenticated`; no edge policy or table grant is added (`private.edge_policy_allowlist` and its fixture are unchanged).

**Registries, checks and provisioning.** `private.function_inventory` gained the column `expected_edge_signin_minter` (true for exactly one function). `tools/db/verify-function-inventory.mjs` and its matrix twin `10_function_inventory.sql` now know the role: **check 2** compares its EXECUTE per function; **check 9** puts it in the edge set (attributes, `NOLOGIN`, who can `SET ROLE` to it), requires the role to exist, requires it to be a member of nothing, forbids `edge_actor` / `edge_system` being members of it, and (for all three target roles) fails any `edge_gateway` grant row that has `INHERIT` or lacks `SET`; **check 10** fails any policy that names it; **check 12** fails any privilege of any kind on any relation or sequence in any schema (the rule for this role is *nothing*, not "only FORCE-RLS app tables"), and `CREATE` in any schema. Every one has a must-fail cell. The runtime self-check (`assertEdgeConnectionSafe`) needed no list change: `EDGE_FORBIDDEN_MEMBERSHIPS` is a deny-list of privileged roles, the minter is not one, and its closure walk already refuses a `SUPERUSER` / `BYPASSRLS` role anywhere in the login's membership closure, the minter included (Deno cell: the minter made `BYPASSRLS` is refused by the gate and by the `signin_mint` transaction's own assertion). `tools/db/provision-edge-login.sh` creates nothing and grants nothing, but it now refuses to bless a login next to a misconfigured minter (`LOGIN`, `INHERIT`, a member of any role, `edge_gateway`'s grant with `INHERIT`, `ADMIN` or without `SET`), and only notes (does not fail) when 0041 is not yet applied; `test-provision-edge-login.sh` proves both.

**How the trust argument of 12.1 changes.**

| Attacker | 0039 | 0041 |
|---|---|---|
| A handler bug, or an injected statement in a per-user (`edge_actor`-bound) transaction | cannot mint | cannot mint (unchanged); cannot redeem a proof it was not issued |
| An injected statement in a **system lane** (drain, queue, import, retention) whose authority is `edge_system` and which cannot change role | **could mint** for (attacker, victim) and wait for a sign-in | **cannot mint at all** (`42501`). This is what (a) buys, and it is a *privilege* boundary |
| The same, **if the statement can also switch role** (`SET ROLE`, `set_config('role', ...)`: `edge_gateway`, the session user of every lane, holds `SET` on all three roles) | could mint | **can reach the minter role**, as it can reach `edge_actor` (and then `bind_actor(<any uid>)`, R6). It still **cannot mint without the victim's live session id**, which it cannot read (the minter, `edge_system` and `edge_actor` have no privilege on `auth.sessions`). This is what (b) buys: a secret, not a role |
| A runtime that merely **forgets to verify the OTP** | minted if the target had signed in within 60 s | mints only with a fresh session of the target: a runtime that never called `verifyOtp` has no session id to give |
| A fully compromised runtime (R6) | unchanged | unchanged. It holds the `edge_gateway` login and the GoTrue service key, can `bind_actor(<any uid>)` and call the pre-existing 0035 wrapper to attach an identity to that account with no proof at all. 0041 adds nothing to R6 and removes nothing from it. Closing R6 is PR5 |

**Honest limits of 0041.** (1) `SET ROLE` is judged by the session user, so (a) is not a barrier against a role-switching statement; the pgTAP cell `KNOWN LIMIT (R6)` pins that (from the minter, `SET ROLE edge_actor` works) so the role is not read as more than it is. (2) (b) makes the minter's argument a secret, but the session id is also in memory in the Edge runtime for the duration of one request, and a runtime that can read its own memory is R6. (3) A session that the **victim's own** normal sign-in created is not usable by anyone who does not know its id; but the id is not bound to the *caller*: whoever calls `verifyOtp` with a valid code holds it, which is the same party the OTP already trusts. (4) The 60 s windows are still symmetric around the database clock; a larger skew refuses genuine proofs (fail closed). (5) Everything marked `[unverified]` above is unverified until the P4 spike. (6) The Apple-claim normalisation at parse time (L2, fact 1) remains a JavaScript step before the database.

**What was not built.** Nothing in the finding list was left out. Deliberately **not** done: (i) making the minter reachable only from a connection that is not `edge_gateway` (a second login for the minter). That would turn (a) into a credential boundary rather than a privilege boundary, at the cost of a second pool, a second secret and a second self-check; it is the natural next step if the owner wants (a) to hold against a role-switching injection without relying on (b), and is recorded here as a design option, not a defect. (ii) The legacy-style removal of the JavaScript trim/lower-case of the Apple claim (see L2, fact 1).

**Proofs.** pgTAP: `supabase/tests/matrix/19_signin_proof_link.sql` (the role by the catalog, the nothing-else proof, the session grant, the unique index, the N2 window), `19_signin_proof_link_edge.sql` (the minter as the real role, `edge_system` / `edge_actor` / delegate / bound refusals, the minter's lack of privilege, the session refusals, the normalisation cells), `10_function_inventory.sql` (checks 2, 9, 10, 12 for the role, with must-fail cells). Deno: `signin-methods.deno.test.ts` (`PR35 ...`: a mint from an `edge_system` transaction is refused, the minter transaction, the session binding, sign-out on every path, normalisation end to end) and `edge-role.deno.test.ts` (the self-check and the minter). Lint: `tools/service-role-lint` (`privileged-mint-scope` fixtures). Numbers and mutation results: `docs/security/p3-money-path-requirements.md`, "Edge role PR #35".

## 13. PR3: the system path (as built)

PR3 moves `import-catalog` entirely onto the edge roles. **There is no migration for the importer (0039 is PR4a's, section 12.1, and touches none of this):** every statement the importer repo runs fits inside the `edge_system`
column grants and policies 0031 already gave it (the whole catalog suites, import / drain / promotion / minimisation / drain-resilience, pass in `edge` mode, and
the pgTAP matrix 16 already proves the grants and the must-fail cells), and every cross-user read or purge the importer needs already had a definer (0030
`list_queued_catalog`, `list_rescore_plays`, `purge_fix_coords`, the two delegate binders; 0033 `purge_install_link_tombstones`). So `edge_system`'s grants, the
policies, `private.edge_policy_allowlist` and its fixture, the definer inventory and FORCE RLS are all **unchanged**. This is a claim about the current
migrations; had a statement needed a grant, the rule was the narrowest one in 0039 with an allowlist row, a fixture and must-fail cells, and never anything on
a PII table (check 12).

**What runs as what, in `edge` mode.**

| Piece | Role | Mechanism |
|---|---|---|
| Importer repo (`withSystemCatalogImport`): signing-key read, `importVersion`, ledger / directory / roster upserts, `enqueueRescore`, backlog `listOpen` / `markFinished` / `beginSweep` / `advance`, `currentSiteVersion` | `edge_system` | the existing column grants and policies, statements unchanged |
| Queued-catalog list (`queuedCatalog.listOpen`) | `edge_system` | `private.list_queued_catalog(limit)`: no `queued_input`, at most 500 rows |
| Rescore page (`rescoreBacklog.nextPlays`) | `edge_system` | `private.list_rescore_plays(course, after_created_at, after_id, limit)`: only a course with an OPEN backlog row, at most 500 rows (the orchestrator never asks for more: `MAX_RESCORE_PAGE`, because a clamp the caller does not know about would read a full page as a short one and close the course early) |
| Fix-coordinate purge | `edge_system` | `private.purge_fix_coords(30, 5000)`: retention pinned to 7..30 days, only removes the `fixCoords` key from rows that carry it |
| Install-link tombstone purge | `edge_system` | `private.purge_install_link_tombstones(5000)`: the 24 months are the function's (runs in both modes) |
| Coarse rate limit (`hitSystemRateLimit`) | `edge_system` | `private.hit_system_rate_limit` (PR2) |
| The drain's per-row transaction | starts as `edge_system`, ends as `edge_actor` | `withDelegatedActor`, below |
| The re-score's per-play transaction | starts as `edge_system`, ends as `edge_actor` | `withDelegatedActor`, below |

`import-catalog` in `edge` mode therefore needs **`GOLFRAVEN_EDGE_DB_URL` only**. `withSystemCatalogImport`'s edge branch returns before `sql()` (the legacy pool) is
reached, and no other call on the path opens it. Proved by running the whole pipeline (key read, import, both drains, both purges, the rate limit) with
`SUPABASE_DB_URL` unset and again pointing at an unusable host, with a control that the same URL breaks `legacy`
(`edge-system-path.deno.test.ts`, section A). A missing edge URL fails closed.

**`withDelegatedActor(delegate, actor, op)`** (`privileged.ts`; types in `types.ts`):

- `delegate` is `{ kind: "queued_evidence", evidenceId }` or `{ kind: "rescore", backlogId, playId }`. `actor` is the owner the caller EXPECTS (the system list's `user_id`).
- `edge`: `openScopedTx("delegate", delegateBind(...))`, one transaction: `SET LOCAL ROLE edge_system`, the three timeouts, `select private.bind_delegate_for_queued_evidence($id)`
  (valid only while that evidence row is `queued_catalog`) or `bind_delegate_for_rescore($backlog, $play)` (valid only while the backlog row is open and the play is at its course),
  then `SET LOCAL ROLE edge_actor`, then the same assertions as the user kind: `current_user = edge_actor`, not super / BYPASSRLS, and `private.actor_uid()` equals the EXPECTED
  owner. A delegate therefore acts as the owner of the row it names, and a caller that names someone else's row while expecting another user fails closed before `op` runs.
  The timeouts are set in `openScopedTx` and nowhere else (the structural pin in `with-ownership.test.ts` still counts four sites).
- A delegate-bound transaction has `kind = 'system_delegate'`: it cannot be re-bound, and `delete_my_data_for_actor`, `export_my_data_for_actor`, the reward-activation definers and the
  sign-in wrappers refuse it (42501). The drain needs none of them. Proved (`export_my_data_for_actor` is refused in a delegated transaction and works in the user-bound control).
- `legacy`: exactly `withOwnership(actor, op)` (service_role has no binder).
- The queued drain **re-reads `queued_input` as the row's owner**: `Repo#evidence.readQueuedInput(id)` (own row, `status = 'queued_catalog'`) runs first inside the per-row transaction.
  `list_queued_catalog` omits the raw submission, so raw coordinates leave the owner's transaction only to the owner. This holds in BOTH modes (the legacy list no longer selects `queued_input`
  either; one behaviour, one set of tests). A row a concurrent drain resolved between the list and the transaction reads as "gone" and is left alone (counted in `scanned` only).
- Signatures: `drainQueuedCatalog(importerRepo, withDelegatedActor, limit, deadline)`, `drainRescoreBacklog(importerRepo, withDelegatedActor, maxPlays, deadline, opts)`; the parameter type is
  `WithDelegatedActorFn` (re-exported from both orchestrators). They import nothing from `privileged.ts`; `import-catalog/index.ts` is the wiring.

**Layered defences in the binders, proved alone (pgTAP 16, cells 712-713).** `bind_delegate_for_queued_evidence` checks `status = 'queued_catalog'` in its body AND `pd_queued_catalog_read` hides every
other row from `private_definer`; `bind_delegate_for_rescore` checks `p.course_id = v_course` in its body AND `pd_rescore_play_read` shows only plays at a course with SOME open backlog row. Each
layer alone gives the same `P0002` and message, so deleting the body's predicate left every cell of matrix 16 and the whole Deno suite green (observed, by mutation, before the cells existed). The two
cells widen the policy to `true` in a rolled-back transaction, prove with a control that the row is then visible to `private_definer`, and expect the body's refusal.

**Honest limit (unchanged from section 3 / R6).** The preconditions bound a BUG in the importer, not a compromised runtime: a runtime holding `edge_system` can insert its own backlog row
for any course (L4), and a runtime holding the edge login can still `bind_actor` any uid. What PR3 buys is that the system path no longer needs the `bind_actor` escape hatch, so the
only way to act as a user in the system path is a delegate whose preconditions the database checks.

**What stays legacy-only in `edge` mode.** Nothing in `privileged.ts`'s importer, drain, rescore or purge paths. The one `edge`-mode refusal PR3 left, the OTP-proven link to ANOTHER account
(`501 email_proof_link_unavailable`), was **built in PR4a** (section 12.1, migration 0039) on the owner's decision of 2026-10-02: a proof-bound definer pair, not a definer that takes the target as an argument. The `501` is not
the production answer in either mode.

**Sign in with Apple (section 12, item 3): left as is, on purpose.** `signin-revocation-drain` (and the KEK reader, and `me-delete`'s revocation) already runs as `edge_system` through
`openScopedTx("system", ...)` (`withSigninSystem`), and it acts on no account: it claims queue rows and completes them. `withDelegatedActor` is a per-ROW USER transaction, not a single system
entry (the importer repo is `withSystemCatalogImport`, the revocation queue is `withSigninSystem`), so moving the revocation drain onto it would add a delegate binder with nothing to bind to.
`SIGNIN_SYSTEM_ACTOR` still retires with the `legacy` path in PR4.

**The periodic self-check** (carried PR2 finding). PR2 remembered a passing `assertEdgeConnectionSafe` for the pool's life, so `ALTER ROLE edge_gateway BYPASSRLS` or
`GRANT service_role TO edge_gateway` made after the first request went unseen until the worker was recycled. The schedule is now `edge-selfcheck-gate.ts`: re-check after 5 minutes since the last
success or 1000 transactions, whichever comes first (one small catalog query per repeat; nothing within the window). A failure is never remembered (the next transaction checks again, so recovery
is seen at once), concurrent callers share one in-flight check, and a failed repeat withdraws the earlier success. It narrows the window from the worker's lifetime to the interval; it does not close it,
and the per-transaction role assertion (edge_actor / edge_system gaining SUPERUSER or BYPASSRLS) still covers those two roles at once. Unit-tested (`edge-selfcheck-gate.test.ts`, fake clock) and proved against
a real cluster (`edge-role.deno.test.ts`: a BYPASSRLS login and a `service_role` membership are refused after the interval, and after the call budget inside it; reverted afterwards).

**Test harness: the throwaway password is no longer on a command line.** `tools/db/test.sh` passed `EDGE_GATEWAY_TEST_PASSWORD='...'` inside the `su -c "<string>"` for the Deno step, which `ps`
shows to any local user for the whole run. It now pipes the password on stdin, and `test-deno-integration.sh` reads one line into its own environment (`EDGE_GATEWAY_TEST_PASSWORD_STDIN=1`).

**PR4 pre-deploy check, `[unverified]`: Supavisor transaction mode and `prepare: true`.** The edge pool is built by `openPool(...)` with `prepare: true`, exactly like the legacy pool, and PR3
does not change it. Nothing in this repo has been run through Supavisor. Two things must be checked against the real project before the first deploy: (1) whether the pooler in transaction mode
accepts postgres.js's named prepared statements `[unverified — training knowledge: pooler support for named statements has varied by version and mode]`; if it does not, the edge pool needs
`prepare: false` (a one-line change in `openPool`, which shares the option with the legacy pool until PR4 deletes it); (2) that one transaction stays on one server connection end to end, because
`private.actor_binding` is keyed on the backend pid AND the transaction, and `openScopedTx` relies on `SET LOCAL ROLE`, `SET LOCAL` timeouts and the bind all landing on the same server session
(a pooler that moved a transaction's statements between server connections would fail closed, since `actor_uid()` would read NULL, but it would fail every request).

**PR4 blockers recorded by PR3** (also in `docs/security/p3-money-path-requirements.md`, "Edge role PR3"). **Status after PR4b: items 1, 2, 3, 5 and 6 are closed (section 14); 4 and 7 are deploy-time checks, written up as the runbook (section 15).**

1. Delete `legacy` (`sql()`, the `service_role` branches, `SIGNIN_SYSTEM_ACTOR`, the `hitSystemRateLimit` / `hitRateLimitForActor` legacy buckets) and add the lint pass (section 9).
2. ~~The OTP-proven cross-account link~~ **done in PR4a** (section 12.1): the proof-bound definers exist and run in `edge`; PR4b only deletes the `legacy` direct path and collapses the handler's `proofBoundLink` branch.
3. E5 (launch-blocking): both retention purges run only inside a catalog import's drain pass; schedule them independently.
4. The Supavisor / `prepare: true` check above, and the first real provisioning of `edge_gateway` on the hosted project (R7: `CREATE ROLE`, tenant config, `pg_hba`), both `[unverified]`.
5. The R2 gate ruling: `play.held_review` is writable by `edge_actor`; close it before the earn-path definer (E4) and no later than the PR4 gate.
6. `import-catalog` in production needs `GOLFRAVEN_EDGE_DB_URL` and no longer needs `SUPABASE_DB_URL`: the deploy config for that function changes with the default flip.
7. The self-check interval (5 minutes / 1000 transactions) is a default chosen without a measured cost; confirm it against real request rates (a repeat is one catalog query).

## 14. PR4b: edge is the only mode (as built)

PR4b is the last step of follow-up 6. **There is no migration** (0001-0039 are byte-identical; `tools/db/check-migrations-immutable.sh --base 8cd86f7`): every retention purge already had a bounded definer that `edge_system` may EXECUTE, `FOR UPDATE` on the drain's evidence row needs only the column `UPDATE` edge_actor already holds on that table, and the R2 ruling changes nothing in the database.
`private.edge_policy_allowlist`, its fixture, the definer inventory, FORCE RLS and checks 9-13 are untouched.

### 14.1 What was deleted

| Deleted | Where |
|---|---|
| `EDGE_DB_MODE`, `getDbMode`, `DbMode`, the `mode` parameter of `buildRepo` / `buildRewardsRepo` / `buildAttestKeyRepo` / `buildImporterRepo` / `buildSigninRepo` / `buildSigninSystemOps` | `privileged.ts` |
| the `service_role` pool: `sql()`, `_sql`, every `SET LOCAL ROLE service_role` + role assertion, every read of `SUPABASE_DB_URL` for database access | `privileged.ts` |
| `withOwnership`'s, `withOwnershipBatch`'s, `withDelegatedActor`'s, `withSystemCatalogImport`'s, `hitRateLimitForActor`'s and `hitSystemRateLimit`'s legacy branches; the legacy `private.hit_rate_limit` buckets (the bare system key); `SIGNIN_SYSTEM_ACTOR` | `privileged.ts` |
| legacy-only repo branches: `release_account_reservations` + `private.delete_my_data(uid)` / `export_my_data(uid)`, `app.activate_*` with a uid, `app.device_link_signals`, `app.register_attest_key`, the in-line `for update of oc / e`, the table scans in `purgeFixCoords` / `nextPlays` / `queuedCatalog.listOpen`, the uid-taking `signin_*` cores | `privileged.ts` |
| `SigninRepo.crossAccountLink`, `SigninRepo.proofBoundLink` (the handler always mints and redeems a proof; the `501 email_proof_link_unavailable` guard and the direct "link to the proven uid" branch are gone) | `signin/types.ts`, `signin/methods-handler.ts` |
| the second Deno pass: `EDGE_DB_MODES`, `EDGE_DB_DATABASES`, the per-mode database clones, the `for` loop | `tools/db/test.sh`, `tools/db/test-deno-integration.sh`, `.github/workflows/ci.yml` (the suite runs **once**, against one clone, in both HARNESS_MODEs) |
| `SUPABASE_DB_URL` as a test input | `supabase/tests/integration/_helpers.ts` |

Tests deleted because they existed only to prove legacy behaviour: the `EDGE_DB_MODE` accepts-only-legacy/edge cell (`edge-role.deno.test.ts`); the "control: the same URL breaks `legacy` mode" cell inside `edge-system-path.deno.test.ts`; the unit cells "a repo with NO route to another account (the guard) answers 501", "a repo with no cross-account route still links the caller's OWN identity" and "legacy shape (not proof-bound)" (`signin-methods-handler.test.ts`); the `legacy` early-returns and `getDbMode() !== "edge"` guards in `signin-methods.deno.test.ts` (the cells themselves now run unconditionally); the `service_role`-shape pins in `with-ownership.test.ts` (rewritten for `openScopedTx`). Every test that ran in both modes still runs, in edge.

### 14.2 What still uses the service-role key, and why

`SUPABASE_SERVICE_ROLE_KEY` is read in exactly two functions of `privileged.ts`, and the lint allows no others:

1. **`adminClient`**: a supabase-js client keyed with it, used only for GoTrue **admin** calls that have no database form: `auth.admin.deleteUser` (`deleteAuthUser`, from `me-delete`, after the database deletion committed). It never reaches Postgres. Removing it needs a GoTrue admin path that does not use the service key; that is not available (PR5 follow-up).
2. **`isServiceRoleBearer`**: a constant-time **comparison** of an inbound bearer token with the key, so a scheduler that holds the key (Supabase's documented cron pattern) can call `signin-revocation-drain` and `retention-purge`. It authenticates the caller and opens nothing. A leaked scheduler token buys "run an idempotent, bounded, rate-limited maintenance pass".

`verifyOtp` is **not** a use of the key: it runs with the anon key. Supabase injects the key into every function's environment whether or not code reads it `[unverified - training knowledge]`, so reading it in these two places adds no exposure. Nothing in `privileged.ts` connects to the database as `service_role`, switches to it, or names it except `EDGE_FORBIDDEN_MEMBERSHIPS`, the self-check's list of roles the edge login must **not** belong to.

### 14.3 The lint pass (design section 5 "Code")

`tools/service-role-lint/src/privileged-lint.ts` (`lintPrivilegedSource`) runs over exactly `supabase/functions/_shared/privileged.ts`, which the general rules still exempt by exact path. It reads the AST: comments are not scanned, string literals, template literals (the tagged ones are the SQL) and identifiers are.

| Rule | Fails on |
|---|---|
| `privileged-forbidden-role` | a `service_role` literal; `SET [LOCAL\|SESSION] ROLE` to anything but `edge_actor` / `edge_system` (an allow-list, case-insensitive, quoted or not, prefix lookalikes refused); `RESET ROLE`; `SET SESSION AUTHORIZATION`; a role-switch whose role is a `${...}` hole. The one exemption is the array `EDGE_FORBIDDEN_MEMBERSHIPS` |
| `privileged-db-url` | `SUPABASE_DB_URL`, `DATABASE_URL`, any `*DB_URL*` other than `GOLFRAVEN_EDGE_DB_URL` |
| `privileged-service-key` | `SERVICE_ROLE_KEY` anywhere but `adminClient` and `isServiceRoleBearer` (a deliberate widening of the brief's "outside `adminClient`": the bearer comparison, 14.2) |
| `privileged-env-access` | **any reference to `Deno`** other than the exact chain `Deno.env.get("<one string literal>")` (PR4c: an allow-list, not a shape list: `const { env } = Deno` followed by a computed name is a reference to `Deno` and fails; `toObject()`, aliasing, spreading, `Deno.readTextFile...` all fail). A `declare const Deno: T` ambient declaration is not a reference |
| `privileged-stray-transaction` | `.begin(` outside `openScopedTx`; `.savepoint(` outside `withOwnershipBatch` (the per-item isolation of one batch, itself inside an `openScopedTx` transaction; the only caller); `begin` / `savepoint` destructured off a connection |
| `privileged-stray-pool` | a call of the `postgres` driver outside `openPool` (not in the brief: a second pool is how a second path would return). **PR4c:** also any **non-call reference** to the driver (`const pg = postgres; pg(url)`, passing it, `{ postgres }`, a namespace import's member; type positions `typeof postgres` / `postgres.TransactionSql` are erased and allowed), a `openPool` **declaration with a parameter**, any **call of `openPool` with an argument**, and a driver call inside `openPool` whose first argument is not the `const` read from `Deno.env.get("GOLFRAVEN_EDGE_DB_URL")` in `openPool` itself |
| `privileged-guc-in-ts` | `set_config(` / `current_setting(` in TypeScript. The one legitimate read, the server version, now reads `pg_settings` |
| `privileged-edge-db-mode` | `EDGE_DB_MODE` in any literal or identifier |
| `privileged-global-access` (PR4c) | `globalThis` / `self` / `window` (the global object reaches `Deno` with no name to match: `globalThis.Deno.env.get(k)`), `eval`, `Function`, and dynamic `import()` in any shape. **One allow-listed use, because the real file has it:** `globalThis.addEventListener` (the closed-socket containment hook: `typeof globalThis.addEventListener` and two listener registrations; it reads no environment and builds no code) |
| `privileged-computed-member` (PR4c) | a computed member access (`a[k]`, `a?.[k]`, `const { [k]: v } = a`) whose key is not a string or number literal or a hole-less template (`db["be" + "gin"]` is `db.begin` by a name built at run time). **No allow-list was needed**: the real file has 101 computed accesses, every one a numeric literal (`rows[0]`) |
| `privileged-unsafe-sql` (PR4c) | `.unsafe(` with anything but one string literal (`t.unsafe("SET LOCAL " + "ROLE postgres")` spells the statement across two literals), and `unsafe` taken off a connection in any other shape (alias, destructure). The real file uses no `.unsafe(` at all. Independently, a top-most `+` chain of string literals is **folded** and scanned as the one string it forms, so the role / URL / key rules see `"SET LOCAL " + "ROLE postgres"` too |

Each rule has a must-fail fixture under `tools/service-role-lint/test/fixtures/privileged/bad/` (37 fixtures since PR4c), a must-pass fixture of every shape the real file uses, and cells in `test/privileged-lint.test.ts`; the real file must pass. Each rule was also proved by mutating a `/tmp` copy of the real file (money-path doc, "Edge role PR4b").
`retention-purge/index.ts` needs no special case: it is an ordinary function file, so the general rules (no `Deno` references, no driver, no client) apply to it, and it is in the CI `deno check` / `deno cache` lists.

### 14.4 E5: the independent retention schedule (launch-blocking, closed in code; scheduling is a deploy step)

`supabase/functions/retention-purge/index.ts` over the pure handler `_shared/retention/purge-handler.ts` and `privileged.ts#retentionPurgeSteps`. One run purges, **as `edge_system`**, six classes, each through a bounded definer (the first four were already EXECUTE-able by `edge_system`; the last two are PR4c's owner-approved grant, 14.8):

| Step | Definer | Bound per batch | Removes |
|---|---|---|---|
| `fix_coords` | `private.purge_fix_coords(30, 5000)` | 5000 (the definer allows 10000) | only the `fixCoords` key of evidence rows past 30 days or no longer re-pickable |
| `install_link_tombstones` | `private.purge_install_link_tombstones(5000)` | 5000 (the definer allows 100000) | tombstones older than 24 months (the function's own constant; two row-narrow policies repeat the cutoff) |
| `signin_email_proofs` | `private.purge_signin_email_proofs()` | 5000 (a constant inside the definer since 0040; was one unbounded pass) | proofs an hour past expiry |
| `signin_revocation_queue` | `private.purge_signin_revocation_queue(30 days)` | 5000 (inside the definer since 0040; was one pass) | finished (revoked / expired) rows older than 30 days; never a pending one |
| `consumed_nonce` (0040) | `private.purge_consumed_nonce()` | 5000 (inside the definer) | nonce tombstones more than 7 days past their source expiry (the policy repeats the floor) |
| `rate_limit_buckets` (0040) | `private.purge_rate_limit_buckets()` | 5000 (inside the definer) | windows whose `window_start` is more than 2 days old, any key, **including the `<uid>:me-delete:user` bucket `delete_my_data` keeps** |

- **Authentication.** The scheduler's bearer is the service-role key, compared in constant time (`isServiceRoleBearer`, the check `signin-revocation-drain` makes). A wrong or missing bearer is `401` **before** the rate limit and before any connection is used: an unauthenticated caller spends nothing. (`405` for anything but POST comes first.)
- **Rate limit.** One coarse system bucket (`system:retention-purge`, `hitSystemRateLimit`), **12 per hour**; the 13th is `429` with `retryAfterSeconds: 3600`. An hourly scheduler uses 1; the rest is headroom for a retry or a manual run.
- **Bounded per run.** A batched step repeats while a batch comes back full, at most `MAX_BATCHES_PER_STEP = 10` times (so at most 50 000 rows per step per run), and no new batch **starts** after `RUN_BUDGET_MS = 30 s`. What is left is reported `truncated` and the next run continues (the fix-coordinate, tombstone and proof purges go oldest-first; the revocation-queue, nonce and rate-limit purges delete in scan order, which a hygiene purge needs no more than idempotence for). Every step is now batched: since 0040 no step is a single unbounded DELETE that a large backlog could push past the 10 s statement timeout on every run. `complete: false` on every run for days means the backlog outruns the schedule: run it more often.
- **Idempotent.** Each purge deletes only what is already past its retention; a second run removes nothing the first did not.
- **Safe to run concurrently.** Each batch is its own short `edge_system` transaction that first takes `pg_try_advisory_xact_lock` on its step (namespace 6): a run that finds the step held reports it `busy` and moves on instead of waiting for, or deadlocking over, the same rows, and two runs never double-count a batch.
- **Failure isolation.** One class failing does not stop the others; the response is `500 retention_step_failed` carrying every step's result with only a short code (the SQLSTATE) per failure, never database text, so a scheduler's monitoring sees it.
- **What it does not do.** The **72-hour expiry of a pending revocation row** (which wipes its credential material) is not a purge and is not separate: it runs inside `private.claim_signin_revocations`, i.e. inside `signin-revocation-drain`. **That drain's schedule is therefore also a retention dependency** (section 15). The drain and the importer keep their own purge calls (cheap, idempotent); retention no longer *depends* on them.
- **Formerly "not covered" (decision for the owner, 2026-10-02: now covered).** `private.purge_consumed_nonce()` and `private.purge_rate_limit_buckets()` were `service_role`-only with nothing scheduling them. The owner approved granting `edge_system` EXECUTE on exactly those two and making them the last two steps; see 14.8. The `[unverified]` alternative recorded here before (a `pg_cron` job as the hosted admin role) is no longer needed.

### 14.5 PR3 gate P1: concurrent drains double-processed a row (closed)

`Repo#evidence.readQueuedInput`, the first statement of the drain's per-row transaction, now reads the row `FOR UPDATE SKIP LOCKED`. A second drain that listed the same row finds it locked and gets **no row**, which the drain already reads as "gone" (counted in `scanned` only), so it skips the row instead of re-deriving it.

- **`SKIP LOCKED`, not `NOWAIT`.** NOWAIT raises `55P03`, which `mapPgTimeoutError` turns into a 503; the drain would count the row `errored` and, for an aged row, try to age it out. SKIP LOCKED is the answer this call already has for "not yours to work on any more", and it does not wait, so a drain never sits behind another for the 5 s lock timeout. A row the first drain committed while the second was queued fails the `status = 'queued_catalog'` re-check (READ COMMITTED re-evaluates a locked row's new version), so it too is "gone".
- **Privileges: nothing was broadened.** `SELECT ... FOR UPDATE` needs `UPDATE` privilege on at least one column and passes the `UPDATE` policy's `USING`. edge_actor holds column `UPDATE` on `app.evidence` (course_id, status, claimed_*, queued_input ... , 0031) and the `edge_actor_evidence_update` policy `user_id = actor_uid()`, so the lock works as-is for a user-bound and a delegate-bound transaction alike (both run as edge_actor). That is the reverse of the reward rows (design section 7, item 14), where edge_actor holds no `UPDATE` at all and the lock needed `private.lock_own_reward_for_actor`.
- **Proof: two real sessions** (`edge-system-path.deno.test.ts`, section D). Session A holds a delegated transaction open after reading the row; session B's re-read returns no row, without waiting, and the row is readable again once A commits. Then a **real second drain** over the held row makes no resolve attempt and reports no error (a blocked drain would have hit the lock timeout), and the next pass resolves the row exactly once.
- **Observation, not changed.** A second drain whose bind happens **after** the first committed gets `P0002` from the delegate binder (the row is no longer `queued_catalog`) before `readQueuedInput` runs, so it counts that row `errored` / `stillQueued` rather than "gone". The row is correctly left alone; only the counter is misleading. Mapping that `P0002` to "gone" in the drain is a small follow-up.

### 14.6 The R2 `held_review` ruling

**Ruling: `edge_actor` keeps write access to `held_review` in both directions; the residue stays inside R6.** Nothing was made one-way, and nothing was broadened.

Every path that sets or clears the column (searched: `grep -rn held_review` over migrations, `privileged.ts`, the handlers, the rules package and the tests):

| Path | Sets | Clears | Runs as |
|---|---|---|---|
| `Repo#play.upsertFromScore` (`INSERT ... ON CONFLICT DO UPDATE SET held_review = excluded.held_review`): the evidence intake handler, the queued-evidence drain's redrain, the re-score backlog drain, the re-pick | yes | **yes** | edge_actor (user-bound, or delegate-bound) |
| `app.play_held_review_cascade` (0017, 0027, 0033) / `private.hold_play_rewards_for_actor` | no (it reacts to the column; it moves the backing code and entitlement to `held_review`, **one-way**: it fires only on `NEW.held_review AND NOT OLD.held_review`) | no | invoker / `private_definer` |
| reviewer tooling `app.resolve_held_offer_code` / `resolve_held_entitlement` (0027) | no | **no**: they move the reward row; a held PLAY is not cleared by a review of the code | `service_role` only |
| every other writer | none exist | none exist | |

So a legitimate edge_actor path **does** clear it. The evidence: `computeHeldReview` in `packages/rules/src/score-play.ts` is `held = no attested contribution AND some non-attested one`, recomputed from **all** the day's evidence on every re-score, so a play first scored held (an unattestable staff-hard scan, `score-play-golden.test.ts` #15) is un-held when an attested booking-hard contribution arrives (`score-play-regate3.test.ts`: `[unattestable staff-hard, attested booking-hard]` gives `heldReview = false`). A one-way column would forbid that re-score, and moving it behind a definer is a change to the scorer's trust model (R6: the runtime computes the score), not a hardening of it.

Why the residue is acceptable now: (1) lifting a hold **releases nothing**: the cascade is one-way and the backing code stays `held_review` until a reviewer's `app.resolve_held_*` moves it (a pgTAP cell asserts it in the same cell as the counted write); (2) an actor with a compromised runtime can already bind any uid (R6) and decide `activate` for its own rewards within the database's backstops (LOW-3), so "un-hold your own play" adds nothing it lacked. **Pinned**, so a later change is a deliberate diff: `16_edge_role.sql` (the cascade cell: the lift is one counted write and releases nothing) and `edge-role.deno.test.ts` ("R2 ruling": a play scored held is un-held through the real Repo as edge_actor). **For the earn-path definer (E4):** re-decide this when `offer_code` can be inserted at earn time, because an earn that trusts `play.held_review` as a backstop is only as strong as who may write it; the options then are a `held_review` that only a definer may clear (the scorer calls it) or an earn path that re-derives the hold itself.

### 14.7 Mutation proofs and numbers

Numbers, the mutation table and the `[unverified]` list are in `docs/security/p3-money-path-requirements.md`, "Edge role PR4b".

### 14.8 PR4c (migration `0040`): the hygiene purges, the bounded sign-in purges, and the lint's second pass (as built)

The follow-up to PR4b: one owner-approved change plus the PR4b security gate's LOW findings. `0001`-`0039` are byte-identical (`tools/db/check-migrations-immutable.sh --base d4ab836`).

**The one new grant** (owner decision 2026-10-02), the only grant this change makes:

```
GRANT EXECUTE ON FUNCTION private.purge_consumed_nonce()     TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_rate_limit_buckets() TO edge_system;
```

No table or column privilege, no policy, no role membership, no `edge_policy_allowlist` / `definer_policy_allowlist` row and no fixture changes; FORCE RLS is untouched and checks 9-13 are unchanged. Both functions already ran under their own `private_definer` policies (`pd_purge_consumed_nonce_expired[_r]`, which repeat the 7-day floor; `pd_rate_limit_purge[_r]`). The migration **asserts the grant took** (`has_function_privilege` for `edge_system`, `service_role`, `edge_actor`, `anon`, `authenticated`, on both functions, and that the two sign-in purges kept theirs: a refused `GRANT` only warns, so it fails in the migration rather than on the first scheduled run) and that exactly four inventory rows changed. `private.function_inventory` now expects `expected_edge_system = true` for the two; the existing inventory gate (`10_function_inventory.sql` check 2, `verify-function-inventory.mjs`) is what proves nothing else gained a grant, because every function in `app` / `api` / `private` is inventoried and compared role by role.

**Bounds, read first.** Both hygiene functions were age-bounded and **neither was row-bounded**: one `DELETE` of the whole expired backlog. `purge_rate_limit_buckets` had never run, so its first scheduled run would have deleted every window since launch in one statement, and a backlog that exceeds the 10 s statement timeout would fail the same way on every run and never shrink. So both are redefined (`0040`, the ownership bracket), each with an explicit row bound, and the same bound is given to the two sign-in purges that were single `DELETE`s (PR4b gate LOW-3):

| Function | Change | Owner / search_path / grants / inventory identity |
|---|---|---|
| `purge_consumed_nonce()` | `CREATE OR REPLACE`, returns `bigint` as before, `DELETE ... WHERE nonce_hash IN (SELECT ... LIMIT 5000)` | unchanged (`private_definer`, `search_path=''`, grants kept, same inventory row) |
| `purge_signin_email_proofs()` | `CREATE OR REPLACE`, oldest first (`expires_at` is indexed), `LIMIT 5000` | unchanged |
| `purge_signin_revocation_queue(interval)` | `CREATE OR REPLACE`, `LIMIT 5000`; the 1..365 day bound is untouched | unchanged |
| `purge_rate_limit_buckets()` | **`DROP` and recreate with the same name and no arguments**, returning `int` (it returned `void`; `CREATE OR REPLACE` cannot change a return type and a batched step needs the count), `LIMIT 5000`. Its grants were **re-made, not widened**: `REVOKE ... FROM PUBLIC`, `GRANT ... TO service_role` (what 0007 granted), then the new `edge_system` grant | owner `private_definer` (created inside the bracket), `search_path=''`, same inventory identity (`''`) |

The bound is a **constant inside each definer** (`v_limit constant int := 5000`), not a parameter: a caller cannot raise it, and no signature (so no inventory identity and no other caller: the drain's `purge` / `purgeEmailProofs` still call the same names) changes. `RETENTION_DEFINER_BATCH_ROWS = 5000` in `privileged.ts` is the same number; a Deno cell proves a full batch of each is exactly that many rows, so the two cannot drift apart silently. The three tables with no index on their age column (`consumed_nonce`, `rate_limit_bucket`, `signin_revocation_queue`) have no `ORDER BY`: an ordered batch would sort the whole backlog on every call, and a hygiene purge needs no order. The 7-day / 2-day / 1-hour / age floors are unchanged, and `matrix 20` proves, for the two floors that are enforced **twice** (the nonce's 7 days and the proof's 1 hour: function body and policy), that the **body alone** still keeps a live row when the policies are widened to `true` in a rolled-back transaction (otherwise a mutant of the body is masked by the policy).

**`<uid>:me-delete:user`.** `delete_my_data` deliberately keeps each deleted account's `<uid>:me-delete:user` bucket (so a retry of the same deletion stays rate-limited); the requirements document assumed a "nightly sweep" would remove it. `purge_rate_limit_buckets` removes any bucket whose `window_start` is more than **2 days** old, whatever its key; the me-delete window is one day, so the bucket is removed between one and two days after its window ENDED (a day after: still kept; a day and an hour: gone). Proved against the real flow (`hit_rate_limit`, then `delete_my_data`, then the purge) in `matrix 20` and in `retention-purge.deno.test.ts`.

**`retention-purge`.** Two more steps (`consumed_nonce`, `rate_limit_buckets`), same pattern as the others (per-step `pg_try_advisory_xact_lock`, batch cap, the 30 s deadline, failure isolation), and the two sign-in steps are now batched (`batchLimit` 5000 instead of one unbatched pass), so a backlog larger than one batch is cleared across batches. **The catalog import's own fix-coordinate purge (and, for the same reason, its tombstone purge) now takes the same per-step try-lock** (`tryRetentionStepLock`, PR4b NIT): while `retention-purge` holds a step the import's pass skips it and reports 0 instead of running a second purge over the same rows; a skipped pass loses nothing, the other run is doing exactly that work.

**The lint pass.** Six bypass shapes the first version missed (PR4b gate LOW-1): `const { env } = Deno` then a computed name; `globalThis.Deno.env.get(k)`; aliasing the driver (`const pg = postgres; pg(url)`); `openPool(anyUrl)` from any function; computed member access `db["be" + "gin"]`; `t.unsafe("SET LOCAL " + "ROLE postgres")`. Fixes: (a) `openPool` takes **no parameter** and reads `GOLFRAVEN_EDGE_DB_URL` itself (its caller `edgeSql` passes nothing); (b) any reference to `Deno` or `globalThis` outside the one allow-listed shape each; (c) any non-callee reference to the driver identifier; (d) a computed member access with a non-literal key (no allow-list needed, 14.3); (e) `.unsafe(` with a non-literal argument. All in the table in 14.3, each with a must-fail fixture and each proved by a `/tmp` mutation of the real file (money-path doc, "Edge role PR4c").

**Smaller items.** `me-export` and `me-push-token` were missing from the CI `deno check` and `deno cache --frozen` lists (so the pin proof never saw them); both are in now, and `supabase/tests/unit/ci-function-lists.test.ts` fails the build if any `supabase/functions/*/index.ts` is missing from any of the three CI lists (check, cache, the tamper test's), so the next function cannot be forgotten.
`isServiceRoleBearer`'s `key === ""` guard survived the PR4b mutation run: with an unset or empty configured key, `Authorization: Bearer <NBSP>` (header normalisation strips space, tab, CR and LF, not NBSP / U+3000) trims to `""` and compared equal to the empty key. A test now covers it (unset and empty key; NBSP, U+3000, EM SPACE, BOM and combinations; the function and the whole handler; a control that the real key admits) and the mutation is caught. *Deno's `Headers` refuses U+3000 outright (not a ByteString), so that case is handed over as a duck-typed request: it tests the comparison, which must not rest on the transport having already refused the byte.*

## 15. Deploy runbook (edge role)

Everything here is a deploy step this repository cannot perform; items marked `[unverified]` were not checked against a real Supabase project (training knowledge).

**0. Deploy order (PR4c).** **Migrations → provision `edge_gateway` → `supabase secrets set GOLFRAVEN_EDGE_DB_URL` → deploy functions**, in that order.
- *Migrations first* because the code calls what they create: `retention-purge` deployed before `0040` runs its two hygiene steps against a function `edge_system` may not yet execute, so each answers `42501` and the run is `500 retention_step_failed` (the other four steps still run; nothing is lost, it just alarms).
- *`edge_gateway` before the secret* because the secret is that login's connection string and a login with no password cannot be used (item 2).
- *The secret before the functions* because **a function deployed before `GOLFRAVEN_EDGE_DB_URL` exists answers `500` on its first database call**: `openPool` throws `GOLFRAVEN_EDGE_DB_URL is not set` and nothing else is tried (there is no fallback URL and the lint keeps it that way), so the failure is closed, loud in the function log, and says why. Every function needs it (`import-catalog` checks its HMAC first, so an HMAC-valid import with no secret is also a `500`).
- *The Vault secret `offline_seed_key` after migration `0045` and before `me-offline-seed` is used* (item 8): until it exists the function answers `503 offline_seed_unavailable` (fail closed, nothing else is affected).
- Secrets set after a function is deployed are read by a **new** isolate; an already-warm isolate keeps answering `500` until it is recycled (`[unverified - training knowledge]`), so redeploy or wait after setting the secret rather than assuming it is picked up.

**1. One database URL.** Every function that touches the database reads **`GOLFRAVEN_EDGE_DB_URL` only** (the `edge_gateway` connection string; `openPool()` takes no argument and reads it itself, PR4c). `SUPABASE_DB_URL` is not read by any code and the lint fails the build on it. **That does not make it harmless:** if the platform still injects it into every function's environment `[unverified]`, it is a **live credential** (a connection string for a privileged project role, `[unverified]` which one) that **only code review and the lint keep unused**. Nothing at run time stops a future change reading it; the lint is the control, so a change to `tools/service-role-lint` or to `privileged.ts`' allow-lists is a security-relevant diff. If the platform offers a way to stop injecting it, take it. `import-catalog` no longer needs `SUPABASE_DB_URL` either (PR3 blocker 6): its deploy config changes with PR4b.

**2. Provision `edge_gateway`.** Migrations 0030-0039 create it `NOLOGIN` with no credential. Once per environment, from an admin role that may `ALTER ROLE edge_gateway`, against the **direct** database connection (not the pooler):
```
<read the generated password from your secret manager> | PGHOST=<direct host> PGPORT=5432 PGUSER=<admin> PGDATABASE=postgres bash tools/db/provision-edge-login.sh --password-stdin
```
The script sends a SCRAM-SHA-256 verifier, never the plaintext. Then `supabase secrets set GOLFRAVEN_EDGE_DB_URL=<url>` with the pooled URL of that login. `[unverified]`: that the hosted project lets `ALTER ROLE ... LOGIN PASSWORD` for a role the migration created, that Supavisor accepts the tenant-qualified user name for it (`edge_gateway.<project-ref>`), and that `pg_hba` admits it (R7). The first request runs the self-check (`session_user = edge_gateway`, no SUPERUSER / BYPASSRLS anywhere in its closure, no membership of `service_role` / `authenticated` / `anon` / `authenticator` / `private_definer` / `supabase_admin` / `postgres`); a failure is a 500 from every handler (fail closed) and says why in the function log. To rotate: re-run the script, then update the secret.

**3. Supavisor transaction mode and `prepare: true` `[unverified]`.** `openPool` builds the one pool with `prepare: true`. Nothing in this repository has run through Supavisor. Two things to check before the first real request: (a) that the pooler in transaction mode accepts postgres.js's named prepared statements (symptoms of "no": `prepared statement "..." does not exist` or a bind-parameter-count error on the second use of a statement; support has varied by pooler version and mode); (b) that one transaction stays on one server connection end to end (the binding is keyed on the backend pid and the transaction; a pooler that moved statements between connections would fail every request closed, with `openScopedTx: the bound actor is 'null'`). **One-line fallback for (a):** in `openPool` (`privileged.ts`) change `prepare: true` to `prepare: false` (it is the only pool now). If (b) fails, use the session-mode / direct URL for `GOLFRAVEN_EDGE_DB_URL` and size `max` (5 per worker) against the project's connection limit.

**3a. Size the connection limit against 5 per worker (PR4c).** `openPool` opens `max: 5` connections **per pool, and there is one pool per warm isolate** (each function, each isolate); every function connects as the one login `edge_gateway`. The worst case is therefore `5 x (concurrent warm isolates across all the functions that use the database)` connections, which the **login's** limit (`ALTER ROLE edge_gateway CONNECTION LIMIT n`, if you set one), the **pooler's per-user pool size** (Supavisor), and the database's `max_connections` (shared with GoTrue, PostgREST, Realtime and the dashboard) must all cover with headroom. Practical sizing: take the highest concurrency you expect for the busiest function, multiply by 5, add the other functions' typical warm counts times 5, and compare with the pooler pool size for `edge_gateway`; if it does not fit, lower `max` in `openPool` (the only place it is set) before raising limits. A pool that cannot get a connection **queues with no acquire timeout** (the `openPool` comment explains why a bound exists only on the TCP handshake), so an exhausted limit shows up as slow requests and the 12 s transaction timeout, not as a clean error. `[unverified]`: how many isolates the hosted platform runs concurrently, whether a tenant-qualified pooler user shares one pool across isolates (it should, which is the point of using the pooler), and the default per-user pool size.

**4. The self-check interval is an unmeasured default.** `EDGE_SELF_CHECK_INTERVAL_MS = 5 min` or `EDGE_SELF_CHECK_EVERY_N_TX = 1000` transactions, whichever comes first (`privileged.ts`); a repeat is one small catalog query, and nothing runs inside the window. Confirm against real request rates: at ~20 requests/s the transaction budget fires about every 50 s, at low rates the 5 minutes do. Count the check query in `pg_stat_statements` after a week and move either constant if it is noise or if the window (how long an `ALTER ROLE edge_gateway BYPASSRLS` goes unseen) is too long. The per-transaction role assertion covers `edge_actor` / `edge_system` at once either way.

**5. Retention schedule.** Schedule `retention-purge` **hourly** (a jittered minute such as :17), `POST` with `Authorization: Bearer <service-role key>` and an empty body. Hourly because the shortest retention it enforces is the sign-in proof (an hour past expiry); fix coordinates (30 days), tombstones (24 months) and the revocation queue (30 days) would be fine daily. The rate limit allows 12 an hour. Mechanism `[unverified - training knowledge]`: Supabase's documented pattern is `pg_cron` + `pg_net` (`select cron.schedule('retention-purge', '17 * * * *', $$ select net.http_post(url := 'https://<project-ref>.supabase.co/functions/v1/retention-purge', headers := jsonb_build_object('Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'service_role_key')), body := '{}'::jsonb) $$)`, the key held in Vault, never in the job text); any external scheduler that can send the bearer works equally. **Not added as a migration on purpose**: nothing here proved `pg_cron` is available in the harness or on the project. Alert on a non-2xx (`500 retention_step_failed` names the step and its SQLSTATE) and on `complete: false` several runs in a row. **Also schedule `signin-revocation-drain` (every 5 minutes, same bearer): it retries revocations for 72 h and its claim is what expires and wipes a pending row's credential material, so it is a retention dependency too.**

**Schedule notes for the six steps (PR4c).** One hourly `retention-purge` covers all of them; the table is what each step needs of the schedule:

| Step | Needs at least | Why hourly is enough / what a missed run costs |
|---|---|---|
| `signin_email_proofs` | hourly | a stale proof is purged an hour past its (5 minute) expiry; a missed hour leaves a used or expired proof row a little longer (it cannot be redeemed: single use and expiry are checked at redemption) |
| `signin_revocation_queue`, `fix_coords`, `install_link_tombstones` | daily | retention in days / months |
| `consumed_nonce` (0040) | daily | tombstones 7 days past expiry; growth is one row per consumed challenge or token. Purging late is safe, purging **early** is the risk and is prevented twice (function and policy) |
| `rate_limit_buckets` (0040) | daily | windows older than 2 days, including the `<uid>:me-delete:user` bucket a deleted account leaves (it is removed 1 to 2 days after its window ends). Growth is one row per bucket per window |

Each step is capped at **10 batches x 5000 rows per run**, so a first run after launch against a large rate-limit backlog (that purge has never run before 0040) may report `complete: false` for a few runs; that is the backlog draining, not a fault. Alert only on `complete: false` several **days** in a row, or on a `500`. `[unverified]`: the first run's wall time against a real backlog (the batches are bounded by the 10 s statement timeout each and the 30 s run budget).

**6. Environment, per function.** `SUPABASE_URL`, `SUPABASE_ANON_KEY` and `SUPABASE_SERVICE_ROLE_KEY` are platform-injected `[unverified]`; the rest are secrets you set. An unset optional vendor value makes that path answer 503 / fail closed, never fall back.

| Function | `GOLFRAVEN_EDGE_DB_URL` | Platform keys it reads | Its own variables |
|---|---|---|---|
| `evidence`, `evidence-batch`, `checkin-challenge`, `me-export`, `me-push-token` | yes | `SUPABASE_URL`, `SUPABASE_ANON_KEY` (JWT check) | none |
| `me-offline-seed` | yes | `SUPABASE_URL`, `SUPABASE_ANON_KEY` (JWT check) | none in the environment. **The derivation key is NOT an environment variable and never reaches the function:** it is the Vault secret `offline_seed_key` (item 8), read only inside `private.offline_seed_derive`. Transaction kind: `actor` (`openScopedTx("actor", userBind(uid))`, through `withOwnership`); the two rate-limit hits run before it |
| `checkin-token` | yes | URL, anon | optional, verification only (no DeviceCheck credential): `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID` (iOS, the App Attest `rpId`); `GR_PLAY_PACKAGE_NAME`, `GR_PLAY_CERT_SHA256`, `GR_PLAY_SERVICE_ACCOUNT_EMAIL`, `GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY` (Android). An unset platform answers `503 attestation_not_configured` to a request that carries THAT platform's attestation; a request with no attestation needs none of them. Its answer may carry `rekey: true` (stale App Attest key hint, `p3-money-path-requirements.md` "Stale App Attest key recovery"): a response-body member only, so no new statement, grant, policy, variable or migration |
| `devices-attest-key` | yes | URL, anon | `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID`, `GR_APPLE_APPATTEST_ENV` |
| `rewards-activate` | yes | URL, anon | `GR_APPLE_TEAM_ID`, `GR_APPLE_BUNDLE_ID`, `GR_APPLE_DEVICECHECK_KEY_ID`, `GR_APPLE_DEVICECHECK_PRIVATE_KEY`, `GR_APPLE_DEVICECHECK_ENV`; `GR_PLAY_PACKAGE_NAME`, `GR_PLAY_CERT_SHA256`, `GR_PLAY_SERVICE_ACCOUNT_EMAIL`, `GR_PLAY_SERVICE_ACCOUNT_PRIVATE_KEY` |
| `me-signin-methods` | yes | URL, anon (JWT check **and** `verifyOtp`) | `GR_APPLE_TEAM_ID`, `GR_APPLE_SIWA_CLIENT_ID`, `GR_APPLE_SIWA_KEY_ID`, `GR_APPLE_SIWA_PRIVATE_KEY` |
| `me-delete` | yes | URL, anon, **service-role key** (`deleteAuthUser`) | the four `GR_APPLE_SIWA_*` (unset: grants stay queued for the 72 h retry) |
| `signin-revocation-drain` | yes | **service-role key** (bearer comparison) | the four `GR_APPLE_SIWA_*` |
| `retention-purge` | yes | **service-role key** (bearer comparison) | none |
| `import-catalog` | yes (**not** `SUPABASE_DB_URL`) | none (HMAC-only, no JWT path) | `CATALOG_ARTIFACT_BASE_URL`, `CATALOG_ARTIFACT_ALLOWED_HOSTS`, `CATALOG_IMPORT_HMAC_SECRET` |

**7. Gateway `verify_jwt` and the bearer pattern `[unverified - training knowledge, none of this was checked against a real project]` (PR4c).** Supabase's function gateway checks, by default (`verify_jwt = true`), that the `Authorization` bearer is a valid JWT signed for the project; the **anon key and the service-role key are both such JWTs**. So for `retention-purge` and `signin-revocation-drain` the gateway check is **not** the authentication: it admits the public anon key too. The authentication is `isServiceRoleBearer` in the function (a constant-time comparison with `SUPABASE_SERVICE_ROLE_KEY`), which is why it must never be removed or made to fall back. Two consequences to settle at deploy time: (a) set `verify_jwt` per function **deliberately** (`supabase/config.toml` `[functions.<name>]` or the deploy flag) and record the choice; nothing in this repository sets it today; (b) the newer **non-JWT secret keys** (`sb_secret_...`) are not JWTs, so a gateway with `verify_jwt = true` may reject them before the function runs, and a scheduler holding one would send a bearer that does **not** equal a legacy JWT-format `SUPABASE_SERVICE_ROLE_KEY` in the environment, so `isServiceRoleBearer` would answer `401`. Before moving the project to the new keys, decide which value the scheduler sends and what `SUPABASE_SERVICE_ROLE_KEY` holds in the function environment, and re-run the scheduler against `retention-purge` and `signin-revocation-drain`; do not "fix" a `401` by loosening the comparison.

Pin `--config supabase/functions/deno.json` at deploy time (the existing `[unverified]` flag): the import map is what resolves `postgres`, `zod` and the rest.

**8. The offline-code derivation key (migration 0045, P4.2b-3a).** Once per environment, from an admin role, **after** `0045` is applied: `select vault.create_secret('<at least 32 random bytes, e.g. the output of `openssl rand -hex 32`>', 'offline_seed_key');` (the name is exact; the function reads the secret by that name and uses the secret TEXT as raw UTF-8 key bytes, minimum 32 bytes, else `55000`). `[unverified]`: that the hosted Vault accepts this call from the project's admin role, and that pgcrypto's `hmac` is reachable as `public.hmac` there (migration 0029's `account_pseudonyms` already assumes the second). Rules for the key:
- **Never delete or change it casually.** Every provisioned seed is derived from it, so changing the value silently invalidates **every** player's offline code fleet-wide: staff see "wrong code" for everyone until each device has re-provisioned (the app does so on its next online use, and the endpoint returns the new seed under the same `seedVersion`, which is why a K change is NOT visible in the version number). It is an incident response (K suspected leaked), not routine rotation: per-device rotation is `POST /v1/me/offline-seed` with `rotate: true`.
- **It is not in the environment, not in a repository, not in a log.** The database never returns it (`private.offline_seed_derive` has no EXECUTE for any role); a missing key is `55000` with a message that names no key material.
- A staging key must differ from the production key (a seed derived in one environment must not verify in the other).

## 16. Addendum: the offline-code definers (migration 0045, P4.2b-3a)

`me-offline-seed` is a plain actor-scoped function: `getActorFromRequest`, two `hitRateLimitForActor` hits (the reveal bucket always, the rotation bucket when `rotate: true`) BEFORE `withOwnership`, then `repo.offlineCode.provisionSeed`, which runs `private.offline_seed_for_actor` as the bound `edge_actor`. No new transaction kind, no `edge_system` use, no `service_role`. The new function is in every CI deno list (`ci-function-lists.test.ts`) and in the earning-side isolation lists (`rewards-isolation.test.ts`: it reads no persistent device bit). `privileged.ts` stays the sole database site; `buildOfflineCodeRepo` is the one new section (two statements, both `private.*_for_actor`). Full design, threat model, rotation, deletion / export and what P5 must do: `docs/security/p3-money-path-requirements.md`, "Offline TOTP seed provisioning".

New `private_definer` policies (all scoped, all in `private.definer_policy_allowlist` and `supabase/tests/fixtures/definer_policy_exprs.txt`): `app.offline_code_step` DELETE / SELECT on `user_id` under `app.delete_my_data.target_user_id` (the account deletion's generic pass and the export read), INSERT / DELETE / SELECT on `device_id` under `app.offline_code.target_device_id` (the record function's one device, set and cleared inside the definer), and `app.device` SELECT keyed on the **actor binding** through `private.offline_code_bound_staff()` (a bound `kind = user` actor with a staff / manager scope, or an admin; NOT a settable GUC: any session can `set_config` a GUC, so a GUC-keyed policy is not an ownership boundary against `edge_actor`, and every `_for_actor` definer filters explicitly by the bound uid). `private.validate_and_register_pseudonym_hmac_id` now also requires the Vault secret's name to match `pseudonym_hmac%`, so the offline key's id cannot be registered as a pseudonym key. No `edge_actor` or `edge_system` policy and no edge grant on the table: `private.edge_policy_allowlist` is unchanged.

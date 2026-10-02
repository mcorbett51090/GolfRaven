-- 16_edge_role.sql
-- Accepted follow-up 6 (0030_edge_role_core.sql / 0031_edge_role_policies.sql): the NOBYPASSRLS Edge role,
-- proved the way the Edge runtime will actually use it -- as a REAL login (`edge_gateway`) that
-- `SET LOCAL ROLE`s into `edge_actor` / `edge_system` and binds an actor with private.bind_actor.
-- Design: docs/security/edge-role-design.md. Nothing in the TypeScript uses this yet (PR2).
--
-- WHY THIS FILE RECONNECTS (the only file that does):
--   * `SET ROLE x` is authorised against the SESSION user's memberships, not the current role's. A
--     superuser (HARNESS_MODE=superuser) or migration_owner (restricted) that did `SET ROLE
--     edge_gateway` could still `SET ROLE service_role` afterwards, so every "SET ROLE escalation
--     fails" cell would be vacuous. The escalation cells are only meaningful on a connection whose
--     session user IS edge_gateway. psql's `\c` opens that connection (tools/db/test.sh provisions
--     LOGIN with tools/db/provision-edge-login.sh first; the harness auth is `trust`).
--   * pgTAP's bookkeeping is per session, so ALL assertions live in the edge_gateway session; the
--     phases before and after it make no assertion.
--
-- THE THREE PHASES
--   0  (harness role, as service_role)  seed three throw-away users UA / UB / UD and their rows. The
--      rows are COMMITTED: edge transactions run in other sessions and must see them.
--   1  (edge_gateway)                   every assertion. Each group is its own BEGIN ... ROLLBACK,
--      except the groups that need a real COMMIT (stale binding after commit, rate-limit commit,
--      nonce tombstone survives commit), which say so.
--   2  (harness role)                   remove everything phase 0 created: the sanctioned private.delete_my_data as
--      service_role, then the residue it retains by design (voided entitlements, the pseudonymous install-link
--      tombstone rows, which have no DELETE grant for any runtime role) as the table-owning harness role through a
--      temporary CURRENT_USER policy. What still stays, inert: the nonce tombstones this file writes
--      (private.consumed_nonce is append-only by design), auth.users rows (only Auth deletes those) and
--      user-nulled fraud_signal / audit_log rows (delete_my_data retains those; their ids are random). The file is
--      therefore RE-RUNNABLE on the same cluster (verified: three superuser and two restricted runs in a row).
--
-- THE NAMES: UA is "the actor", UB "someone else", UD "a third account on the same install". All their
-- ids start eeee0000-. Nothing here touches the helpers.sql fixtures except as read-only references
-- (fac_x, trl_t/trl_v, courses crs_x1).
--
-- ⛔ WATCH (the silent-breakage class this role introduces): under RLS an UPDATE with no matching policy
-- affects ZERO rows and raises nothing. Every UPDATE cell below therefore asserts a ROW COUNT, and each
-- one is paired with a CONTROL on the actor's own row so a 0 can only mean "policy", never "the
-- statement matched nothing for some other reason".

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db, substr(md5(random()::text), 1, 12) AS run \gset

-- ============================================================================
-- PHASE 0: seed (harness role -> service_role; committed)
-- ============================================================================
SET ROLE service_role;
BEGIN;
-- (No email column: nothing in this file needs one, and the repo is public.)
INSERT INTO auth.users (id) VALUES
  ('eeee0000-0000-0000-0000-0000000000a0'),
  ('eeee0000-0000-0000-0000-0000000000b0'),
  ('eeee0000-0000-0000-0000-0000000000d0')
ON CONFLICT (id) DO NOTHING; -- auth.users rows are never deleted by this harness (only by Auth), so a re-run finds them
INSERT INTO app.profile (user_id, handle) VALUES
  ('eeee0000-0000-0000-0000-0000000000a0', 'edge_ua'),
  ('eeee0000-0000-0000-0000-0000000000b0', 'edge_ub'),
  ('eeee0000-0000-0000-0000-0000000000d0', 'edge_ud');
INSERT INTO app.app_review_demo_account (user_id) VALUES ('eeee0000-0000-0000-0000-0000000000d0');

-- Catalog: ONE course with a radius geometry (the matcher cell; edge_system cannot write geometry, so it
-- has to be seeded). Everything else the importer cells need (backlog rows, a revoked kid, ledger and course
-- rows) is written by edge_system INSIDE the tests and rolled back: service_role has no DELETE on the backlog
-- or the revocation table, so committed rows there could not be cleaned up.
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('crs_edge_geo', 'course', 'verified', 1);
INSERT INTO app.catalog_course (id, facility_id, name, verification_status, geometry_kind, radius_center, radius_m, catalog_version) VALUES
  ('crs_edge_geo', 'fac_x', 'Edge Geo Course', 'play-verified', 'radius', ST_SetSRID(ST_MakePoint(-86.0, 36.0), 4326), 500, 1);

-- Offers (face value 10): E1 backs UA's play-linked code, E2 backs UB's code (budget reserved 10), E3 backs
-- UA's earned code (the activation cell), E4 has a cap of 5 so it cannot cover a code (the held-for-budget cell).
INSERT INTO app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, budget_reserved, face_value, valid_from, valid_to, status) VALUES
  ('eeee0000-0000-0000-0000-00000000e101', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 0, 10, current_date, current_date + 30, 'live'),
  ('eeee0000-0000-0000-0000-00000000e102', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 10, 10, current_date, current_date + 30, 'live'),
  ('eeee0000-0000-0000-0000-00000000e103', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 100, 0, 10, current_date, current_date + 30, 'live'),
  ('eeee0000-0000-0000-0000-00000000e104', 'trl_t', 'fac_x', '{}'::jsonb, 'operator', 5, 0, 10, current_date, current_date + 30, 'live');

-- Devices: UA a1 and UD d1 share an install link (and d1 belongs to a fraud-voided account); UB b1 is alone.
-- (Hash 'e...e': distinctive, because the install-link tombstone has no DELETE grant for anyone and these rows
-- stay in the harness database after the file.)
INSERT INTO app.device (id, user_id, platform, install_link_hash, fraud_voided_at) VALUES
  ('eeee0000-0000-0000-0000-00000000a001', 'eeee0000-0000-0000-0000-0000000000a0', 'android', repeat('e', 64), NULL),
  ('eeee0000-0000-0000-0000-00000000b001', 'eeee0000-0000-0000-0000-0000000000b0', 'ios', NULL, NULL),
  ('eeee0000-0000-0000-0000-00000000d001', 'eeee0000-0000-0000-0000-0000000000d0', 'android', repeat('e', 64), now());
-- The pseudonymous install-link tombstone (P3f round 3): one row per (install, account), surviving account
-- deletion. UA, UD and UB each get theirs through the real function, plus one for an account that no longer
-- exists (a random id): on install e...e that is three tombstones against two live devices.
SELECT app.record_install_link('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', repeat('e', 64));
SELECT app.record_install_link('eeee0000-0000-0000-0000-0000000000d0', 'eeee0000-0000-0000-0000-00000000d001', repeat('e', 64));
SELECT app.record_install_link('eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', repeat('b', 64));
INSERT INTO app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id)
SELECT repeat('e', 64), a.pseudonym, a.key_id FROM private.account_pseudonyms(gen_random_uuid()) a WHERE a.preferred;

-- Evidence: UA accepted (fixCoords, recent, at crs_y1 -- which the purge cell gives an open backlog row, so
-- its coordinates are KEPT), UA accepted (fixCoords, 40 days old: purged by age), UA queued_catalog (the
-- delegate target), UB accepted (fixCoords at crs_x1, a verified never-split course: purged).
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, input_hash, course_id, facility_id, local_date, summary, integrity, status, catalog_version, created_at) VALUES
  ('eeee0000-0000-0000-0000-0000000a0e01', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'foreground_checkin', 'edge-a-recent', 'h-a1', 'crs_y1', 'fac_y', current_date, '{}'::jsonb, '{"fixCoords": [1], "keep": true}'::jsonb, 'accepted', 1, now()),
  ('eeee0000-0000-0000-0000-0000000a0e02', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'foreground_checkin', 'edge-a-old', 'h-a2', 'crs_y1', 'fac_y', current_date, '{}'::jsonb, '{"fixCoords": [2], "other": 2}'::jsonb, 'accepted', 1, now() - interval '40 days'),
  ('eeee0000-0000-0000-0000-0000000b0e01', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', 'foreground_checkin', 'edge-b-ev', 'h-b1', 'crs_x1', 'fac_x', current_date, '{}'::jsonb, '{"fixCoords": [3]}'::jsonb, 'accepted', 1, now());
INSERT INTO app.evidence (id, user_id, device_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input) VALUES
  ('eeee0000-0000-0000-0000-0000000a0e03', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'foreground_checkin', 'edge-a-queued', 'h-a3', current_date, 'queued_catalog', 'fac_x', 'crs_x1', '20300102-0000001', '{"k": "v"}'::jsonb);

-- Plays: UA at crs_y1 (the rescore delegate target) and at crs_x1 (the held-review cascade target); UB at
-- crs_x1 and at crs_y1. Different dates so the (user, course, date) and user-pick indexes never collide.
INSERT INTO app.play (id, user_id, course_id, facility_id, play_date, policy_version, status, score_badge) VALUES
  ('eeee0000-0000-0000-0000-0000000a0a01', 'eeee0000-0000-0000-0000-0000000000a0', 'crs_y1', 'fac_y', current_date - 1, 'v1', 'confirmed', 0.60),
  ('eeee0000-0000-0000-0000-0000000a0a02', 'eeee0000-0000-0000-0000-0000000000a0', 'crs_x1', 'fac_x', current_date - 3, 'v1', 'confirmed', 0.60),
  ('eeee0000-0000-0000-0000-0000000b0a01', 'eeee0000-0000-0000-0000-0000000000b0', 'crs_x1', 'fac_x', current_date - 3, 'v1', 'confirmed', 0.60),
  ('eeee0000-0000-0000-0000-0000000b0a02', 'eeee0000-0000-0000-0000-0000000000b0', 'crs_y1', 'fac_y', current_date - 2, 'v1', 'confirmed', 0.60);
INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES
  ('eeee0000-0000-0000-0000-0000000b0a01', 'eeee0000-0000-0000-0000-0000000b0e01', 'eeee0000-0000-0000-0000-0000000000b0'),
  ('eeee0000-0000-0000-0000-0000000a0a02', 'eeee0000-0000-0000-0000-0000000a0e01', 'eeee0000-0000-0000-0000-0000000000a0');

-- (No fixed ids: delete_my_data keeps fraud_signal rows with the user nulled, so a re-run must not collide.)
INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES
  ('eeee0000-0000-0000-0000-0000000000b0', 'seed_b', '{}'::jsonb),
  ('eeee0000-0000-0000-0000-0000000000a0', 'seed_a', '{}'::jsonb);

-- Challenges and tokens (their nonces are recorded in the append-only tombstone ledger by the trigger:
-- this is also the service_role path of the redefined trigger function).
INSERT INTO app.checkin_challenge (id, user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES
  ('eeee0000-0000-0000-0000-0000000a0c01', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'fac_x', 'edge-seed-nonce-a-' || :'run', 'live', now() - interval '1 minute', now() + interval '1 hour'),
  ('eeee0000-0000-0000-0000-0000000b0c01', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', 'fac_x', 'edge-seed-nonce-b-' || :'run', 'live', now() - interval '1 minute', now() + interval '1 hour');
INSERT INTO app.checkin_token (jti, challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) VALUES
  ('eeee0000-0000-0000-0000-0000000a0d01', 'eeee0000-0000-0000-0000-0000000a0c01', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'fac_x', 'unattestable', 'live', now() - interval '1 minute', now() + interval '1 hour'),
  ('eeee0000-0000-0000-0000-0000000b0d01', 'eeee0000-0000-0000-0000-0000000b0c01', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', 'fac_x', 'unattestable', 'live', now() - interval '1 minute', now() + interval '1 hour');

INSERT INTO app.push_token (user_id, device_id, expo_token) VALUES
  ('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'ExpoA'),
  ('eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', 'ExpoB');
INSERT INTO app.signin_provider_token (user_id, provider, refresh_token_ciphertext, dek_wrapped, kek_id) VALUES
  ('eeee0000-0000-0000-0000-0000000000a0', 'apple', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-1'),
  ('eeee0000-0000-0000-0000-0000000000b0', 'google', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-1');
INSERT INTO app.connector_account (id, user_id, provider, external_user_id, refresh_token_ciphertext, dek_wrapped, kek_id) VALUES
  ('eeee0000-0000-0000-0000-0000000a0b01', 'eeee0000-0000-0000-0000-0000000000a0', 'garmin', 'ext-a', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-1'),
  ('eeee0000-0000-0000-0000-0000000b0b01', 'eeee0000-0000-0000-0000-0000000000b0', 'arccos', 'ext-b', '\xdeadbeef'::bytea, '\xdeadbeef'::bytea, 'kek-1');

-- Codes and entitlements. UA's OC1 and entitlement are backed by UA's crs_x1 play (the cascade); OC3 is earned
-- (activation); UB's OCB holds a 10 reservation on E2 (the deletion cell hands it back).
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, activated_device_id, activated_at, expires_at, play_id) VALUES
  ('eeee0000-0000-0000-0000-0000000a0901', 'eeee0000-0000-0000-0000-00000000e101', 'eeee0000-0000-0000-0000-0000000000a0', 'fac_x', 'issued', 'eeee0000-0000-0000-0000-00000000a001', now(), now() + interval '30 days', 'eeee0000-0000-0000-0000-0000000a0a02');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state) VALUES
  ('eeee0000-0000-0000-0000-0000000a0903', 'eeee0000-0000-0000-0000-00000000e103', 'eeee0000-0000-0000-0000-0000000000a0', 'fac_x', 'earned'),
  ('eeee0000-0000-0000-0000-0000000a0904', 'eeee0000-0000-0000-0000-00000000e104', 'eeee0000-0000-0000-0000-0000000000a0', 'fac_x', 'earned');
INSERT INTO app.offer_code (id, offer_id, user_id, facility_id, state, activated_device_id, activated_at, expires_at, play_id, reserved_amount) VALUES
  ('eeee0000-0000-0000-0000-0000000b0901', 'eeee0000-0000-0000-0000-00000000e102', 'eeee0000-0000-0000-0000-0000000000b0', 'fac_x', 'issued', 'eeee0000-0000-0000-0000-00000000b001', now(), now() + interval '30 days', 'eeee0000-0000-0000-0000-0000000b0a01', 10);
INSERT INTO app.entitlement (id, user_id, kind, trail_id, state, activated_device_id, activated_at, play_id) VALUES
  ('eeee0000-0000-0000-0000-0000000a0801', 'eeee0000-0000-0000-0000-0000000000a0', 'special_marker', 'trl_v', 'redeemable', 'eeee0000-0000-0000-0000-00000000a001', now(), 'eeee0000-0000-0000-0000-0000000a0a02'),
  ('eeee0000-0000-0000-0000-0000000b0801', 'eeee0000-0000-0000-0000-0000000000b0', 'special_marker', 'trl_t', 'earned', NULL, NULL, NULL);
INSERT INTO app.device_reward_ledger (id, device_id, user_id, reward_kind, reward_id) VALUES
  ('eeee0000-0000-0000-0000-0000000b0701', 'eeee0000-0000-0000-0000-00000000b001', 'eeee0000-0000-0000-0000-0000000000b0', 'offer', 'eeee0000-0000-0000-0000-0000000b0901'),
  ('eeee0000-0000-0000-0000-0000000a0701', 'eeee0000-0000-0000-0000-00000000a001', 'eeee0000-0000-0000-0000-0000000000a0', 'offer', 'eeee0000-0000-0000-0000-0000000a0901');
-- One audit row each (the audit table is insert-only: delete_my_data in phase 2 REDACTS the actor).
INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id) VALUES
  ('eeee0000-0000-0000-0000-0000000000b0', 'play.repick', 'play', 'eeee0000-0000-0000-0000-0000000b0a01'),
  ('eeee0000-0000-0000-0000-0000000000a0', 'evidence.insert', 'app.evidence', 'eeee0000-0000-0000-0000-0000000a0e01');
COMMIT;
RESET ROLE;

-- ============================================================================
-- PHASE 1: reconnect as the real login
-- ============================================================================
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(585);

-- ----------------------------------------------------------------------------
-- Test-only helpers (session-local, in pg_temp; never part of a migration)
-- ----------------------------------------------------------------------------
-- The own-row matrix. ONE table of statement templates, one loop. {A} is the actor, {B} someone else, {D} the
-- third account; {DA}/{DB} are A's and B's devices. For every table, as a bound edge_actor (A):
--   own insert      lives (the CONTROL: the statement is well-formed and the role may write the actor's row)
--   foreign insert  throws 42501 with the row-level-security message (not a column/table privilege message)
--   foreign select  0 rows, own select > 0 rows (the control that the probe can see rows at all)
--   foreign update  0 ROWS AFFECTED (the silent case), own update >= 1 row
CREATE FUNCTION pg_temp.subst(p_sql text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT replace(replace(replace(replace(replace(p_sql,
    '{A}', 'eeee0000-0000-0000-0000-0000000000a0'), '{B}', 'eeee0000-0000-0000-0000-0000000000b0'),
    '{D}', 'eeee0000-0000-0000-0000-0000000000d0'), '{DA}', 'eeee0000-0000-0000-0000-00000000a001'),
    '{DB}', 'eeee0000-0000-0000-0000-00000000b001')
$f$;

CREATE FUNCTION pg_temp.own_row_cells() RETURNS SETOF text LANGUAGE plpgsql AS $f$
DECLARE
  c record;
  v_n int;
BEGIN
  FOR c IN SELECT * FROM (VALUES
    ('device',
      $q$SELECT count(*) FROM app.device WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.device WHERE user_id = '{A}'$q$,
      $q$UPDATE app.device SET last_seen = now() WHERE user_id = '{B}'$q$, $q$UPDATE app.device SET last_seen = now() WHERE user_id = '{A}'$q$,
      $q$INSERT INTO app.device (id, user_id, platform) VALUES (gen_random_uuid(), '{B}', 'ios')$q$, $q$INSERT INTO app.device (id, user_id, platform) VALUES (gen_random_uuid(), '{A}', 'ios')$q$),
    ('evidence',
      $q$SELECT count(*) FROM app.evidence WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.evidence WHERE user_id = '{A}'$q$,
      $q$UPDATE app.evidence SET integrity = integrity WHERE user_id = '{B}'$q$, $q$UPDATE app.evidence SET integrity = integrity WHERE user_id = '{A}'$q$,
      $q$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, local_date) VALUES ('{B}', 'self_report', 'edge-x-' || gen_random_uuid(), 'h', current_date)$q$,
      $q$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, local_date) VALUES ('{A}', 'self_report', 'edge-x-' || gen_random_uuid(), 'h', current_date)$q$),
    ('play',
      $q$SELECT count(*) FROM app.play WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.play WHERE user_id = '{A}'$q$,
      $q$UPDATE app.play SET policy_version = policy_version WHERE user_id = '{B}'$q$, $q$UPDATE app.play SET policy_version = policy_version WHERE user_id = '{A}'$q$,
      $q$INSERT INTO app.play (user_id, course_id, facility_id, play_date, policy_version) VALUES ('{B}', 'crs_x1', 'fac_x', current_date - 20, 'v1')$q$,
      $q$INSERT INTO app.play (user_id, course_id, facility_id, play_date, policy_version) VALUES ('{A}', 'crs_x1', 'fac_x', current_date - 21, 'v1')$q$),
    ('play_evidence',
      $q$SELECT count(*) FROM app.play_evidence WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.play_evidence WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text,
      $q$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES ('eeee0000-0000-0000-0000-0000000b0a02', 'eeee0000-0000-0000-0000-0000000b0e01', '{B}')$q$,
      $q$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES ('eeee0000-0000-0000-0000-0000000a0a01', 'eeee0000-0000-0000-0000-0000000a0e02', '{A}')$q$),
    ('fraud_signal',
      $q$SELECT count(*) FROM app.fraud_signal WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.fraud_signal WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text,
      $q$INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES ('{B}', 'edge_x', '{}')$q$, $q$INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES ('{A}', 'edge_x', '{}')$q$),
    ('checkin_challenge',
      $q$SELECT count(*) FROM app.checkin_challenge WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.checkin_challenge WHERE user_id = '{A}'$q$,
      $q$UPDATE app.checkin_challenge SET used_at = now() WHERE user_id = '{B}' AND used_at IS NULL$q$, $q$UPDATE app.checkin_challenge SET used_at = now() WHERE user_id = '{A}' AND used_at IS NULL$q$,
      $q$INSERT INTO app.checkin_challenge (user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('{B}', '{DB}', 'fac_x', 'edge-c-' || gen_random_uuid(), 'live', clock_timestamp(), now() + interval '2 minutes')$q$,
      $q$INSERT INTO app.checkin_challenge (user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('{A}', '{DA}', 'fac_x', 'edge-c-' || gen_random_uuid(), 'live', clock_timestamp(), now() + interval '2 minutes')$q$),
    ('checkin_token',
      $q$SELECT count(*) FROM app.checkin_token WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.checkin_token WHERE user_id = '{A}'$q$,
      $q$UPDATE app.checkin_token SET consumed_at = now() WHERE user_id = '{B}' AND consumed_at IS NULL$q$, $q$UPDATE app.checkin_token SET consumed_at = now() WHERE user_id = '{A}' AND consumed_at IS NULL$q$,
      $q$INSERT INTO app.checkin_token (challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) VALUES ('eeee0000-0000-0000-0000-0000000b0c01', '{B}', '{DB}', 'fac_x', 'unattestable', 'live', clock_timestamp(), now() + interval '10 minutes')$q$,
      $q$WITH c AS (INSERT INTO app.checkin_challenge (user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('{A}', '{DA}', 'fac_x', 'edge-c-' || gen_random_uuid(), 'live', clock_timestamp(), now() + interval '2 minutes') RETURNING id)
         INSERT INTO app.checkin_token (challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) SELECT id, '{A}', '{DA}', 'fac_x', 'unattestable', 'live', clock_timestamp(), now() + interval '10 minutes' FROM c$q$),
    ('push_token',
      $q$SELECT count(*) FROM app.push_token WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.push_token WHERE user_id = '{A}'$q$,
      $q$UPDATE app.push_token SET expo_token = 'x' WHERE user_id = '{B}'$q$, $q$UPDATE app.push_token SET expo_token = 'x' WHERE user_id = '{A}'$q$,
      $q$INSERT INTO app.push_token (user_id, device_id, expo_token) VALUES ('{B}', '{DB}', 'x') ON CONFLICT (user_id, device_id) DO UPDATE SET expo_token = excluded.expo_token$q$,
      $q$INSERT INTO app.push_token (user_id, device_id, expo_token) VALUES ('{A}', '{DA}', 'x') ON CONFLICT (user_id, device_id) DO UPDATE SET expo_token = excluded.expo_token$q$),
    ('signin_provider_token',
      $q$SELECT count(*) FROM app.signin_provider_token WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.signin_provider_token WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text, NULL::text, NULL::text),
    ('connector_account',
      $q$SELECT count(*) FROM app.connector_account WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.connector_account WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text, NULL::text, NULL::text),
    ('app_review_demo_account',
      $q$SELECT count(*) FROM app.app_review_demo_account WHERE user_id = '{D}'$q$, NULL::text,
      NULL::text, NULL::text, NULL::text, NULL::text),
    ('device_reward_ledger',
      $q$SELECT count(*) FROM app.device_reward_ledger WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.device_reward_ledger WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text,
      $q$INSERT INTO app.device_reward_ledger (device_id, user_id, reward_kind, reward_id) VALUES ('{DB}', '{B}', 'offer', gen_random_uuid())$q$,
      $q$INSERT INTO app.device_reward_ledger (device_id, user_id, reward_kind, reward_id) VALUES ('{DA}', '{A}', 'offer', gen_random_uuid())$q$),
    ('offer_code',
      $q$SELECT count(*) FROM app.offer_code WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.offer_code WHERE user_id = '{A}'$q$,
      $q$UPDATE app.offer_code SET hold_detail = hold_detail WHERE user_id = '{B}'$q$, $q$UPDATE app.offer_code SET hold_detail = hold_detail WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text),
    ('entitlement',
      $q$SELECT count(*) FROM app.entitlement WHERE user_id = '{B}'$q$, $q$SELECT count(*) FROM app.entitlement WHERE user_id = '{A}'$q$,
      $q$UPDATE app.entitlement SET hold_detail = hold_detail WHERE user_id = '{B}'$q$, $q$UPDATE app.entitlement SET hold_detail = hold_detail WHERE user_id = '{A}'$q$,
      NULL::text, NULL::text),
    ('offer',
      $q$SELECT count(*) FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e102'$q$, $q$SELECT count(*) FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e101'$q$,
      $q$UPDATE app.offer SET budget_reserved = budget_reserved WHERE id = 'eeee0000-0000-0000-0000-00000000e102'$q$, $q$UPDATE app.offer SET budget_reserved = budget_reserved WHERE id = 'eeee0000-0000-0000-0000-00000000e101'$q$,
      NULL::text, NULL::text),
    ('review_item',
      NULL::text, NULL::text, NULL::text, NULL::text,
      $q$INSERT INTO app.review_item (kind, subject_table, subject_id, detail) VALUES ('held_offer_budget_unreserved', 'offer_code', 'eeee0000-0000-0000-0000-0000000b0901', '{}')$q$,
      $q$INSERT INTO app.review_item (kind, subject_table, subject_id, detail) VALUES ('held_offer_budget_unreserved', 'offer_code', 'eeee0000-0000-0000-0000-0000000a0901', '{}')$q$),
    ('audit_log',
      $q$SELECT count(*) FROM app.audit_log WHERE actor_user_id = '{B}'$q$, $q$SELECT count(*) FROM app.audit_log WHERE actor_user_id = '{A}'$q$,
      NULL::text, NULL::text,
      $q$INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id) VALUES ('{B}', 'play.repick', 'play', 'x')$q$,
      $q$INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id) VALUES ('{A}', 'play.repick', 'play', 'x')$q$)
  ) AS t(tbl, fsel, osel, fupd, oupd, fins, oins)
  LOOP
    IF c.oins IS NOT NULL THEN
      RETURN NEXT lives_ok(pg_temp.subst(c.oins), c.tbl || ': control -- the bound actor can insert ITS OWN row');
      RETURN NEXT throws_ok(pg_temp.subst(c.fins), '42501', 'new row violates row-level security policy for table "' || c.tbl || '"',
        c.tbl || ': must-fail -- the bound actor cannot insert a row owned by someone else (RLS WITH CHECK, not a privilege error)');
    END IF;
    IF c.fsel IS NOT NULL THEN
      EXECUTE pg_temp.subst(c.fsel) INTO v_n;
      RETURN NEXT is(v_n, 0, c.tbl || ': must-fail -- the bound actor sees none of the other account''s rows');
    END IF;
    IF c.osel IS NOT NULL THEN
      EXECUTE pg_temp.subst(c.osel) INTO v_n;
      RETURN NEXT cmp_ok(v_n, '>', 0, c.tbl || ': control -- the bound actor sees its own rows (the probe is capable of seeing rows)');
    END IF;
    IF c.fupd IS NOT NULL THEN
      EXECUTE pg_temp.subst(c.fupd);
      GET DIAGNOSTICS v_n = ROW_COUNT;
      RETURN NEXT is(v_n, 0, c.tbl || ': must-fail -- UPDATE of another account''s rows affects 0 rows (silent: asserted by row count)');
      EXECUTE pg_temp.subst(c.oupd);
      GET DIAGNOSTICS v_n = ROW_COUNT;
      RETURN NEXT cmp_ok(v_n, '>=', 1, c.tbl || ': control -- the same UPDATE on the actor''s own row affects >= 1 row');
    END IF;
  END LOOP;
END
$f$;

-- Every table a user's data lives in (plus offer and the catalogs): with NO binding, or with a forged one, the
-- unscoped count is 0 -- and the catalog tables, which are public data, are NOT 0 (the control).
CREATE FUNCTION pg_temp.unbound_counts(p_label text) RETURNS SETOF text LANGUAGE plpgsql AS $f$
DECLARE
  t text;
  v_n int;
BEGIN
  FOREACH t IN ARRAY ARRAY['device', 'evidence', 'play', 'play_evidence', 'fraud_signal', 'checkin_challenge', 'checkin_token',
                           'push_token', 'signin_provider_token', 'connector_account', 'app_review_demo_account',
                           'device_reward_ledger', 'offer_code', 'entitlement', 'offer', 'audit_log', 'install_link_account', 'review_item']
  LOOP
    EXECUTE format('SELECT count(*) FROM app.%I', t) INTO v_n;
    RETURN NEXT is(v_n, 0, p_label || ': ' || t || ' -- sees no rows');
  END LOOP;
  EXECUTE 'SELECT count(*) FROM app.catalog_course' INTO v_n;
  RETURN NEXT cmp_ok(v_n, '>', 0, p_label || ': control -- the public catalog is still readable (the probe can see rows)');
END
$f$;

-- Short forms for the groups below ({A} {B} {D} {DA} {DB} are substituted).
CREATE FUNCTION pg_temp.lives(p_sql text, p_desc text) RETURNS text LANGUAGE sql AS $f$
  SELECT lives_ok(pg_temp.subst(p_sql), p_desc)
$f$;
CREATE FUNCTION pg_temp.throws(p_sql text, p_code text, p_msg text, p_desc text) RETURNS text LANGUAGE sql AS $f$
  SELECT throws_ok(pg_temp.subst(p_sql), p_code::char(5), p_msg, p_desc)
$f$;
CREATE FUNCTION pg_temp.scalar(p_sql text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  v text;
BEGIN
  EXECUTE pg_temp.subst(p_sql) INTO v;
  RETURN v;
END
$f$;


CREATE FUNCTION pg_temp.rows(p_sql text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE
  v_n int;
BEGIN
  EXECUTE pg_temp.subst(p_sql);
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$f$;

-- Unique per-run values (the nonce ledger and the rate-limit table outlive a transaction).
SELECT 'edge-nonce-' || substr(md5(random()::text), 1, 12) AS nonce1 \gset
SELECT 'edge-rl-' || substr(md5(random()::text), 1, 12) AS rlkey \gset

-- ============================================================================
-- 0. Posture: this really is a login role with nothing special about it
-- ============================================================================
SELECT is(session_user::text, 'edge_gateway', 'posture: the session user is edge_gateway (a real login, so SET ROLE is judged by ITS memberships)');
SELECT is(
  (SELECT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolinherit
   FROM pg_roles WHERE rolname = 'edge_gateway'),
  true, 'posture: edge_gateway can log in and is NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION NOINHERIT');
SELECT is(
  (SELECT bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolinherit)
   FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system')),
  true, 'posture: edge_actor and edge_system are NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION');

-- ============================================================================
-- 1. No role: edge_gateway itself can name and touch nothing
-- ============================================================================
SELECT pg_temp.throws($$SELECT count(*) FROM app.play$$, '42501', 'permission denied for schema app', 'no role: edge_gateway cannot read app.play (no schema usage, no grant)');
SELECT pg_temp.throws($$SELECT count(*) FROM app.catalog_course$$, '42501', 'permission denied for schema app', 'no role: edge_gateway cannot even read the public catalog');
SELECT pg_temp.throws($$INSERT INTO app.device (id, user_id, platform) VALUES (gen_random_uuid(), '{A}', 'ios')$$, '42501', 'permission denied for schema app', 'no role: edge_gateway cannot insert');
SELECT pg_temp.throws($$SELECT private.actor_uid()$$, '42501', 'permission denied for schema private', 'no role: edge_gateway cannot call private.actor_uid');
SELECT pg_temp.throws($$SELECT private.bind_actor('{A}')$$, '42501', 'permission denied for schema private', 'no role: edge_gateway cannot bind an actor');
SELECT pg_temp.throws($$SELECT count(*) FROM private.actor_binding$$, '42501', 'permission denied for schema private', 'no role: edge_gateway cannot read the actor binding table');
SELECT pg_temp.throws($$SELECT count(*) FROM private.consumed_nonce$$, '42501', 'permission denied for schema private', 'no role: edge_gateway cannot read the nonce ledger');
SELECT pg_temp.throws($$SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000a0903', '{A}', '{DA}', 'x', 'activate')$$, '42501', 'permission denied for schema app', 'no role: edge_gateway cannot call an app function');
SELECT pg_temp.throws($$SELECT count(*) FROM auth.users$$, '42501', 'permission denied for schema auth', 'no role: edge_gateway cannot read auth.users');
SELECT pg_temp.throws($$SELECT count(*) FROM vault.decrypted_secrets$$, '42501', 'permission denied for schema vault', 'no role: edge_gateway cannot read the vault');

-- ============================================================================
-- 2. SET ROLE escalation fails (judged by the session user, which IS edge_gateway)
-- ============================================================================
SELECT throws_ok(format('SET ROLE %I', r), '42501', format('permission denied to set role "%s"', r), format('escalation: edge_gateway cannot SET ROLE %s', r))
FROM unnest(ARRAY['service_role', 'authenticated', 'anon', 'authenticator', 'private_definer', 'supabase_admin', 'postgres', 'migration_owner', :'harness_user']) AS r;
SELECT throws_ok('SET SESSION AUTHORIZATION service_role', '42501', NULL, 'escalation: edge_gateway cannot SET SESSION AUTHORIZATION');
SELECT lives_ok('SET ROLE edge_actor', 'edge_gateway can SET ROLE edge_actor (the one escalation that is intended)');
SELECT throws_ok('SET ROLE service_role', '42501', 'permission denied to set role "service_role"', 'escalation: from INSIDE edge_actor, SET ROLE service_role still fails (session user is edge_gateway)');
SELECT throws_ok('SET ROLE private_definer', '42501', 'permission denied to set role "private_definer"', 'escalation: from inside edge_actor, SET ROLE private_definer fails');
SELECT lives_ok('RESET ROLE', 'RESET ROLE returns to edge_gateway');
SELECT lives_ok('SET ROLE edge_system', 'edge_gateway can SET ROLE edge_system');
SELECT throws_ok('SET ROLE authenticated', '42501', 'permission denied to set role "authenticated"', 'escalation: from inside edge_system, SET ROLE authenticated fails');
SELECT lives_ok('RESET ROLE', 'RESET ROLE again');
SELECT is(current_user::text, 'edge_gateway', 'after RESET ROLE the current user is edge_gateway again');

-- The roles cannot rewrite their own boundary either.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok('CREATE ROLE zz_edge_probe', '42501', NULL, 'boundary: edge_actor cannot CREATE ROLE');
SELECT throws_ok('ALTER ROLE edge_actor BYPASSRLS', '42501', NULL, 'boundary: edge_actor cannot grant itself BYPASSRLS');
SELECT throws_ok('GRANT service_role TO edge_actor', '42501', NULL, 'boundary: edge_actor cannot grant itself service_role');
SELECT throws_ok('ALTER TABLE app.play DISABLE ROW LEVEL SECURITY', '42501', NULL, 'boundary: edge_actor cannot disable RLS on app.play');
SELECT throws_ok('ALTER TABLE app.play NO FORCE ROW LEVEL SECURITY', '42501', NULL, 'boundary: edge_actor cannot un-FORCE RLS on app.play');
SELECT throws_ok($$CREATE POLICY zz_edge_probe ON app.play FOR SELECT TO edge_actor USING (true)$$, '42501', NULL, 'boundary: edge_actor cannot create a policy for itself');
SELECT throws_ok('CREATE TABLE app.zz_edge_probe (a int)', '42501', 'permission denied for schema app', 'boundary: edge_actor cannot create objects in app');
SELECT throws_ok('CREATE FUNCTION private.zz_edge_probe() RETURNS int LANGUAGE sql AS $z$ SELECT 1 $z$', '42501', 'permission denied for schema private', 'boundary: edge_actor cannot create functions in private');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok('ALTER ROLE edge_system BYPASSRLS', '42501', NULL, 'boundary: edge_system cannot grant itself BYPASSRLS');
SELECT throws_ok('ALTER TABLE app.catalog_course DISABLE ROW LEVEL SECURITY', '42501', NULL, 'boundary: edge_system cannot disable RLS on a catalog table');
ROLLBACK;

-- ============================================================================
-- 3. Unbound edge_actor sees nothing
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'unbound: private.actor_uid() is NULL');
SELECT * FROM pg_temp.unbound_counts('unbound');
SELECT pg_temp.throws($$INSERT INTO app.device (id, user_id, platform) VALUES (gen_random_uuid(), '{A}', 'ios')$$, '42501', 'new row violates row-level security policy for table "device"', 'unbound: cannot insert a row for any user');
SELECT pg_temp.throws($$INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES (NULL, 'x', '{}')$$, '42501', 'new row violates row-level security policy for table "fraud_signal"', 'unbound: cannot insert an ownerless row either (NULL user_id is not a way round the policy)');
SELECT is(pg_temp.rows($$UPDATE app.play SET policy_version = policy_version$$), 0, 'unbound: UPDATE affects 0 rows');
ROLLBACK;

-- ============================================================================
-- 4. Forged session state is ignored
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT
    set_config('request.jwt.claims', '{"sub":"eeee0000-0000-0000-0000-0000000000b0","role":"authenticated"}', true),
    set_config('request.jwt.claim.sub', 'eeee0000-0000-0000-0000-0000000000b0', true),
    set_config('request.jwt.claim.role', 'service_role', true),
    set_config('app.delete_my_data.target_user_id', 'eeee0000-0000-0000-0000-0000000000b0', true),
    set_config('app.delete_my_data.target_email', 'forged-target', true),
    set_config('app.guard.offer_code_id', 'eeee0000-0000-0000-0000-0000000b0901', true),
    set_config('app.guard.entitlement_id', 'eeee0000-0000-0000-0000-0000000b0801', true),
    set_config('app.guard.play_id', 'eeee0000-0000-0000-0000-0000000b0a01', true),
    set_config('app.edge.link_device_id', 'eeee0000-0000-0000-0000-00000000b001', true),
    set_config('app.edge.link_hash', repeat('a', 64), true)$$,
  'forged: every session variable any policy in this database has ever read is set to impersonate B');
SELECT throws_ok($$SELECT set_config('role', 'service_role', true)$$, '42501', NULL, 'forged: set_config(''role'') cannot become service_role');
SELECT * FROM pg_temp.unbound_counts('forged GUCs, no binding');
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'forged: bind A (the actual actor) with the forged GUCs still set');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'forged: the binding, not the forged claims, decides the actor');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'eeee0000-0000-0000-0000-0000000000b0'), 0, 'forged: bound as A with B''s claims forged, B''s devices stay invisible');
SELECT is((SELECT count(*)::int FROM app.offer_code WHERE user_id = 'eeee0000-0000-0000-0000-0000000000b0'), 0, 'forged: B''s offer codes stay invisible (guard-GUC forged)');
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 2, 'forged: A''s own plays are still A''s');
ROLLBACK;

-- ============================================================================
-- 5. The binding: one per transaction, fail closed afterwards
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'bind: edge_actor binds A');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'bind: actor_uid() is A');
SELECT pg_temp.throws($$SELECT private.bind_actor('{B}')$$, '42501', 'bind_actor: this transaction already has a bound actor', 'bind: a second bind (another user) in the same transaction raises');
SELECT pg_temp.throws($$SELECT private.bind_actor('{A}')$$, '42501', 'bind_actor: this transaction already has a bound actor', 'bind: a second bind (the same user) raises too');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'bind: still A after the refused re-binds');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.bind_actor(NULL)$$, '22023', 'bind_actor: the actor uid must not be NULL', 'bind: NULL uid raises');
SELECT throws_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-00000000dead')$$, 'P0002', 'bind_actor: no such user', 'bind: an unknown uid raises');
SELECT is(private.actor_uid(), NULL::uuid, 'bind: a refused bind leaves the transaction unbound');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_actor;
SAVEPOINT s1;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'savepoint: bind A inside a savepoint');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'savepoint: bound inside the savepoint');
ROLLBACK TO SAVEPOINT s1;
SELECT is(private.actor_uid(), NULL::uuid, 'savepoint: after ROLLBACK TO the savepoint the binding is gone (fails closed)');
SELECT is((SELECT count(*)::int FROM app.device), 0, 'savepoint: and the transaction sees no rows');
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, 'savepoint: the undone bind may be replaced (the transaction has no bound actor)');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000b0'::uuid, 'savepoint: now bound to B');
ROLLBACK;

-- A real COMMIT: the binding row survives it, but is dead.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'commit: bind A in transaction 1');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'commit: bound in transaction 1');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'stale: the next transaction on the same connection is NOT bound');
SELECT is((SELECT count(*)::int FROM app.device), 0, 'stale: it sees no device rows');
SELECT is((SELECT count(*)::int FROM app.play), 0, 'stale: it sees no play rows');
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, 'stale: and may bind afresh (the old row is replaced)');
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000b0'::uuid, 'stale: now bound to B');
ROLLBACK;
SET ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'stale: an autocommit statement on the same connection is unbound too');
SELECT is((SELECT count(*)::int FROM app.evidence), 0, 'stale: autocommit sees no evidence rows');
RESET ROLE;

-- Who may bind.
BEGIN;
SET LOCAL ROLE edge_system;
SELECT pg_temp.throws($$SELECT private.bind_actor('{A}')$$, '42501', 'permission denied for function bind_actor', 'bind: edge_system cannot bind an actor');
SELECT throws_ok($$SELECT private.actor_uid()$$, '42501', 'permission denied for function actor_uid', 'bind: edge_system cannot even ask who the actor is');
SELECT throws_ok($$SELECT private.bind_actor_internal('eeee0000-0000-0000-0000-0000000000a0', 'user')$$, '42501', 'permission denied for function bind_actor_internal', 'bind: nobody can reach the binding core');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.bind_actor_internal('eeee0000-0000-0000-0000-0000000000a0', 'system_delegate')$$, '42501', 'permission denied for function bind_actor_internal', 'bind: edge_actor cannot reach the binding core either (no self-declared system_delegate)');
ROLLBACK;

-- ============================================================================
-- 6. The own-row matrix: A against B, every table
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'matrix: bind A');
SELECT * FROM pg_temp.own_row_cells();
SELECT pg_temp.throws($$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES ('eeee0000-0000-0000-0000-0000000a0a01', 'eeee0000-0000-0000-0000-0000000b0e01', '{A}')$$, '42501', 'new row violates row-level security policy for table "play_evidence"', 'play_evidence: A''s play linked to B''s evidence is refused');
SELECT pg_temp.throws($$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES ('eeee0000-0000-0000-0000-0000000b0a02', 'eeee0000-0000-0000-0000-0000000a0e02', '{A}')$$, '42501', 'new row violates row-level security policy for table "play_evidence"', 'play_evidence: B''s play linked to A''s evidence is refused');
SELECT pg_temp.throws($$INSERT INTO app.device_reward_ledger (device_id, user_id, reward_kind, reward_id) VALUES ('{DB}', '{A}', 'offer', gen_random_uuid())$$, '42501', 'new row violates row-level security policy for table "device_reward_ledger"', 'device_reward_ledger: A''s reward on B''s device is refused');
SELECT pg_temp.throws($$INSERT INTO app.review_item (kind, subject_table, subject_id, detail) VALUES ('held_offer_budget_unreserved', 'play', 'eeee0000-0000-0000-0000-0000000a0a01', '{}')$$, '42501', 'new row violates row-level security policy for table "review_item"', 'review_item: only an offer_code subject is allowed');
SELECT pg_temp.throws($$INSERT INTO app.review_item (kind, subject_table, subject_id, detail) VALUES ('anything_else', 'offer_code', 'eeee0000-0000-0000-0000-0000000a0901', '{}')$$, '42501', 'new row violates row-level security policy for table "review_item"', 'review_item: only the two budget-unreserved kinds are allowed');
SELECT pg_temp.throws($$INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id) VALUES ('{A}', 'admin.anything', 'play', 'x')$$, '42501', 'new row violates row-level security policy for table "audit_log"', 'audit_log: only the play.repick action can be written');
SELECT pg_temp.throws($$INSERT INTO app.checkin_challenge (user_id, staff_user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('{A}', '{A}', '{DA}', 'fac_x', 'edge-c-' || gen_random_uuid(), 'live', clock_timestamp(), now() + interval '2 minutes')$$, '42501', 'new row violates row-level security policy for table "checkin_challenge"', 'checkin_challenge: a staff-issued challenge is not an edge_actor path');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action <> 'play.repick'), 0, 'audit_log: A''s own non-repick audit row (seeded by the harness) is not visible to the actor');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, 'matrix (reversed): bind B');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 0, 'reversed: B sees none of A''s devices');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'eeee0000-0000-0000-0000-0000000000b0'), 1, 'reversed: control -- B sees its own device');
SELECT is((SELECT count(*)::int FROM app.offer_code WHERE user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 0, 'reversed: B sees none of A''s offer codes');
SELECT is((SELECT count(*)::int FROM app.entitlement WHERE user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 0, 'reversed: B sees none of A''s entitlements');
SELECT is((SELECT count(*)::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e101'), 0, 'reversed: B does not see the offer A holds a code on');
SELECT is((SELECT count(*)::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e102'), 1, 'reversed: control -- B sees the offer it holds a code on');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = 'eeee0000-0000-0000-0000-0000000000b0'), 1, 'reversed: control -- B sees its own play.repick audit row');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000d0')$$, 'demo: bind D (the app-review demo account)');
SELECT is((SELECT count(*)::int FROM app.app_review_demo_account WHERE user_id = 'eeee0000-0000-0000-0000-0000000000d0'), 1, 'demo: control -- the demo account sees its own demo row');
ROLLBACK;

-- ============================================================================
-- 7. Column and privilege limits (what the role may not do even to its OWN rows)
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'limits: bind A');
SELECT pg_temp.throws($$SELECT refresh_token_ciphertext FROM app.signin_provider_token$$, '42501', NULL, 'limits: sign-in token ciphertext is unreadable (column grant is user_id, provider only)');
SELECT pg_temp.throws($$SELECT dek_wrapped FROM app.connector_account$$, '42501', NULL, 'limits: connector key material is unreadable');
SELECT pg_temp.throws($$SELECT cleared_by FROM app.fraud_signal$$, '42501', NULL, 'limits: fraud_signal.cleared_by is unreadable');
SELECT pg_temp.throws($$UPDATE app.device SET attest_public_key = NULL WHERE user_id = '{A}'$$, '42501', NULL, 'limits: device.attest_public_key is not writable (App Attest registration is not an edge path)');
SELECT pg_temp.throws($$UPDATE app.device SET attest_key_id = 'x' WHERE user_id = '{A}'$$, '42501', NULL, 'limits: device.attest_key_id is not writable');
SELECT pg_temp.throws($$UPDATE app.device SET fraud_voided_at = now() WHERE user_id = '{A}'$$, '42501', NULL, 'limits: device.fraud_voided_at is admin-only');
SELECT pg_temp.throws($$UPDATE app.offer_code SET review_cleared_at = now() WHERE user_id = '{A}'$$, '42501', NULL, 'limits: offer_code.review_cleared_at is a reviewer decision');
SELECT pg_temp.throws($$UPDATE app.offer_code SET rests_on_unattestable = false WHERE user_id = '{A}'$$, '42501', NULL, 'limits: offer_code.rests_on_unattestable is written only by the earn path');
SELECT pg_temp.throws($$UPDATE app.offer_code SET expires_at = now() + interval '1 year' WHERE user_id = '{A}'$$, '42501', NULL, 'limits: offer_code.expires_at is not writable');
SELECT pg_temp.throws($$UPDATE app.offer_code SET play_id = NULL WHERE user_id = '{A}'$$, '42501', NULL, 'limits: offer_code.play_id is not writable');
SELECT pg_temp.throws($$UPDATE app.entitlement SET review_cleared_at = now() WHERE user_id = '{A}'$$, '42501', NULL, 'limits: entitlement.review_cleared_at is a reviewer decision');
SELECT pg_temp.throws($$UPDATE app.offer SET budget_cap = 1000000 WHERE id = 'eeee0000-0000-0000-0000-00000000e101'$$, '42501', NULL, 'limits: offer.budget_cap is not writable');
SELECT pg_temp.throws($$UPDATE app.offer SET budget_used = 0 WHERE id = 'eeee0000-0000-0000-0000-00000000e101'$$, '42501', NULL, 'limits: offer.budget_used is not writable');
SELECT pg_temp.throws($$UPDATE app.offer SET status = 'draft' WHERE id = 'eeee0000-0000-0000-0000-00000000e101'$$, '42501', NULL, 'limits: offer.status is not writable');
SELECT pg_temp.throws($$UPDATE app.play SET user_id = '{B}' WHERE user_id = '{A}'$$, '42501', NULL, 'limits: a row cannot be re-owned (user_id is in no UPDATE grant)');
SELECT pg_temp.throws($$UPDATE app.evidence SET user_id = '{B}' WHERE user_id = '{A}'$$, '42501', NULL, 'limits: evidence cannot be re-owned');
SELECT pg_temp.throws($$UPDATE app.checkin_challenge SET nonce_hash = 'x' WHERE user_id = '{A}'$$, '42501', NULL, 'limits: a challenge nonce cannot be rewritten');
SELECT pg_temp.throws($$UPDATE app.checkin_token SET attestation_grade = 'attested' WHERE user_id = '{A}'$$, '42501', NULL, 'limits: a token''s attestation grade cannot be rewritten');
SELECT pg_temp.throws($$UPDATE app.audit_log SET detail = '{}' WHERE actor_user_id = '{A}'$$, '42501', NULL, 'limits: the audit log is insert-only for edge_actor');
SELECT pg_temp.throws($$INSERT INTO app.offer_code (offer_id, user_id, facility_id) VALUES ('eeee0000-0000-0000-0000-00000000e101', '{A}', 'fac_x')$$, '42501', 'permission denied for table offer_code', 'limits: edge_actor cannot create an offer code (the earn path is not an edge_actor path)');
SELECT pg_temp.throws($$INSERT INTO app.entitlement (user_id, kind, trail_id) VALUES ('{A}', 'special_marker', 'trl_u')$$, '42501', 'permission denied for table entitlement', 'limits: edge_actor cannot create an entitlement');
SELECT pg_temp.throws($$INSERT INTO app.catalog_course (id, facility_id, name, catalog_version) VALUES ('crs_zz', 'fac_x', 'zz', 1)$$, '42501', 'permission denied for table catalog_course', 'limits: edge_actor cannot write the catalog');
SELECT pg_temp.throws($$UPDATE app.catalog_course SET name = 'zz'$$, '42501', NULL, 'limits: edge_actor cannot update the catalog');
SELECT pg_temp.throws($$INSERT INTO app.catalog_signing_key (kid, public_key_b64url) VALUES ('zz', 'zz')$$, '42501', 'permission denied for table catalog_signing_key', 'limits: edge_actor cannot register a signing key');
SELECT pg_temp.throws($$SELECT created_at FROM app.catalog_signing_key$$, '42501', NULL, 'limits: only the key columns are readable on catalog_signing_key');
SELECT pg_temp.throws($$SELECT cursor_play_id FROM app.catalog_rescore_backlog$$, '42501', NULL, 'limits: only course_id and done_at are readable on the rescore backlog');
SELECT is((SELECT count(*)::int FROM (SELECT kid, public_key_b64url, revoked_at FROM app.catalog_signing_key) k), 0, 'limits: control -- the key columns ARE readable (the table is empty in the harness)');
SELECT is((SELECT count(*)::int FROM (SELECT course_id, done_at FROM app.catalog_rescore_backlog) k), 0, 'limits: control -- course_id/done_at ARE readable');
SELECT throws_ok(format('DELETE FROM app.%I', t), '42501', format('permission denied for table %s', t), format('limits: edge_actor has no DELETE on app.%s', t))
FROM unnest(ARRAY['device', 'evidence', 'play', 'play_evidence', 'fraud_signal', 'checkin_challenge', 'checkin_token', 'push_token', 'device_reward_ledger', 'offer_code', 'entitlement', 'offer', 'review_item', 'audit_log', 'catalog_course']) AS t;
SELECT throws_ok(format('TRUNCATE app.%I', t), '42501', format('permission denied for table %s', t), format('limits: edge_actor cannot TRUNCATE app.%s', t))
FROM unnest(ARRAY['play', 'evidence', 'offer_code']) AS t;
ROLLBACK;

-- ============================================================================
-- 8. No private.* tables, no admin functions, for either role
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok(format('SELECT count(*) FROM %s', t), '42501', NULL, 'private access: edge_actor cannot read ' || t)
FROM unnest(ARRAY['private.actor_binding', 'private.consumed_nonce', 'private.rate_limit_bucket', 'private.definer_policy_allowlist', 'private.edge_policy_allowlist',
                  'private.function_inventory', 'private.pii_retention_policy', 'private.pii_export_policy', 'private.pseudonym_key_registry',
                  'app.admin_user', 'app.partner_member', 'app.profile', 'app.attestation', 'app.partner_invite', 'app.course_qr_token', 'app.purchase_evidence',
                  'app.receipt_fingerprint', 'app.catalog_designer', 'app.catalog_trail', 'app.catalog_roster_version', 'storage.objects', 'auth.users']) AS t;
SELECT pg_temp.throws(q.sql, '42501', 'permission denied for function ' || q.fn, 'private access: edge_actor cannot call ' || q.fn)
FROM (VALUES
  ('hit_rate_limit', $s$SELECT private.hit_rate_limit('k', interval '1 hour', 5)$s$),
  ('delete_my_data', $s$SELECT private.delete_my_data('{B}')$s$),
  ('export_my_data', $s$SELECT private.export_my_data('{B}')$s$),
  ('purge_consumed_nonce', $s$SELECT private.purge_consumed_nonce()$s$),
  ('purge_rate_limit_buckets', $s$SELECT private.purge_rate_limit_buckets()$s$),
  ('is_admin', $s$SELECT private.is_admin('{A}')$s$),
  ('list_queued_catalog', $s$SELECT * FROM private.list_queued_catalog(10)$s$),
  ('list_rescore_plays', $s$SELECT * FROM private.list_rescore_plays('crs_y1', NULL, NULL, 10)$s$),
  ('purge_fix_coords', $s$SELECT private.purge_fix_coords(30, 10)$s$),
  ('bind_delegate_for_queued_evidence', $s$SELECT private.bind_delegate_for_queued_evidence('eeee0000-0000-0000-0000-0000000a0e03')$s$),
  ('bind_delegate_for_rescore', $s$SELECT private.bind_delegate_for_rescore(1, 'eeee0000-0000-0000-0000-0000000a0a01')$s$),
  ('hit_system_rate_limit', $s$SELECT private.hit_system_rate_limit('k', interval '1 hour', 5)$s$),
  ('resolve_held_offer_code', $s$SELECT app.resolve_held_offer_code('eeee0000-0000-0000-0000-0000000a0901', true, '{A}')$s$),
  ('resolve_held_entitlement', $s$SELECT app.resolve_held_entitlement('eeee0000-0000-0000-0000-0000000a0801', true, '{A}')$s$),
  ('mark_account_devices_fraud_voided', $s$SELECT app.mark_account_devices_fraud_voided('{B}', '{A}')$s$),
  ('device_link_signals', $s$SELECT * FROM app.device_link_signals('{DA}')$s$),
  ('reserve_offer_budget', $s$SELECT app.reserve_offer_budget('eeee0000-0000-0000-0000-00000000e101', 1)$s$),
  ('consume_offer_budget', $s$SELECT app.consume_offer_budget('eeee0000-0000-0000-0000-00000000e101', 1)$s$),
  ('dedupe_receipt_fingerprint', $s$SELECT app.dedupe_receipt_fingerprint(gen_random_uuid(), '{A}', 'p', 'fac_x', current_date, NULL)$s$)
) AS q(fn, sql);
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok(format('SELECT count(*) FROM %s', t), '42501', NULL, 'private access: edge_system cannot read ' || t)
FROM unnest(ARRAY['private.actor_binding', 'private.consumed_nonce', 'private.rate_limit_bucket', 'private.definer_policy_allowlist', 'private.edge_policy_allowlist',
                  'private.function_inventory', 'private.pii_retention_policy', 'private.pii_export_policy', 'private.pseudonym_key_registry',
                  'app.admin_user', 'app.partner_member', 'app.profile', 'app.attestation', 'app.partner_invite', 'app.course_qr_token', 'app.purchase_evidence',
                  'app.receipt_fingerprint', 'storage.objects', 'auth.users']) AS t;
SELECT pg_temp.throws(q.sql, '42501', 'permission denied for function ' || q.fn, 'private access: edge_system cannot call ' || q.fn)
FROM (VALUES
  ('hit_actor_rate_limit', $s$SELECT private.hit_actor_rate_limit('k', interval '1 hour', 5)$s$),
  ('delete_my_data_for_actor', $s$SELECT private.delete_my_data_for_actor()$s$),
  ('export_my_data_for_actor', $s$SELECT private.export_my_data_for_actor()$s$),
  ('record_consumed_nonce', $s$SELECT private.record_consumed_nonce('x', now())$s$),
  ('device_link_signals_for_actor', $s$SELECT * FROM private.device_link_signals_for_actor('{DA}')$s$),
  ('hit_rate_limit', $s$SELECT private.hit_rate_limit('k', interval '1 hour', 5)$s$),
  ('delete_my_data', $s$SELECT private.delete_my_data('{B}')$s$),
  ('export_my_data', $s$SELECT private.export_my_data('{B}')$s$),
  ('activate_offer_code', $s$SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000a0903', '{A}', '{DA}', 'x', 'activate')$s$),
  ('activate_entitlement', $s$SELECT app.activate_entitlement('eeee0000-0000-0000-0000-0000000a0801', '{A}', '{DA}', 'x', 'activate')$s$),
  ('reserve_offer_for_code', $s$SELECT app.reserve_offer_for_code('eeee0000-0000-0000-0000-00000000e101', 'eeee0000-0000-0000-0000-0000000a0901', 'x')$s$),
  ('release_offer_budget', $s$SELECT app.release_offer_budget('eeee0000-0000-0000-0000-00000000e101', 1)$s$),
  ('release_account_reservations', $s$SELECT app.release_account_reservations('{A}')$s$),
  ('resolve_held_offer_code', $s$SELECT app.resolve_held_offer_code('eeee0000-0000-0000-0000-0000000a0901', true, '{A}')$s$),
  ('mark_account_devices_fraud_voided', $s$SELECT app.mark_account_devices_fraud_voided('{B}', '{A}')$s$),
  ('device_link_signals', $s$SELECT * FROM app.device_link_signals('{DA}')$s$),
  ('record_install_link', $s$SELECT app.record_install_link('{A}', '{DA}', repeat('e', 64))$s$),
  ('account_pseudonyms', $s$SELECT * FROM private.account_pseudonyms('{A}')$s$),
  ('validate_and_register_pseudonym_hmac_id', $s$SELECT private.validate_and_register_pseudonym_hmac_id(gen_random_uuid())$s$)
) AS q(fn, sql);
ROLLBACK;


-- ============================================================================
-- 9. edge_system: the catalog import, and nothing about players
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok(format('SELECT count(*) FROM app.%I', t), '42501', 'permission denied for table ' || t, 'edge_system: no access to app.' || t)
FROM unnest(ARRAY['device', 'evidence', 'play', 'play_evidence', 'fraud_signal', 'checkin_challenge', 'checkin_token', 'push_token',
                  'signin_provider_token', 'connector_account', 'app_review_demo_account', 'device_reward_ledger', 'offer_code',
                  'entitlement', 'offer', 'review_item', 'audit_log']) AS t;
SELECT throws_ok($$INSERT INTO app.evidence (user_id, source, source_ref, input_hash, local_date) VALUES ('eeee0000-0000-0000-0000-0000000000a0', 'self_report', 'x', 'h', current_date)$$, '42501', 'permission denied for table evidence', 'edge_system: cannot write a player''s evidence');
SELECT throws_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, '42501', 'permission denied for function bind_actor', 'edge_system: cannot bind an actor');

-- The importer's own statements (Repo#catalog in privileged.ts buildImporterRepo), as edge_system.
SELECT lives_ok($s$INSERT INTO app.catalog_version (version, site_version, contract_version, sha256, kid, published_at)
  VALUES (990, '29991231-0000099', 'v1', repeat('b', 64), 'kid_edge_sys', now())$s$, 'import: catalog_version insert');
SELECT is((SELECT coalesce(max(version), 0)::int FROM app.catalog_version), 990, 'import: catalog_version read (max)');
SELECT lives_ok($s$INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version)
  SELECT t.id, t.kind, 'stub'::app.ledger_status, t.fv FROM unnest(ARRAY['crs_sys1', 'fac_sys1', 'trl_sys1', 'des_sys1', 'hol_sys1']::text[], ARRAY['course', 'facility', 'trail', 'designer', 'hole']::text[], ARRAY[990, 990, 990, 990, 990]::int[]) AS t(id, kind, fv)
  ON CONFLICT (id) DO NOTHING$s$, 'import: ledger ids (ensureLedgerIdsExist)');
SELECT is(pg_temp.rows($s$UPDATE app.catalog_id_ledger l SET status = 'verified'::app.ledger_status, verified_in_version = 990, tombstoned_at = coalesce(l.tombstoned_at, now()), merged_into = coalesce(l.merged_into, nullif('', ''))
  FROM unnest(ARRAY['crs_sys1']::text[]) AS t(id) WHERE l.id = t.id$s$), 1, 'import: ledger state update (applyLedgerState) affects the row');
SELECT lives_ok($s$INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('trl_sys1', 'trail-sys', 'Trail Sys', 990)
  ON CONFLICT (id) DO UPDATE SET slug = excluded.slug, name = excluded.name, catalog_version = excluded.catalog_version$s$, 'import: trail upsert');
SELECT lives_ok($s$INSERT INTO app.catalog_designer (id, name, catalog_version) VALUES ('des_sys1', 'Des Sys', 990)
  ON CONFLICT (id) DO UPDATE SET name = excluded.name, catalog_version = excluded.catalog_version$s$, 'import: designer upsert');
SELECT lives_ok($s$INSERT INTO app.catalog_facility (id, slug, region, tz, name, catalog_version) VALUES ('fac_sys1', 'fac-sys', 'US-TN', 'America/Chicago', 'Fac Sys', 990)
  ON CONFLICT (id) DO UPDATE SET slug = excluded.slug, region = excluded.region, tz = excluded.tz, name = excluded.name, catalog_version = excluded.catalog_version$s$, 'import: facility upsert');
SELECT lives_ok($s$INSERT INTO app.catalog_course (id, facility_id, name, holes, verification_status, closed, catalog_version)
  SELECT t.id, t.facility_id, t.name, t.holes, t.vs, t.closed = 1, t.cv FROM unnest(ARRAY['crs_sys1']::text[], ARRAY['fac_sys1']::text[], ARRAY['Crs Sys']::text[], ARRAY[18]::int[], ARRAY['unverified']::app.verification_status[], ARRAY[0]::int[], ARRAY[990]::int[]) AS t(id, facility_id, name, holes, vs, closed, cv)
  ON CONFLICT (id) DO UPDATE SET facility_id = excluded.facility_id, name = excluded.name, holes = coalesce(excluded.holes, app.catalog_course.holes), verification_status = excluded.verification_status, closed = excluded.closed, catalog_version = excluded.catalog_version$s$, 'import: course upsert');
SELECT is(pg_temp.rows($s$UPDATE app.catalog_course c SET designer_id = d.designer_id FROM unnest(ARRAY['crs_sys1']::text[], ARRAY['des_sys1']::text[]) AS d(course_id, designer_id)
  WHERE c.id = d.course_id AND EXISTS (SELECT 1 FROM app.catalog_designer WHERE id = d.designer_id)$s$), 1, 'import: course designer update affects the row');
SELECT lives_ok($s$INSERT INTO app.catalog_hole (id, course_id, number, catalog_version) VALUES ('hol_sys1', 'crs_sys1', 1, 990)
  ON CONFLICT (id) DO UPDATE SET course_id = excluded.course_id, number = excluded.number, catalog_version = excluded.catalog_version$s$, 'import: hole upsert');
SELECT lives_ok($s$INSERT INTO app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) VALUES ('trl_sys1', 1, 'course', 'facility', now())
  ON CONFLICT (trail_id, version) DO NOTHING$s$, 'import: roster version insert');
SELECT lives_ok($s$INSERT INTO app.catalog_roster_member (trail_id, roster_version, unit, course_id, stop_order) VALUES ('trl_sys1', 1, 'course', 'crs_sys1', 1)$s$, 'import: roster member insert (identity column needs no sequence grant)');
SELECT lives_ok($s$INSERT INTO app.catalog_kid_revocation (kid, first_revoked_in_catalog_version) SELECT k, '29991231-0000099' FROM unnest(ARRAY['kid_edge_rev']::text[]) AS k ON CONFLICT (kid) DO NOTHING$s$, 'import: kid revocation insert');
SELECT lives_ok($s$SELECT k.kid, k.public_key_b64url, coalesce(k.revoked_at, (SELECT r.recorded_at FROM app.catalog_kid_revocation r WHERE r.kid = k.kid)) FROM app.catalog_signing_key k WHERE k.kid = 'kid_edge'$s$, 'import: signing key lookup');
SELECT lives_ok($s$INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) SELECT c, 'promotion', 990 FROM unnest(ARRAY['crs_sys1', 'crs_y1']::text[]) AS c ON CONFLICT (course_id, reason, catalog_version) DO NOTHING$s$, 'import: rescore backlog insert (a row for crs_sys1 and one for the harness course crs_y1)');
SELECT is(pg_temp.rows($s$UPDATE app.catalog_rescore_backlog SET cursor_play_id = NULL, cursor_created_at = NULL, finished_at = coalesce(finished_at, clock_timestamp()), swept = true WHERE course_id = 'crs_sys1'$s$), 1, 'import: backlog cursor update affects the row');
SELECT throws_ok($s$UPDATE app.catalog_version SET sha256 = repeat('c', 64) WHERE version = 990$s$, '42501', NULL, 'limits: catalog_version is append-only for edge_system (no UPDATE grant)');
SELECT throws_ok($s$UPDATE app.catalog_course SET boundary = NULL WHERE id = 'crs_sys1'$s$, '42501', NULL, 'limits: edge_system cannot write course geometry');
SELECT throws_ok($s$INSERT INTO app.catalog_signing_key (kid, public_key_b64url) VALUES ('zz', 'zz')$s$, '42501', 'permission denied for table catalog_signing_key', 'limits: edge_system cannot register a signing key');
SELECT throws_ok($s$DELETE FROM app.catalog_course WHERE id = 'crs_sys1'$s$, '42501', 'permission denied for table catalog_course', 'limits: edge_system cannot delete catalog rows');
-- what edge_actor sees of those same rows (the transaction can switch: the session user is edge_gateway)
SET LOCAL ROLE edge_actor;
SELECT is((SELECT count(*)::int FROM app.catalog_kid_revocation WHERE kid = 'kid_edge_rev'), 1, 'catalog read: edge_actor sees the revoked kid (open_read policy)');
SELECT is((SELECT count(*)::int FROM app.catalog_rescore_backlog WHERE course_id = 'crs_y1' AND done_at IS NULL), 1, 'catalog read: edge_actor sees that crs_y1 has an open backlog row (repickEligible)');
SELECT is((SELECT count(*)::int FROM app.catalog_course WHERE id = 'crs_sys1'), 1, 'catalog read: edge_actor sees the imported course');
SET LOCAL ROLE edge_system;
-- system rate limit
SELECT is(private.hit_system_rate_limit('edge-sys-test', interval '1 hour', 2), 1, 'system rate limit: first hit returns 1');
SELECT is(private.hit_system_rate_limit('edge-sys-test', interval '1 hour', 2), 2, 'system rate limit: second hit returns 2');
SELECT is(private.hit_system_rate_limit('edge-sys-test', interval '1 hour', 2), 3, 'system rate limit: the over-cap hit returns the count and does NOT raise (the increment must commit)');
SELECT throws_ok($$SELECT private.hit_system_rate_limit('', interval '1 hour', 2)$$, '22023', NULL, 'system rate limit: an empty key raises');
SELECT throws_ok($$SELECT private.hit_system_rate_limit('k', interval '2 days', 2)$$, '22023', NULL, 'system rate limit: a window over a day raises');
SELECT throws_ok($$SELECT private.hit_system_rate_limit('k', interval '1 hour', 0)$$, '22023', NULL, 'system rate limit: max 0 raises');
ROLLBACK;

-- ============================================================================
-- 9b. edge_system's cross-user definers
-- ============================================================================
BEGIN;
SET LOCAL ROLE edge_system;
SELECT lives_ok($s$INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) VALUES ('crs_y1', 'promotion', 1)$s$, 'definers: an open backlog row for crs_y1 (written by edge_system)');
SELECT is((SELECT count(*)::int FROM private.list_queued_catalog(100) WHERE id = 'eeee0000-0000-0000-0000-0000000a0e03' AND user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 1, 'list_queued_catalog returns the queued row and its owner');
SELECT is((SELECT count(*)::int FROM private.list_queued_catalog(100) WHERE id = 'eeee0000-0000-0000-0000-0000000a0e01'), 0, 'list_queued_catalog does not return an accepted row');
SELECT is((pg_get_function_result('private.list_queued_catalog(integer)'::regprocedure) ~ 'queued_input'), false, 'list_queued_catalog does not return the raw queued submission (no coordinates leave the owner''s own transaction)');
SELECT is((SELECT count(*)::int FROM private.list_rescore_plays('crs_y1', NULL, NULL, 100) WHERE user_id IN ('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-0000000000b0')), 2, 'list_rescore_plays returns the plays at the course with an OPEN backlog row');
SELECT is((SELECT count(*)::int FROM private.list_rescore_plays('crs_x1', NULL, NULL, 100)), 0, 'list_rescore_plays returns nothing for a course with no open backlog row, though plays exist there (the policy, not the function body, enforces it)');
SELECT is((SELECT count(*)::int FROM private.list_rescore_plays('crs_y1', (SELECT created_at FROM private.list_rescore_plays('crs_y1', NULL, NULL, 1)), (SELECT play_id FROM private.list_rescore_plays('crs_y1', NULL, NULL, 1)), 100)
           WHERE user_id IN ('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-0000000000b0')), 1, 'list_rescore_plays: the keyset cursor pages (one play after the first)');
-- purge: two rows lose their coordinates (UA 40 days old; UB at a verified, never-split course); UA's recent row at crs_y1 (open backlog) keeps them
SELECT is(private.purge_fix_coords(30, 100) >= 2, true, 'purge_fix_coords: purges the aged row and the row at a course that can no longer be re-picked');
SELECT is(private.purge_fix_coords(30, 100), 0, 'purge_fix_coords: idempotent (nothing left to purge)');
SELECT throws_ok($$SELECT private.purge_fix_coords(31, 10)$$, '22023', NULL, 'purge_fix_coords: a retention above 30 days is refused');
SELECT throws_ok($$SELECT private.purge_fix_coords(0, 10)$$, '22023', NULL, 'purge_fix_coords: a retention of 0 is refused');
SELECT throws_ok($$SELECT private.purge_fix_coords(30, 0)$$, '22023', NULL, 'purge_fix_coords: a limit of 0 is refused');
-- the delegate: bind the owner of ONE queued row, then act as that user
SELECT is(private.bind_delegate_for_queued_evidence('eeee0000-0000-0000-0000-0000000a0e03'), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'delegate: binds the owner of the queued row (returns the uid)');
SELECT throws_ok($$SELECT private.bind_delegate_for_queued_evidence('eeee0000-0000-0000-0000-0000000a0e03')$$, '42501', 'bind_actor: this transaction already has a bound actor', 'delegate: a second bind in the same transaction raises');
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), 'eeee0000-0000-0000-0000-0000000000a0'::uuid, 'delegate: after SET LOCAL ROLE edge_actor the actor is the row owner');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 1, 'delegate: the delegate sees the owner''s rows');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'eeee0000-0000-0000-0000-0000000000b0'), 0, 'delegate: and nobody else''s');
SELECT is((SELECT integrity::text FROM app.evidence WHERE id = 'eeee0000-0000-0000-0000-0000000a0e01'), '{"keep": true, "fixCoords": [1]}', 'purge: the recent row at the open-backlog course KEPT its coordinates');
SELECT is((SELECT integrity::text FROM app.evidence WHERE id = 'eeee0000-0000-0000-0000-0000000a0e02'), '{"other": 2}', 'purge: the aged row lost ONLY fixCoords (every other key kept)');
SELECT is((SELECT queued_input::text FROM app.evidence WHERE id = 'eeee0000-0000-0000-0000-0000000a0e03'), '{"k": "v"}', 'delegate: the queued submission is readable by the delegate acting as its owner');
SELECT throws_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, '42501', 'bind_actor: this transaction already has a bound actor', 'delegate: the delegate-bound transaction cannot be re-pointed at another user');
SELECT throws_ok($$SELECT private.delete_my_data_for_actor()$$, '42501', 'delete_my_data_for_actor: a system delegate may not delete an account', 'delegate: a system delegate cannot delete the account');
SELECT throws_ok($$SELECT private.export_my_data_for_actor()$$, '42501', 'export_my_data_for_actor: a system delegate may not export an account', 'delegate: a system delegate cannot export the account');
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT private.bind_delegate_for_queued_evidence('eeee0000-0000-0000-0000-0000000a0e03')$$, '42501', 'bind_actor: this transaction already has a bound actor', 'delegate: switching back to edge_system does not allow a second bind');
ROLLBACK;

BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT private.bind_delegate_for_queued_evidence('eeee0000-0000-0000-0000-0000000b0e01')$$, 'P0002', 'bind_delegate_for_queued_evidence: no queued_catalog evidence row with that id', 'delegate misuse: an evidence row that is NOT queued_catalog cannot be bound');
SELECT throws_ok($$SELECT private.bind_delegate_for_queued_evidence(gen_random_uuid())$$, 'P0002', 'bind_delegate_for_queued_evidence: no queued_catalog evidence row with that id', 'delegate misuse: an unknown id cannot be bound');
SELECT throws_ok($$SELECT private.bind_delegate_for_rescore(-1, 'eeee0000-0000-0000-0000-0000000a0a01')$$, 'P0002', 'bind_delegate_for_rescore: no open rescore backlog row with that id', 'delegate misuse: an unknown backlog row cannot be bound');
SELECT lives_ok($s$INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) VALUES ('crs_y1', 'split', 1)$s$, 'delegate misuse setup: a backlog row for crs_y1 ...');
SELECT is(pg_temp.rows($s$UPDATE app.catalog_rescore_backlog SET done_at = now() WHERE course_id = 'crs_y1' AND reason = 'split'$s$), 1, 'delegate misuse setup: ... which is then CLOSED (done_at set)');
SELECT throws_ok($$SELECT private.bind_delegate_for_rescore((SELECT id FROM app.catalog_rescore_backlog WHERE course_id = 'crs_y1' AND reason = 'split'), 'eeee0000-0000-0000-0000-0000000b0a02')$$, 'P0002', 'bind_delegate_for_rescore: no open rescore backlog row with that id', 'delegate misuse: a closed backlog row cannot be bound');
SELECT lives_ok($s$INSERT INTO app.catalog_rescore_backlog (course_id, reason, catalog_version) VALUES ('crs_y1', 'promotion', 1)$s$, 'delegate misuse setup: an OPEN backlog row for crs_y1');
SELECT throws_ok($$SELECT private.bind_delegate_for_rescore((SELECT id FROM app.catalog_rescore_backlog WHERE course_id = 'crs_y1' AND reason = 'promotion'), 'eeee0000-0000-0000-0000-0000000a0a02')$$, 'P0002', 'bind_delegate_for_rescore: that play is not at the backlog row''s course', 'delegate misuse: a play at ANOTHER course cannot be bound through this backlog row');
SELECT throws_ok($$SELECT private.bind_delegate_for_rescore((SELECT id FROM app.catalog_rescore_backlog WHERE course_id = 'crs_y1' AND reason = 'promotion'), gen_random_uuid())$$, 'P0002', 'bind_delegate_for_rescore: that play is not at the backlog row''s course', 'delegate misuse: an unknown play cannot be bound');
SELECT is(private.bind_delegate_for_rescore((SELECT id FROM app.catalog_rescore_backlog WHERE course_id = 'crs_y1' AND reason = 'promotion'), 'eeee0000-0000-0000-0000-0000000b0a02'), 'eeee0000-0000-0000-0000-0000000000b0'::uuid, 'delegate: the rescore binder binds the owner of a play at the backlog course (B)');
SET LOCAL ROLE edge_actor;
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id = 'eeee0000-0000-0000-0000-0000000000b0'), 2, 'delegate (rescore): acting as B, B''s plays are visible');
SELECT is((SELECT count(*)::int FROM app.play WHERE user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 0, 'delegate (rescore): and A''s are not');
ROLLBACK;


-- ============================================================================
-- 10. Must-pass: what the Edge code does today still moves rows under edge_actor
-- ============================================================================
-- 10a. The held-review cascade (0017, invoker-rights, NOT redefined) and the P3f reservation trigger.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'cascade: bind A');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0901'), 'issued', 'cascade: before -- the play-backed code is issued');
SELECT is((SELECT budget_reserved::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e101'), 0, 'cascade: before -- nothing is reserved on the offer');
SELECT is(pg_temp.rows($$UPDATE app.play SET held_review = true WHERE id = 'eeee0000-0000-0000-0000-0000000a0a02' AND user_id = '{A}'$$), 1, 'cascade: the actor can put its own play on hold (1 row, not a silent 0)');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0901'), 'held_review', 'cascade: the backing offer code moved to held_review under edge_actor');
SELECT is((SELECT state::text FROM app.entitlement WHERE id = 'eeee0000-0000-0000-0000-0000000a0801'), 'held_review', 'cascade: the backing entitlement moved to held_review under edge_actor');
SELECT is((SELECT reserved_amount::int FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0901'), 10, 'cascade: the P3f trigger reserved the code''s face value');
SELECT is((SELECT budget_reserved::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e101'), 10, 'cascade: the shared offer budget row was updated by the trigger, as edge_actor');
SELECT is((SELECT expiry_paused_at IS NOT NULL FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0901'), true, 'cascade: the expiry clock paused');
SELECT is((SELECT issued_before_hold FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0901'), true, 'cascade: issued_before_hold recorded (the trigger''s own NEW assignments are not privilege-checked)');
SELECT lives_ok($$SET CONSTRAINTS ALL IMMEDIATE$$, 'cascade: the deferred play-guard constraint triggers (private_definer) accept the result');
SELECT is(pg_temp.rows($$UPDATE app.play SET held_review = false WHERE id = 'eeee0000-0000-0000-0000-0000000a0a02' AND user_id = '{A}'$$), 1, 'cascade: lifting the hold is also a counted write');
ROLLBACK;
-- The same hold by B changes nothing of A's.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, 'cascade: bind B');
SELECT is(pg_temp.rows($$UPDATE app.play SET held_review = true WHERE id = 'eeee0000-0000-0000-0000-0000000a0a02'$$), 0, 'cascade: B cannot hold A''s play (0 rows)');
SELECT is(pg_temp.rows($$UPDATE app.play SET held_review = true WHERE id = 'eeee0000-0000-0000-0000-0000000b0a01' AND user_id = '{B}'$$), 1, 'cascade: B holds its own play');
SELECT is((SELECT state::text FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000b0901'), 'held_review', 'cascade: B''s code moved');
SELECT is((SELECT budget_reserved::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e102'), 10, 'cascade: B''s code already held its reservation (idempotent: no double reservation)');
ROLLBACK;

-- 10b. Activation (P3f, invoker-rights, p_user_id is data not authority)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'activation: bind A');
SELECT is((SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000a0903', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'tokhash', 'activate')::text), 'issued', 'activation: an earned code activates under edge_actor');
SELECT is((SELECT reserved_amount::int FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0903'), 10, 'activation: it reserved the offer''s face value');
SELECT is((SELECT budget_reserved::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e103'), 10, 'activation: the offer budget row moved');
SELECT is((SELECT count(*)::int FROM app.device_reward_ledger WHERE reward_id = 'eeee0000-0000-0000-0000-0000000a0903'), 1, 'activation: the ledger row was written');
SELECT is((SELECT app.activate_entitlement('eeee0000-0000-0000-0000-0000000a0801', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'tokhash', 'held_review')::text), 'held_review', 'activation: an entitlement can be held under edge_actor');
SELECT throws_ok($$SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000b0901', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'x', 'activate')$$, 'P0002', NULL, 'activation: must-fail -- A cannot activate B''s code (the row is invisible)');
SELECT throws_ok($$SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000b0901', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', 'x', 'activate')$$, 'P0002', NULL, 'activation: must-fail -- naming B as p_user_id changes nothing');
SELECT throws_ok($$SELECT app.activate_entitlement('eeee0000-0000-0000-0000-0000000b0801', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', 'x', 'activate')$$, 'P0002', NULL, 'activation: must-fail -- A cannot activate B''s entitlement');
SELECT is((SELECT app.release_account_reservations('eeee0000-0000-0000-0000-0000000000b0')::int), 0, 'activation: release_account_reservations(B) as A releases nothing (B''s codes are invisible)');
SELECT is(pg_temp.rows($$INSERT INTO app.review_item (kind, subject_table, subject_id, detail) VALUES ('issued_offer_budget_unreserved', 'offer_code', 'eeee0000-0000-0000-0000-0000000a0903', '{}')$$), 1, 'activation: the "budget could not be reserved" review item can be written for the actor''s own code');
ROLLBACK;

-- 10c. The nonce tombstone (the redefined trigger function) -- including across a COMMIT
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'nonce: bind A');
SELECT lives_ok(format($$INSERT INTO app.checkin_challenge (user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'fac_x', %L, 'live', clock_timestamp(), now() + interval '2 minutes')$$, :'nonce1'), 'nonce: a fresh challenge is accepted and its nonce recorded');
SELECT throws_ok(format($$INSERT INTO app.checkin_challenge (user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'fac_x', %L, 'live', clock_timestamp(), now() + interval '2 minutes')$$, :'nonce1'), '23514', format('checkin_challenge: nonce_hash %s was already consumed (tombstoned) and cannot be reused', :'nonce1'), 'nonce: the same nonce is rejected as already tombstoned');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'nonce: bind A in a later transaction');
SELECT throws_ok(format($$INSERT INTO app.checkin_challenge (user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'fac_x', %L, 'live', clock_timestamp(), now() + interval '2 minutes')$$, :'nonce1'), '23514', NULL, 'nonce: the tombstone survived the COMMIT -- reuse is still rejected');
SELECT throws_ok(format($$SELECT private.record_consumed_nonce(%L, now())$$, :'nonce1'), '23514', NULL, 'nonce: a DIRECT call cannot re-record an existing nonce either (insert-only; the unique violation is the whole check)');
ROLLBACK;

-- 10d. Rate limits: the bucket increments COMMIT, per actor, never raising over the cap
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'rate limit: bind A');
SELECT is(private.hit_actor_rate_limit(:'rlkey', interval '1 hour', 2), 1, 'rate limit: the first hit returns 1');
SELECT is(private.hit_actor_rate_limit(:'rlkey', interval '1 hour', 2), 2, 'rate limit: the second hit returns 2');
SELECT is(private.hit_actor_rate_limit(:'rlkey', interval '1 hour', 2), 3, 'rate limit: the over-cap hit returns 3 and does NOT raise (a raise would roll the increment back)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'rate limit: bind A in a later transaction');
SELECT is(private.hit_actor_rate_limit(:'rlkey', interval '1 hour', 2), 4, 'rate limit: the earlier hits COMMITTED (the next transaction continues from 3)');
SELECT is(private.hit_actor_rate_limit(:'rlkey' || '-other', interval '1 hour', 2), 1, 'rate limit: another key is another bucket');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, 'rate limit: bind B');
SELECT is(private.hit_actor_rate_limit(:'rlkey', interval '1 hour', 2), 1, 'rate limit: B has its OWN bucket for the same key (the uid prefix is added in the database)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('k', interval '1 hour', 2)$$, '42501', 'hit_actor_rate_limit: no actor is bound in this transaction', 'rate limit: unbound raises');
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'rate limit: bind A');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('', interval '1 hour', 2)$$, '22023', NULL, 'rate limit: an empty key raises');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit(repeat('k', 129), interval '1 hour', 2)$$, '22023', NULL, 'rate limit: an overlong key raises');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('k', interval '2 days', 2)$$, '22023', NULL, 'rate limit: a window over a day raises (the nightly purge keeps two days)');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('k', interval '0 seconds', 2)$$, '22023', NULL, 'rate limit: a zero window raises');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('k', interval '1 hour', 0)$$, '22023', NULL, 'rate limit: max 0 raises');
SELECT throws_ok($$SELECT private.hit_actor_rate_limit('k', interval '1 hour', NULL)$$, '22023', NULL, 'rate limit: NULL max raises');
ROLLBACK;

-- 10e. Account deletion and export for the bound actor; the purge keeps the me-delete bucket
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.delete_my_data_for_actor()$$, '42501', 'delete_my_data_for_actor: no actor is bound in this transaction', 'delete: unbound raises');
SELECT throws_ok($$SELECT private.export_my_data_for_actor()$$, '42501', 'export_my_data_for_actor: no actor is bound in this transaction', 'export: unbound raises');
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000b0')$$, 'delete: bind B');
SELECT is(private.hit_actor_rate_limit('evidence:user', interval '1 hour', 100), 1, 'delete: an ordinary B bucket exists (key format <uid>:evidence:user)');
SELECT is(private.hit_actor_rate_limit('me-delete:user', interval '1 hour', 5), 1, 'delete: the me-delete bucket exists');
SELECT is(jsonb_typeof(private.export_my_data_for_actor()), 'object', 'export: returns an object for the bound actor');
SELECT is(position('eeee0000-0000-0000-0000-00000000b001' in private.export_my_data_for_actor()::text) > 0, true, 'export: control -- it contains B''s device id');
SELECT is(position('eeee0000-0000-0000-0000-0000000000a0' in private.export_my_data_for_actor()::text), 0, 'export: contains nothing of A');
SELECT is(position('eeee0000-0000-0000-0000-00000000a001' in private.export_my_data_for_actor()::text), 0, 'export: contains none of A''s rows (A''s device id)');
SELECT is(position('eeee0000-0000-0000-0000-0000000000d0' in private.export_my_data_for_actor()::text), 0, 'export: contains nothing of D');
SELECT is((SELECT budget_reserved::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e102'), 10, 'delete: before -- B''s code holds a reservation on the shared offer');
SELECT is((SELECT app.release_account_reservations('eeee0000-0000-0000-0000-0000000000b0')::int), 10, 'delete: app.release_account_reservations returns what B''s codes reserved');
SELECT is((SELECT budget_reserved::int FROM app.offer WHERE id = 'eeee0000-0000-0000-0000-00000000e102'), 0, 'delete: the shared offer budget row was handed back (invoker-rights function, edge_actor policies)');
SELECT is(private.delete_my_data_for_actor() ->> 'user_id', 'eeee0000-0000-0000-0000-0000000000b0', 'delete: delete_my_data_for_actor deletes the BOUND actor');
SELECT is((SELECT count(*)::int FROM app.device), 0, 'delete: B''s devices are gone');
SELECT is((SELECT count(*)::int FROM app.play), 0, 'delete: B''s plays are gone');
SELECT is((SELECT count(*)::int FROM app.offer_code), 0, 'delete: B''s offer codes are gone');
SELECT is((SELECT state::text FROM app.entitlement WHERE id = 'eeee0000-0000-0000-0000-0000000b0801'), 'void', 'delete: B''s entitlement is voided in place (never deleted outright)');
SELECT is(private.hit_actor_rate_limit('evidence:user', interval '1 hour', 100), 1, 'delete: the ordinary bucket was PURGED with the account data (the key format matches the 0022 purge)');
SELECT is(private.hit_actor_rate_limit('me-delete:user', interval '1 hour', 5), 2, 'delete: the purge KEPT the me-delete:user bucket (a retry stays rate-limited)');
ROLLBACK;

-- 10f. The matcher (PostGIS under edge_actor), the catalog columns, the cross-account device-link signal
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'matcher: bind A');
SELECT is((SELECT ST_DWithin(radius_center::geography, ST_SetSRID(ST_MakePoint(-86.0, 36.0), 4326)::geography, coalesce(radius_m, 0) + 50) FROM app.catalog_course WHERE id = 'crs_edge_geo'), true, 'matcher: ST_DWithin runs as edge_actor -- a fix at the centre is inside');
SELECT is((SELECT ST_DWithin(radius_center::geography, ST_SetSRID(ST_MakePoint(-86.0, 36.5), 4326)::geography, coalesce(radius_m, 0) + 50) FROM app.catalog_course WHERE id = 'crs_edge_geo'), false, 'matcher: a fix 55 km away is outside');
SELECT is((SELECT accounts_on_install FROM private.device_link_signals_for_actor('eeee0000-0000-0000-0000-00000000a001')), 3, 'device link: three accounts on A''s install -- two live devices, plus the tombstone of an account that no longer exists (the larger count wins, as in app.device_link_signals)');
SELECT is((SELECT voided_account_used_install FROM private.device_link_signals_for_actor('eeee0000-0000-0000-0000-00000000a001')), true, 'device link: a fraud-voided account used it');
SELECT is(nullif(current_setting('app.edge.link_hash', true), ''), NULL, 'device link: the scoping GUCs are cleared again afterwards');
SELECT is(nullif(current_setting('app.edge.link_device_id', true), ''), NULL, 'device link: ... all three of them');
SELECT is((SELECT count(DISTINCT user_id)::int FROM app.device WHERE install_link_hash = repeat('e', 64)), 1, 'device link: WHY the definer exists -- a plain edge_actor read of the linked devices sees only its own account (a silent undercount)');
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('e', 64)), 1, 'device link: ... and a plain read of the tombstone sees only the actor''s own row, of the three that exist');
SELECT throws_ok($$SELECT * FROM private.device_link_signals_for_actor('eeee0000-0000-0000-0000-00000000b001')$$, 'P0002', 'device_link_signals_for_actor: that device is not owned by this actor', 'device link: must-fail -- a device that is not the actor''s');
SELECT throws_ok($$SELECT * FROM private.device_link_signals_for_actor('eeee0000-0000-0000-0000-00000000d001')$$, 'P0002', NULL, 'device link: must-fail -- another account''s device on the same install');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT * FROM private.device_link_signals_for_actor('eeee0000-0000-0000-0000-00000000a001')$$, '42501', 'device_link_signals_for_actor: no actor is bound in this transaction', 'device link: unbound raises');
ROLLBACK;

-- 10g. The install-link tombstone (P3f round 3): no user column, so its policies are keyed on the actor's pseudonym
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT is((SELECT count(*)::int FROM app.install_link_account), 0, 'tombstone: unbound sees none (and the query does not raise: the policy is a CASE, because account_pseudonyms(NULL) raises)');
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'tombstone: bind A');
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('e', 64)), 1, 'tombstone: A sees ITS row on the shared install, not the other two');
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('b', 64)), 0, 'tombstone: must-fail -- B''s row on B''s install is invisible to A');
SELECT lives_ok($$SELECT app.record_install_link('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', repeat('e', 64))$$, 'tombstone: app.record_install_link runs under edge_actor (idempotent: A already has its row)');
SELECT is((SELECT count(*)::int FROM app.install_link_account WHERE install_link_hash = repeat('e', 64)), 1, 'tombstone: ... and wrote no second row');
SELECT throws_ok($$SELECT app.record_install_link('eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-00000000b001', repeat('b', 64))$$, '42501', NULL, 'tombstone: must-fail -- A cannot record an install link for B''s device (the device row is invisible, so the function raises instead of writing)');
SELECT throws_ok($$SELECT app.record_install_link('eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000b001', repeat('c', 64))$$, '42501', NULL, 'tombstone: must-fail -- A cannot stamp its own uid on B''s device');
SELECT throws_ok(format($$INSERT INTO app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id)
  SELECT repeat('c', 64), a.pseudonym, a.key_id FROM private.account_pseudonyms(%L) a WHERE a.preferred$$, 'eeee0000-0000-0000-0000-0000000000b0'),
  '42501', 'new row violates row-level security policy for table "install_link_account"', 'tombstone: must-fail -- A cannot insert a row carrying B''s pseudonym');
SELECT lives_ok(format($$INSERT INTO app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id)
  SELECT repeat('c', 64), a.pseudonym, a.key_id FROM private.account_pseudonyms(%L) a WHERE a.preferred$$, 'eeee0000-0000-0000-0000-0000000000a0'),
  'tombstone: control -- A CAN insert a row carrying its own pseudonym (the BEFORE INSERT registrar trigger runs as edge_actor)');
SELECT throws_ok($$UPDATE app.install_link_account SET fraud_voided_at = now()$$, '42501', NULL, 'tombstone: edge_actor cannot mark an account fraud-voided (no UPDATE grant)');
SELECT throws_ok($$DELETE FROM app.install_link_account$$, '42501', NULL, 'tombstone: edge_actor cannot delete tombstone rows');
SELECT throws_ok($$SELECT account_pseudonym_hmac_id FROM app.install_link_account$$, '42501', NULL, 'tombstone: the hmac key id column is not readable');
ROLLBACK;

-- 10h. A clean activation the cap cannot cover is HELD (P3f round 3, N1): reserve_offer_for_code reads review_item
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'held for budget: bind A');
SELECT is((SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000a0904', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'tokhash', 'activate')::text), 'held_review', 'held for budget: a clean activation on an offer whose cap (5) cannot cover the face value (10) is HELD, not issued');
SELECT is((SELECT reserved_amount::int FROM app.offer_code WHERE id = 'eeee0000-0000-0000-0000-0000000a0904'), 0, 'held for budget: it holds no reservation');
SELECT is((SELECT count(*)::int FROM app.review_item WHERE subject_id = 'eeee0000-0000-0000-0000-0000000a0904' AND kind = 'held_offer_budget_unreserved'), 1, 'held for budget: exactly ONE review item names it (the once-per-code check reads review_item as edge_actor)');
SELECT is((SELECT app.activate_offer_code('eeee0000-0000-0000-0000-0000000a0904', 'eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-00000000a001', 'tokhash', 'activate')::text), 'held_review', 'held for budget: a second activation is an idempotent no-op');
SELECT is((SELECT count(*)::int FROM app.review_item WHERE subject_id = 'eeee0000-0000-0000-0000-0000000a0904'), 1, 'held for budget: still one review item');
SELECT is(pg_temp.rows($$SELECT 1 FROM app.review_item WHERE subject_id = 'eeee0000-0000-0000-0000-0000000b0901'$$), 0, 'held for budget: review items of other accounts'' codes are invisible');
SELECT throws_ok($$SELECT detail FROM app.review_item$$, '42501', NULL, 'held for budget: review_item.detail is not readable (column grant)');
ROLLBACK;

-- 10i. The Repo's own statements (supabase/functions/_shared/privileged.ts), shape for shape, as the bound actor.
-- This is the list PR2 will run; every one is asserted by ROW COUNT, so a statement that a missing policy or
-- grant would turn into a silent 0 (or a 42501) is caught here rather than in production.
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('eeee0000-0000-0000-0000-0000000000a0')$$, 'repo: bind A');
-- device
SELECT is(pg_temp.rows($$INSERT INTO app.device (id, user_id, platform) VALUES ('eeee0000-0000-0000-0000-00000000a0f1', '{A}', 'ios') ON CONFLICT (id) DO NOTHING RETURNING id$$), 1, 'repo device.ensureOwn: insert ... ON CONFLICT DO NOTHING RETURNING');
SELECT is(pg_temp.rows($$INSERT INTO app.device (id, user_id, platform) VALUES ('eeee0000-0000-0000-0000-00000000a0f1', '{A}', 'ios') ON CONFLICT (id) DO NOTHING RETURNING id$$), 0, 'repo device.ensureOwn: the same id again is a conflict, 0 rows');
SELECT is(pg_temp.rows($$INSERT INTO app.device (id, user_id, platform) VALUES ('{DB}', '{A}', 'ios') ON CONFLICT (id) DO NOTHING RETURNING id$$), 0, 'repo device.ensureOwn: B''s device id is a conflict too, 0 rows, and nothing leaks (the Repo then finds no own row and raises its 409)');
SELECT is(pg_temp.rows($$SELECT id FROM app.device WHERE id = '{DB}' AND user_id = '{A}'$$), 0, 'repo device.ensureOwn: ... the follow-up own-row select finds nothing');
SELECT is(pg_temp.rows($$UPDATE app.device SET attest_counter = 5, last_seen = now() WHERE id = '{DA}' AND user_id = '{A}' AND attest_counter < 5 RETURNING id$$), 1, 'repo rewards.advanceAttestCounter');
SELECT is(pg_temp.rows($$UPDATE app.device SET devicecheck_token_hash = coalesce('th'::text, devicecheck_token_hash), integrity_last = '{"grade":"unattestable"}'::jsonb, last_seen = now() WHERE id = '{DA}' AND user_id = '{A}'$$), 1, 'repo rewards.recordDeviceVerdict');
SELECT is(pg_temp.rows($$UPDATE app.device SET install_link_hash = coalesce(install_link_hash, repeat('d', 64)::text) WHERE id = '{DA}' AND user_id = '{A}'$$), 1, 'repo rewards.recordInstallLink (the device row side)');
SELECT is(pg_temp.rows($$SELECT id, platform, attest_key_id, attest_counter, attest_public_key FROM app.device WHERE id = '{DA}' AND user_id = '{A}'$$), 1, 'repo rewards.deviceAttestState');
-- evidence
SELECT is(pg_temp.rows($$INSERT INTO app.evidence (user_id, device_id, source, source_ref, input_hash, course_id, facility_id, started_at, ended_at, local_date, summary, integrity, cosignal, attestation_grade, matcher_version, catalog_version, status)
  VALUES ('{A}', '{DA}', 'foreground_checkin', 'repo-ev-1', 'h', 'crs_x1', 'fac_x', now(), now(), current_date, '{}'::jsonb, '{"fixCoords":[1]}'::jsonb, '{}'::jsonb, 'unattestable'::app.attestation_grade, 'm1', 1, 'accepted'::app.evidence_status)
  ON CONFLICT (user_id, source, source_ref) DO NOTHING RETURNING id, status, input_hash$$), 1, 'repo evidence.insertIdempotent (accepted)');
SELECT is(pg_temp.rows($$INSERT INTO app.evidence (user_id, device_id, source, source_ref, input_hash, course_id, facility_id, started_at, ended_at, local_date, summary, integrity, cosignal, attestation_grade, matcher_version, catalog_version, status)
  VALUES ('{A}', '{DA}', 'foreground_checkin', 'repo-ev-1', 'h', 'crs_x1', 'fac_x', now(), now(), current_date, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, 'unattestable'::app.attestation_grade, 'm1', 1, 'accepted'::app.evidence_status)
  ON CONFLICT (user_id, source, source_ref) DO NOTHING RETURNING id, status, input_hash$$), 0, 'repo evidence.insertIdempotent: a replay is 0 rows');
SELECT is(pg_temp.rows($$INSERT INTO app.evidence (user_id, device_id, source, source_ref, input_hash, local_date, status, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input)
  VALUES ('{A}', '{DA}', 'foreground_checkin', 'repo-ev-q', 'h', current_date, 'queued_catalog'::app.evidence_status, 'fac_x', 'crs_x1', '29991231-0000099', '{"k":1}'::jsonb)
  ON CONFLICT (user_id, source, source_ref) DO NOTHING RETURNING id, status, input_hash$$), 1, 'repo evidence.insertIdempotent (queued_catalog)');
SELECT is(pg_temp.rows($$SELECT id, status, input_hash, facility_id, course_id, local_date FROM app.evidence WHERE user_id = '{A}' AND source = 'foreground_checkin'::app.evidence_source AND source_ref = 'repo-ev-1'$$), 1, 'repo evidence.findExisting');
SELECT is(pg_temp.rows($$SELECT count(*) FROM app.evidence WHERE user_id = '{A}' AND status = 'queued_catalog'$$), 1, 'repo evidence.countOpenQueued (the advisory lock is pg_catalog)');
SELECT lives_ok($$SELECT pg_advisory_xact_lock(2, 12345)$$, 'repo: pg_advisory_xact_lock is callable');
SELECT is(pg_temp.rows($$SELECT id, source, facility_id, course_id, local_date, summary, integrity, cosignal, attestation_grade FROM app.evidence WHERE user_id = '{A}' AND facility_id = 'fac_x' AND (course_id = 'crs_x1' OR course_id IS NULL) AND local_date = current_date AND status = 'accepted' ORDER BY created_at ASC LIMIT 10000$$), 1, 'repo evidence.listForPlay');
SELECT is(pg_temp.rows($$UPDATE app.evidence SET status = 'accepted', facility_id = 'fac_x', course_id = 'crs_x1', summary = '{}'::jsonb, integrity = '{}'::jsonb, attestation_grade = 'unattestable'::app.attestation_grade, catalog_version = 1, claimed_facility_id = NULL, claimed_course_id = NULL, claimed_catalog_version = NULL, queued_input = NULL WHERE id = 'eeee0000-0000-0000-0000-0000000a0e03' AND user_id = '{A}' AND status = 'queued_catalog'$$), 1, 'repo evidence.resolveQueuedRow');
SELECT is(pg_temp.rows($$UPDATE app.evidence e SET summary = (SELECT coalesce(jsonb_object_agg(t.k, CASE WHEN t.k IN ('fix', 'checkinFix', 'checkoutFix') AND jsonb_typeof(t.v) = 'object' THEN jsonb_set(t.v, '{verificationTier}', to_jsonb(c.verification_status::text)) ELSE t.v END), '{}'::jsonb) FROM jsonb_each(e.summary) AS t(k, v))
  FROM app.catalog_course c WHERE c.id = e.course_id AND e.user_id = '{A}' AND e.course_id = 'crs_x1' AND e.local_date = current_date AND e.status = 'accepted' RETURNING e.id$$), 2, 'repo evidence.refreshFixTiers (UPDATE ... FROM catalog_course ... RETURNING)');
SELECT is(pg_temp.rows($$SELECT device_id FROM app.evidence WHERE id = 'eeee0000-0000-0000-0000-0000000a0e01' AND user_id = '{A}'$$), 1, 'repo evidence.deviceIdFor');
SELECT is(pg_temp.rows($$UPDATE app.evidence SET summary = '{}'::jsonb WHERE id = 'eeee0000-0000-0000-0000-0000000a0e01' AND user_id = '{A}'$$), 1, 'repo repickApply: evidence summary');
SELECT is(pg_temp.rows($$UPDATE app.evidence SET integrity = integrity - 'fixCoords' WHERE user_id = '{A}' AND course_id = 'crs_y1' AND local_date = current_date AND facility_id = 'fac_y' AND integrity ? 'fixCoords'$$), 2, 'repo repickApply: clear the stored fix coordinates (both of the actor''s rows at that course and date)');
-- play
SELECT is(pg_temp.rows($$INSERT INTO app.play (user_id, course_id, facility_id, play_date, course_disambiguated_by, score_badge, score_monetary, hard_signal, presence_signal, money, held_review, policy_version, input_digest, status)
  VALUES ('{A}', 'crs_x1', 'fac_x', current_date - 3, NULL, 0.7, 0.7, false, false, false, false, 'v2', 'd1', (CASE WHEN 0.7 >= 0.50 THEN 'confirmed' ELSE 'provisional' END)::app.play_status)
  ON CONFLICT (user_id, course_id, play_date) DO UPDATE SET score_badge = excluded.score_badge, score_monetary = excluded.score_monetary, hard_signal = excluded.hard_signal, presence_signal = excluded.presence_signal, money = excluded.money, held_review = excluded.held_review, policy_version = excluded.policy_version, input_digest = excluded.input_digest,
    status = (CASE WHEN app.play.status = 'disputed' THEN app.play.status::text WHEN excluded.score_badge >= 0.50 THEN 'confirmed' ELSE 'provisional' END)::app.play_status
  RETURNING id, (xmax = 0) AS inserted$$), 1, 'repo play.upsertFromScore: the ON CONFLICT DO UPDATE path (an existing play)');
SELECT is(pg_temp.rows($$INSERT INTO app.play (user_id, course_id, facility_id, play_date, course_disambiguated_by, score_badge, score_monetary, hard_signal, presence_signal, money, held_review, policy_version, input_digest, status)
  VALUES ('{A}', 'crs_x1', 'fac_x', current_date - 9, NULL, 0.7, 0.7, false, false, false, false, 'v2', 'd1', 'confirmed'::app.play_status)
  ON CONFLICT (user_id, course_id, play_date) DO UPDATE SET score_badge = excluded.score_badge RETURNING id, (xmax = 0) AS inserted$$), 1, 'repo play.upsertFromScore: the insert path');
SELECT is(pg_temp.rows($$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES ('eeee0000-0000-0000-0000-0000000a0a01', 'eeee0000-0000-0000-0000-0000000a0e02', '{A}') ON CONFLICT (evidence_id) DO NOTHING$$), 1, 'repo play.upsertFromScore: link evidence');
SELECT is(pg_temp.rows($$INSERT INTO app.play_evidence (play_id, evidence_id, user_id) VALUES ('eeee0000-0000-0000-0000-0000000a0a01', 'eeee0000-0000-0000-0000-0000000a0e02', '{A}') ON CONFLICT (evidence_id) DO NOTHING$$), 0, 'repo play.upsertFromScore: re-link is a clean 0 rows');
SELECT is(pg_temp.rows($$SELECT id, score_badge, score_monetary, presence_signal, money, held_review FROM app.play WHERE user_id = '{A}' AND course_id = 'crs_x1' AND play_date = current_date - 3$$), 1, 'repo play.getForDate');
SELECT is(pg_temp.rows($$UPDATE app.play p SET course_disambiguated_by = 'user' WHERE p.id = 'eeee0000-0000-0000-0000-0000000a0a01' AND p.user_id = '{A}' AND p.course_disambiguated_by IS NULL AND NOT EXISTS (SELECT 1 FROM app.play o WHERE o.user_id = p.user_id AND o.facility_id = p.facility_id AND o.play_date = p.play_date AND o.course_disambiguated_by = 'user' AND o.id <> p.id) RETURNING p.id$$), 1, 'repo play.markUserPick');
SELECT is(pg_temp.rows($$UPDATE app.play SET course_id = 'crs_y1', course_disambiguated_by = 'user' WHERE id = 'eeee0000-0000-0000-0000-0000000a0a01' AND user_id = '{A}'$$), 1, 'repo play.repickApply: the course move');
SELECT is(pg_temp.rows($$INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail) VALUES ('{A}', 'play.repick', 'play', 'eeee0000-0000-0000-0000-0000000a0a01', '{"x":1}'::jsonb)$$), 1, 'repo play.repickApply: the audit row');
SELECT is(pg_temp.rows($$SELECT 1 FROM app.audit_log WHERE actor_user_id = '{A}' AND action = 'play.repick' AND subject_table = 'play' AND subject_id = 'eeee0000-0000-0000-0000-0000000a0a01' LIMIT 1$$), 1, 'repo play.repickPrepare: the "already re-picked" check reads the actor''s own audit row');
SELECT is((SELECT count(*)::int FROM app.play p JOIN app.catalog_id_ledger l ON l.id = p.course_id AND l.status = 'verified' WHERE p.user_id = 'eeee0000-0000-0000-0000-0000000000a0' AND p.status NOT IN ('void', 'disputed') AND (p.score_badge >= 0.50 OR p.money)), 3, 'repo play.uniqueCourseCount: the join with the id ledger works under edge_actor');
-- fraud signals
SELECT is(pg_temp.rows($$INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES ('{A}', 'clock_skew', '{"fixIds":["x"]}'::jsonb)$$), 1, 'repo fraudSignal.insert (plain)');
SELECT is(pg_temp.rows($$INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES ('{A}', 'quarantined_evidence_row', '{"playId":"p1","quarantineDigest":"dd"}'::jsonb) ON CONFLICT ((detail ->> 'playId'), (detail ->> 'quarantineDigest')) WHERE kind = 'quarantined_evidence_row' DO NOTHING$$), 1, 'repo fraudSignal.insert (quarantine, ON CONFLICT on the partial expression index)');
SELECT is(pg_temp.rows($$INSERT INTO app.fraud_signal (user_id, kind, detail) VALUES ('{A}', 'quarantined_evidence_row', '{"playId":"p1","quarantineDigest":"dd"}'::jsonb) ON CONFLICT ((detail ->> 'playId'), (detail ->> 'quarantineDigest')) WHERE kind = 'quarantined_evidence_row' DO NOTHING$$), 0, 'repo fraudSignal.insert (quarantine): the same set again is 0 rows');
SELECT is(pg_temp.rows($$INSERT INTO app.fraud_signal (user_id, kind, detail) SELECT '{A}'::uuid, 'attestation_failed', '{}'::jsonb WHERE NOT EXISTS (SELECT 1 FROM app.fraud_signal WHERE user_id = '{A}' AND kind = 'attestation_failed' AND cleared_at IS NULL) RETURNING id$$), 1, 'repo rewards.raiseAttestationFailedIfNone');
SELECT is(pg_temp.rows($$INSERT INTO app.fraud_signal (user_id, kind, detail) SELECT '{A}'::uuid, 'attestation_failed', '{}'::jsonb WHERE NOT EXISTS (SELECT 1 FROM app.fraud_signal WHERE user_id = '{A}' AND kind = 'attestation_failed' AND cleared_at IS NULL) RETURNING id$$), 0, 'repo rewards.raiseAttestationFailedIfNone: the second is 0 rows (the NOT EXISTS read sees the first)');
SELECT is(pg_temp.rows($$SELECT 1 WHERE EXISTS (SELECT 1 FROM app.fraud_signal WHERE user_id = '{A}' AND kind = 'attestation_failed' AND cleared_at IS NULL AND created_at > coalesce(NULL::timestamptz, '-infinity'::timestamptz))$$), 1, 'repo rewards.hasOpenAttestationFailedSignal');
SELECT is(pg_temp.rows($$INSERT INTO app.fraud_signal (user_id, kind, detail) SELECT '{A}'::uuid, 'multi_account_device'::text, '{"onceKey":"k1"}'::jsonb WHERE NOT EXISTS (SELECT 1 FROM app.fraud_signal WHERE user_id = '{A}' AND kind = 'multi_account_device' AND cleared_at IS NULL AND detail ->> 'onceKey' = 'k1') RETURNING id$$), 1, 'repo rewards.raiseFraudSignalOnce');
-- challenge / token
SELECT is(pg_temp.rows($$INSERT INTO app.checkin_challenge (user_id, staff_user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('{A}', null, '{DA}', 'fac_x', 'repo-nonce-' || gen_random_uuid(), 'live', clock_timestamp(), now() + interval '2 minutes') RETURNING id, expires_at$$), 1, 'repo challenge.insert (with RETURNING)');
SELECT is(pg_temp.rows($$SELECT count(*)::int FROM app.checkin_challenge WHERE device_id = '{DA}' AND user_id = '{A}' AND used_at IS NULL AND expires_at > now()$$), 1, 'repo challenge.countOpenPrefetched');
SELECT is(pg_temp.rows($$SELECT id, device_id, facility_id, nonce_hash, kind, expires_at, used_at FROM app.checkin_challenge WHERE id = 'eeee0000-0000-0000-0000-0000000a0c01' AND user_id = '{A}'$$), 1, 'repo challenge.getOwn');
SELECT is(pg_temp.rows($$UPDATE app.checkin_challenge SET used_at = now() WHERE id = 'eeee0000-0000-0000-0000-0000000a0c01' AND user_id = '{A}' AND nonce_hash = (SELECT nonce_hash FROM app.checkin_challenge WHERE id = 'eeee0000-0000-0000-0000-0000000a0c01') AND used_at IS NULL RETURNING id$$), 1, 'repo challenge.consume');
SELECT is(pg_temp.rows($$UPDATE app.checkin_challenge SET used_at = now() WHERE id = 'eeee0000-0000-0000-0000-0000000a0c01' AND user_id = '{A}' AND used_at IS NULL RETURNING id$$), 0, 'repo challenge.consume: a second consume is 0 rows');
SELECT is(pg_temp.rows($$WITH c AS (INSERT INTO app.checkin_challenge (user_id, staff_user_id, device_id, facility_id, nonce_hash, kind, issued_at, expires_at) VALUES ('{A}', null, '{DA}', 'fac_x', 'repo-nonce-' || gen_random_uuid(), 'live', clock_timestamp(), now() + interval '2 minutes') RETURNING id)
  INSERT INTO app.checkin_token (challenge_id, user_id, device_id, facility_id, attestation_grade, challenge_kind, issued_at, expires_at) SELECT id, '{A}', '{DA}', 'fac_x', 'unattestable'::app.attestation_grade, 'live', clock_timestamp(), now() + interval '10 minutes' FROM c RETURNING jti, expires_at$$), 1, 'repo checkinToken.insert (with RETURNING)');
SELECT is(pg_temp.rows($$UPDATE app.checkin_token SET consumed_at = now() FROM app.checkin_challenge cc WHERE checkin_token.challenge_id = cc.id AND checkin_token.jti = 'eeee0000-0000-0000-0000-0000000a0d01' AND checkin_token.user_id = '{A}' AND checkin_token.device_id = '{DA}' AND checkin_token.consumed_at IS NULL AND checkin_token.expires_at > now() AND cc.issued_at <= now() AND now() <= cc.expires_at RETURNING checkin_token.facility_id, checkin_token.attestation_grade, checkin_token.challenge_kind$$), 1, 'repo checkinToken.consumeForFix (UPDATE ... FROM challenge ... RETURNING)');
-- push token, me
SELECT is(pg_temp.rows($$INSERT INTO app.push_token (user_id, device_id, expo_token, updated_at) VALUES ('{A}', '{DA}', 'ExpoX', now()) ON CONFLICT (user_id, device_id) DO UPDATE SET expo_token = excluded.expo_token, updated_at = excluded.updated_at RETURNING device_id, updated_at$$), 1, 'repo pushToken.upsert');
SELECT is(pg_temp.rows($$SELECT count(*)::int FROM app.push_token WHERE user_id = '{A}'$$), 1, 'repo pushToken.countForUser');
SELECT is(pg_temp.rows($$SELECT DISTINCT provider FROM app.signin_provider_token WHERE user_id = '{A}'$$), 1, 'repo me.listSigninProviders');
SELECT is(pg_temp.rows($$SELECT DISTINCT provider FROM app.connector_account WHERE user_id = '{A}'$$), 1, 'repo me.listConnectorProviders');
SELECT is(pg_temp.rows($$SELECT count(*)::int FROM app.device WHERE user_id = '{A}'$$), 1, 'repo device.countForUser');
-- rewards
SELECT is(pg_temp.rows($$SELECT oc.id, oc.state, oc.activated_device_id, oc.expires_at, oc.expiry_paused_at, oc.rests_on_unattestable, oc.review_cleared_at::text AS review_cleared_at, coalesce(p.held_review, false) AS play_held
  FROM app.offer_code oc LEFT JOIN app.play p ON p.id = oc.play_id AND p.user_id = oc.user_id WHERE oc.id = 'eeee0000-0000-0000-0000-0000000a0901' AND oc.user_id = '{A}' FOR UPDATE OF oc$$), 1, 'repo rewards.lockOwnReward (offer code: join + FOR UPDATE OF)');
SELECT is(pg_temp.rows($$SELECT e.id, e.state, e.activated_device_id, e.rests_on_unattestable, e.review_cleared_at::text AS review_cleared_at, coalesce(p.held_review, false) AS play_held
  FROM app.entitlement e LEFT JOIN app.play p ON p.id = e.play_id AND p.user_id = e.user_id WHERE e.id = 'eeee0000-0000-0000-0000-0000000a0801' AND e.user_id = '{A}' FOR UPDATE OF e$$), 1, 'repo rewards.lockOwnReward (entitlement)');
SELECT is(pg_temp.rows($$SELECT (EXISTS (SELECT 1 FROM app.device_reward_ledger WHERE user_id = '{A}') OR EXISTS (SELECT 1 FROM app.offer_code WHERE user_id = '{A}' AND state IN ('issued', 'redeemed') AND activated_device_id IS NOT NULL) OR EXISTS (SELECT 1 FROM app.entitlement WHERE user_id = '{A}' AND state IN ('redeemable', 'vouchered', 'redeemed') AND activated_device_id IS NOT NULL)) AS prior$$), 1, 'repo rewards.hasPriorReward');
SELECT is(pg_temp.rows($$SELECT EXISTS (SELECT 1 FROM app.app_review_demo_account WHERE user_id = '{A}') AS demo$$), 1, 'repo rewards.isAppReviewDemoAccount');
SELECT is((SELECT s.accounts_on_install FROM app.device d CROSS JOIN LATERAL private.device_link_signals_for_actor(d.id) s WHERE d.id = 'eeee0000-0000-0000-0000-00000000a001' AND d.user_id = 'eeee0000-0000-0000-0000-0000000000a0'), 3, 'repo rewards.androidInstallSignals: the LATERAL join over the actor''s own device (PR2 swaps the function name)');
-- catalog reads
SELECT is(pg_temp.rows($$SELECT version, site_version, contract_version, sha256, kid, published_at FROM app.catalog_version ORDER BY site_version DESC NULLS LAST, version DESC LIMIT 1$$), 1, 'repo catalog.currentVersion');
SELECT is(pg_temp.rows($$SELECT count(*)::int AS n FROM app.catalog_version WHERE site_version IS NOT NULL AND site_version <= '29991231-0000099'$$), 1, 'repo catalog.releaseRank');
SELECT is(pg_temp.rows($$SELECT id, kind, status, verified_in_version, split_from, tombstoned_at, merged_into, first_catalog_version FROM app.catalog_id_ledger WHERE id = 'crs_x1'$$), 1, 'repo catalog.resolveLedgerId');
SELECT is(pg_temp.rows($$SELECT tz FROM app.catalog_facility WHERE id = 'fac_x'$$), 1, 'repo catalog.facilityTz');
SELECT is(pg_temp.rows($$SELECT facility_id FROM app.catalog_course WHERE id = 'crs_x1'$$), 1, 'repo catalog.courseFacilityId');
SELECT is(pg_temp.rows($$SELECT coalesce(nullif((SELECT count(*) FROM app.catalog_hole WHERE course_id = 'crs_x1'), 0), (SELECT holes FROM app.catalog_course WHERE id = 'crs_x1'), 0)::int AS n$$), 1, 'repo catalog.courseHoleCount');
SELECT is(pg_temp.rows($$SELECT k.kid, k.public_key_b64url, coalesce(k.revoked_at, (SELECT r.recorded_at FROM app.catalog_kid_revocation r WHERE r.kid = k.kid)) AS revoked_at FROM app.catalog_signing_key k WHERE k.kid = 'kid1'$$), 0, 'repo catalog.signingKey (the key table is empty in the harness; the statement runs)');
SELECT is(pg_temp.rows($$SELECT EXISTS (SELECT 1 FROM app.catalog_id_ledger l WHERE l.id = 'crs_x1' AND (l.status = 'stub' OR l.split_from IS NOT NULL OR EXISTS (SELECT 1 FROM app.catalog_id_ledger s WHERE s.split_from = l.id) OR EXISTS (SELECT 1 FROM app.catalog_rescore_backlog b WHERE b.course_id = l.id AND b.done_at IS NULL))) AS e$$), 1, 'repo catalog.repickEligible');
SELECT is((SELECT ST_DWithin(radius_center::geography, ST_SetSRID(ST_MakePoint(-86.0, 36.0), 4326)::geography, coalesce(radius_m, 0) + 50) FROM app.catalog_course WHERE id = 'crs_edge_geo'), true, 'repo catalog.matchFix: the radius branch');
ROLLBACK;

-- No finish(): it counts the rows pgTAP keeps in a temp table, which every ROLLBACK above discards, so it would
-- report a false "planned N but ran M". pg_prove checks the plan against the TAP lines actually printed.

-- ============================================================================
-- PHASE 2: cleanup (harness role, as service_role)
-- ============================================================================
\c :"harness_db" :"harness_user"
SET ROLE service_role;
BEGIN;
SELECT app.release_account_reservations(u) FROM unnest(ARRAY['eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-0000000000d0']::uuid[]) AS u;
SELECT private.delete_my_data(u) FROM unnest(ARRAY['eeee0000-0000-0000-0000-0000000000a0', 'eeee0000-0000-0000-0000-0000000000b0', 'eeee0000-0000-0000-0000-0000000000d0']::uuid[]) AS u;
DELETE FROM app.catalog_course WHERE id = 'crs_edge_geo';
DELETE FROM app.catalog_id_ledger WHERE id = 'crs_edge_geo';
DELETE FROM app.offer WHERE id IN ('eeee0000-0000-0000-0000-00000000e101', 'eeee0000-0000-0000-0000-00000000e102', 'eeee0000-0000-0000-0000-00000000e103', 'eeee0000-0000-0000-0000-00000000e104');
DELETE FROM private.rate_limit_bucket WHERE bucket_key LIKE 'eeee0000-%' OR bucket_key LIKE 'system:edge-%';
COMMIT;
RESET ROLE;

-- What delete_my_data retains by design (voided entitlements, pseudonymous install-link tombstones) has no DELETE grant
-- for any runtime role, but the harness role OWNS those tables, so a test fixture can remove its own residue with the
-- same temporary CURRENT_USER policy the migrations use (the tables are FORCE RLS: an owner needs a policy too).
-- Without this the file would collide with itself on a second run against the same cluster.
BEGIN;
CREATE POLICY edge16_cleanup_entitlement ON app.entitlement FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY edge16_cleanup_install_link ON app.install_link_account FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
DELETE FROM app.entitlement WHERE id::text LIKE 'eeee0000-%';
DELETE FROM app.install_link_account WHERE install_link_hash IN (repeat('e', 64), repeat('b', 64), repeat('c', 64));
DROP POLICY edge16_cleanup_entitlement ON app.entitlement;
DROP POLICY edge16_cleanup_install_link ON app.install_link_account;
COMMIT;

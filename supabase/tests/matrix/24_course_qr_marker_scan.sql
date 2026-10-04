-- 24_course_qr_marker_scan.sql
-- 0046_course_qr_marker_scan.sql, the structural invariants and the PIN derivation: the course QR's PUBLIC keys and the failure-alarm table are definer-only,
-- the daily PIN is DERIVED (HMAC-SHA256 under a Vault pepper) and the pepper is readable by NOBODY but the one derivation function, the tables a scan writes are
-- written only through the definers, and the registries (function inventory, definer policy allow-list) describe what the migration built. The edge_actor lane (the scan,
-- the PIN counters, the co-signal intake, AT(3) / AT(4) / AT(13) / AT(19)) is 24_course_qr_marker_scan_edge.sql: it has to reconnect as a real edge_gateway login.
--
-- THE TEST VECTORS below were computed OUTSIDE the database (Python hmac / hashlib, never this function) from a pepper this file BUILDS AT RUN TIME as repeat('p', 40)
-- (no secret literal lives in this file or in the repository) and the message
--   b'golfraven/course-pin/v1' + b'\x00' + facility_id.encode() + b'\x00' + 'YYYY-MM-DD'.encode() + b'\x00' + struct.pack('>I', pin_epoch)
-- reduced as int.from_bytes(mac[:4], 'big') % 10000, zero padded to 4 digits, so a change to the derivation (the label, the field order, the separators, the encoding,
-- the reduction, the key, the hash) fails here, not in production. supabase/tests/unit/course-qr-pin-vector.test.ts pins the same vectors from the TypeScript side.

SELECT plan(71);

-- ----------------------------------------------------------------------------
-- 0. Structure: the two new tables
-- ----------------------------------------------------------------------------
SELECT has_table('app', 'course_qr_key', 'app.course_qr_key exists');
SELECT columns_are('app', 'course_qr_key', ARRAY['purpose', 'kid', 'public_key_b64url', 'created_at', 'revoked_at'], 'the key table holds public keys only: no private key, no secret column');
SELECT col_is_pk('app', 'course_qr_key', ARRAY['purpose', 'kid'], 'a kid is unique per purpose');
SELECT has_table('app', 'course_pin_alarm', 'app.course_pin_alarm exists');
SELECT columns_are('app', 'course_pin_alarm', ARRAY['id', 'facility_id', 'local_date', 'pin_epoch_before', 'pin_epoch_after', 'failures', 'raised_at'],
  'the alarm table holds NO user id and NO PIN (so it is not a personal table)');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'app.course_pin_alarm'::regclass AND k.contype = 'u'), 1, 'one alarm per (facility, local date, epoch): a unique constraint');
SELECT is((SELECT bool_and(c.relrowsecurity AND c.relforcerowsecurity) FROM pg_class c WHERE c.oid IN ('app.course_qr_key'::regclass, 'app.course_pin_alarm'::regclass)), true, 'both new tables have RLS enabled AND forced');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n), (VALUES ('app.course_qr_key'), ('app.course_pin_alarm')) t(n)
           WHERE has_any_column_privilege(r.n, t.n, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, t.n, 'DELETE,TRUNCATE,TRIGGER')), 0,
  'no client role and no edge role holds ANY privilege on either (every path is a definer)');
SELECT is((SELECT bool_and(c.relacl::text !~ '(^\{|,)=') FROM pg_class c WHERE c.oid IN ('app.course_qr_key'::regclass, 'app.course_pin_alarm'::regclass)), true, 'PUBLIC holds nothing on either');
SELECT is((has_table_privilege('service_role', 'app.course_qr_key', 'SELECT') AND has_table_privilege('service_role', 'app.course_pin_alarm', 'SELECT')), true, 'service_role may READ both (diagnostics) ...');
SELECT is((has_table_privilege('service_role', 'app.course_qr_key', 'INSERT,UPDATE,DELETE') OR has_table_privilege('service_role', 'app.course_pin_alarm', 'INSERT,UPDATE,DELETE')), false, '... and may not write them');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid IN ('app.course_qr_key'::regclass, 'app.course_pin_alarm'::regclass) AND p.polroles <> ARRAY['private_definer'::regrole::oid]), 0,
  'the new tables have policies for private_definer ONLY (no client or edge role has one)');
-- the key table's CHECKs (seeded the way 0035 / 0039 / 0045 seed a FORCE-RLS table with no policy for the harness role: a temporary CURRENT_USER policy, rolled back)
BEGIN;
CREATE POLICY current_user_seed_course_qr_key_24 ON app.course_qr_key FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
SELECT throws_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('rotating_token', 'k-bad', 'tooshort')$$, '23514', NULL, 'a public key must be exactly 43 base64url characters (32 raw bytes)');
SELECT throws_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('hand_over', 'k1', repeat('A', 43))$$, '23514', NULL, 'the purpose is closed: rotating_token | printed_qr');
SELECT throws_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'bad kid!', repeat('A', 43))$$, '23514', NULL, 'a kid is a short id (no spaces or punctuation)');
SELECT lives_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'pq1', repeat('A', 43))$$, 'control: a well-formed key is accepted');
SELECT throws_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('printed_qr', 'pq1', repeat('B', 43))$$, '23505', NULL, 'a kid is unique per purpose');
SELECT lives_ok($$INSERT INTO app.course_qr_key (purpose, kid, public_key_b64url) VALUES ('rotating_token', 'pq1', repeat('B', 43))$$, 'while the same kid string may exist for the other purpose (the namespaces are separate)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 1. What the definers may do on the tables they do not own: column-narrow, and nothing for any edge or client role
-- ----------------------------------------------------------------------------
SELECT is(has_column_privilege('private_definer', 'app.facility_programme', 'pin_epoch', 'UPDATE') AND NOT has_column_privilege('private_definer', 'app.facility_programme', 'participation', 'UPDATE')
          AND NOT has_column_privilege('private_definer', 'app.facility_programme', 'qr_mode', 'UPDATE'), true, 'private_definer may UPDATE facility_programme.pin_epoch and no other column');
SELECT is(has_column_privilege('private_definer', 'app.catalog_facility', 'tz', 'SELECT') AND has_column_privilege('private_definer', 'app.catalog_facility', 'id', 'SELECT')
          AND NOT has_column_privilege('private_definer', 'app.catalog_facility', 'name', 'SELECT'), true, 'private_definer may read catalog_facility (id, tz) and nothing else of it');
SELECT is(has_column_privilege('private_definer', 'app.trail_programme', 'status', 'SELECT') AND has_column_privilege('private_definer', 'app.trail_programme', 'marker_source', 'SELECT')
          AND NOT has_column_privilege('private_definer', 'app.trail_programme', 'fee_amount', 'SELECT'), true, 'private_definer may read trail_programme (trail_id, status, marker_source) and not its fees');
SELECT is(has_column_privilege('private_definer', 'app.course_qr_token', 'used_at', 'UPDATE') AND has_column_privilege('private_definer', 'app.course_qr_token', 'used_by_user', 'UPDATE')
          AND NOT has_column_privilege('private_definer', 'app.course_qr_token', 'nonce_hash', 'UPDATE') AND NOT has_column_privilege('private_definer', 'app.course_qr_token', 'issued_at', 'UPDATE')
          AND NOT has_column_privilege('private_definer', 'app.course_qr_token', 'facility_id', 'UPDATE') AND NOT has_table_privilege('private_definer', 'app.course_qr_token', 'INSERT'), true,
  'private_definer may only mark a token used: UPDATE(used_by_user, used_at); it cannot issue (INSERT) or edit one (S2b issues)');
SELECT is(has_column_privilege('private_definer', 'app.purchase_evidence', 'status', 'UPDATE') AND has_column_privilege('private_definer', 'app.purchase_evidence', 'cosignal', 'UPDATE')
          AND NOT has_column_privilege('private_definer', 'app.purchase_evidence', 'user_id', 'UPDATE') AND NOT has_column_privilege('private_definer', 'app.purchase_evidence', 'facility_id', 'UPDATE')
          AND NOT has_column_privilege('private_definer', 'app.purchase_evidence', 'local_date', 'UPDATE') AND NOT has_column_privilege('private_definer', 'app.purchase_evidence', 'method', 'UPDATE'), true,
  'private_definer may UPDATE purchase_evidence (status, cosignal) only');
SELECT is(has_column_privilege('private_definer', 'app.marker_credit', 'status', 'UPDATE') AND NOT has_column_privilege('private_definer', 'app.marker_credit', 'user_id', 'UPDATE')
          AND NOT has_column_privilege('private_definer', 'app.marker_credit', 'purchase_evidence_id', 'UPDATE'), true, 'private_definer may UPDATE marker_credit.status only');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_table_privilege(r.n, 'app.purchase_evidence', 'INSERT,UPDATE,DELETE') OR has_table_privilege(r.n, 'app.marker_credit', 'INSERT,UPDATE,DELETE')
              OR has_any_column_privilege(r.n, 'app.purchase_evidence', 'INSERT,UPDATE') OR has_any_column_privilege(r.n, 'app.marker_credit', 'INSERT,UPDATE')
              OR has_any_column_privilege(r.n, 'app.course_qr_token', 'INSERT,UPDATE') OR has_any_column_privilege(r.n, 'app.facility_qr', 'INSERT,UPDATE')
              OR has_column_privilege(r.n, 'app.facility_programme', 'pin_epoch', 'UPDATE')), 0,
  'no client role and no edge role can write what a scan writes (purchase_evidence, marker_credit, course_qr_token, facility_qr, the PIN epoch): every write is a definer');
SELECT is((SELECT count(*)::int FROM pg_class c WHERE c.oid IN ('app.purchase_evidence'::regclass, 'app.marker_credit'::regclass, 'app.course_qr_token'::regclass, 'app.facility_qr'::regclass,
           'app.facility_programme'::regclass, 'app.trail_programme'::regclass, 'app.catalog_facility'::regclass) AND NOT (c.relrowsecurity AND c.relforcerowsecurity)), 0,
  'FORCE ROW LEVEL SECURITY is intact on every existing table the scan touches');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%' AND p.polroles = ARRAY['private_definer'::regrole::oid]), 15, 'the migration added exactly 15 policies, every one for private_definer only');
SELECT is((SELECT array_agg(p.polname || ' ' || coalesce(pg_get_expr(p.polqual, p.polrelid), '-') || ' / ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '-') ORDER BY p.polname) FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%'), ARRAY[
  'pd_marker_scan_alarm_insert - / (private.actor_uid() IS NOT NULL)',
  'pd_marker_scan_alarm_select (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_credit_insert - / (user_id = private.actor_uid())',
  'pd_marker_scan_credit_select (user_id = private.actor_uid()) / -',
  'pd_marker_scan_credit_update (user_id = private.actor_uid()) / (user_id = private.actor_uid())',
  'pd_marker_scan_facility_programme_epoch (private.actor_uid() IS NOT NULL) / (private.actor_uid() IS NOT NULL)',
  'pd_marker_scan_facility_qr_read (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_facility_read (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_key_read (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_purchase_insert - / (user_id = private.actor_uid())',
  'pd_marker_scan_purchase_select (user_id = private.actor_uid()) / -',
  'pd_marker_scan_purchase_update (user_id = private.actor_uid()) / (user_id = private.actor_uid())',
  'pd_marker_scan_token_select (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_token_update (private.actor_uid() IS NOT NULL) / ((used_by_user = private.actor_uid()) AND (used_at IS NOT NULL))',
  'pd_marker_scan_trail_programme_read (private.actor_uid() IS NOT NULL) / -'
],
  'the 15 policies, expression for expression (a broadened USING or WITH CHECK fails here: the token UPDATE may only mark a token used BY THE BOUND ACTOR, the purchase and credit writes are the bound actor''s own rows)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%'
             AND (coalesce(pg_get_expr(p.polqual, p.polrelid), '') || ' ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')) ~* 'current_setting|set_config'), 0,
  'HARD RULE: not one of them is keyed on a settable GUC (each is keyed on the actor BINDING, private.actor_uid())');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%'
             AND (coalesce(pg_get_expr(p.polqual, p.polrelid), '') || ' ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')) NOT LIKE '%private.actor_uid()%'), 0, 'every one of them names private.actor_uid()');

-- ----------------------------------------------------------------------------
-- 2. The pepper: readable by nobody but the one derivation function; the function posture
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_pepper'), 1, 'the pepper: exactly ONE function in the database names it');
SELECT is((SELECT p.proname FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_pepper'), 'course_pin_derive', 'the pepper: and it is private.course_pin_derive');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.course_pin_derive(text, date, integer)', 'EXECUTE')), 0, 'the pepper: no role at all may EXECUTE the derivation core');
SELECT is((SELECT p.proacl::text !~ '(^\{|,)=' FROM pg_proc p WHERE p.oid = 'private.course_pin_derive(text, date, integer)'::regprocedure), true, 'the pepper: PUBLIC has no EXECUTE on the derivation core');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_derive' AND p.proname <> 'course_pin_derive'), 2,
  'the derivation core is called by exactly two functions: the PIN gate (course_pin_attempt_for_actor) and the scan (marker_scan_for_actor)');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)', 'EXECUTE')), ARRAY['edge_actor'], 'only edge_actor may EXECUTE marker_scan_for_actor');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)', 'EXECUTE')), ARRAY['edge_actor'], 'only edge_actor may EXECUTE marker_cosignal_attach_for_actor');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.course_pin_attempt_for_actor(text, text, timestamptz)', 'EXECUTE')), ARRAY['edge_actor'], 'only edge_actor may EXECUTE course_pin_attempt_for_actor');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.course_qr_public_key_for_actor(text, text)', 'EXECUTE')), ARRAY['edge_actor'], 'only edge_actor may EXECUTE course_qr_public_key_for_actor');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.course_pin_derive(text, date, integer)'::regprocedure, 'private.course_pin_attempt_for_actor(text, text, timestamptz)'::regprocedure,
             'private.marker_scan_for_actor(text, text, text, text, text, timestamptz, text, text, uuid)'::regprocedure, 'private.marker_cosignal_attach_for_actor(text, timestamptz, text, text, uuid)'::regprocedure,
             'private.course_qr_public_key_for_actor(text, text)'::regprocedure)
           AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']), 5, 'all five are SECURITY DEFINER, owned by private_definer, with search_path = ''''');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname IN ('marker_scan_for_actor', 'marker_cosignal_attach_for_actor', 'course_pin_attempt_for_actor', 'course_qr_public_key_for_actor')
             AND p.pronargs >= 1 AND pg_get_function_identity_arguments(p.oid) ~* '(^|, )p_(user|uid|actor)'), 0, 'no `_for_actor` definer takes a user id argument: a wrong uid cannot even be expressed');

-- ----------------------------------------------------------------------------
-- 3. The derivation against OUTSIDE test vectors (run as private_definer: the owner is the only role that may call the core)
-- ----------------------------------------------------------------------------
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40));
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_derive('fac_s24a', '2030-01-02', 0), '0442', 'vector: (fac_s24a, 2030-01-02, epoch 0)');
SELECT is(private.course_pin_derive('fac_s24a', '2030-01-02', 1), '9537', 'vector: the SAME facility and day at epoch 1 is a different PIN (a rotation)');
SELECT is(private.course_pin_derive('fac_s24a', '2030-01-03', 0), '6640', 'vector: the NEXT local day is a different PIN (the PIN changes every day)');
SELECT is(private.course_pin_derive('fac_s24b', '2030-01-02', 0), '6091', 'vector: ANOTHER facility, the same day and epoch, is a different PIN');
SELECT is(private.course_pin_derive('fac_x', '2030-01-02', 0), '9072', 'vector: a third facility');
SELECT is(private.course_pin_derive('fac_s24a', '2030-01-02', 256), '6449', 'vector: epoch 256 (a multi-byte epoch: 4 bytes, big-endian)');
SELECT is(private.course_pin_derive('fac_s24a', '2030-01-02', 0), private.course_pin_derive('fac_s24a', '2030-01-02', 0), 'deterministic: the same inputs give the same PIN');
SELECT matches(private.course_pin_derive('fac_s24a', '2030-01-02', 0), '^[0-9]{4}$', 'a PIN is exactly 4 digits (leading zeros kept)');
SELECT throws_ok($$SELECT private.course_pin_derive(NULL, '2030-01-02', 0)$$, '22023', NULL, 'a NULL facility is refused');
SELECT throws_ok($$SELECT private.course_pin_derive('fac_s24a', NULL, 0)$$, '22023', NULL, 'a NULL date is refused');
SELECT throws_ok($$SELECT private.course_pin_derive('fac_s24a', '2030-01-02', -1)$$, '22023', NULL, 'a negative epoch is refused');
SELECT throws_ok($$SELECT private.course_pin_derive('', '2030-01-02', 0)$$, '22023', NULL, 'a blank facility is refused');
ROLLBACK;

-- 3b. The pepper missing / too short: the derivation FAILS CLOSED (55000) and names no key material
BEGIN;
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.course_pin_derive('fac_s24a', '2030-01-02', 0)$$, '55000', 'course_pin_derive: the course PIN pepper is not provisioned in Vault', 'no pepper in the Vault: 55000, with a message that names no key');
ROLLBACK;
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 31));
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.course_pin_derive('fac_s24a', '2030-01-02', 0)$$, '55000', NULL, 'a 31-byte pepper is refused (the minimum is 32 bytes)');
ROLLBACK;
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('q', 40));
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_derive('fac_s24a', '2030-01-02', 0), '5962', 'vector: a DIFFERENT pepper gives a different PIN (the key really is an input)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. The two triggers
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE service_role;
SELECT is((SELECT pin_epoch FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), 0, 'the fixture facility is at PIN epoch 0');
UPDATE app.facility_programme SET pin_epoch = 5 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x';
SELECT is((SELECT pin_epoch FROM app.facility_programme WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'), 5, 'the epoch may go UP');
SELECT throws_ok($$UPDATE app.facility_programme SET pin_epoch = 4 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'$$, '23514', NULL, 'the epoch never goes DOWN (a lower one would revive a rotated-out PIN)');
SELECT lives_ok($$UPDATE app.facility_programme SET pin_epoch = 5 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'$$, 'the same value is not a decrease');
ROLLBACK;
BEGIN;
SET LOCAL ROLE service_role;
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at)
VALUES (encode(digest('s24-struct-token', 'sha256'), 'hex'), 'fac_x', '00000000-0000-0000-0000-1000000000a1', 'k1', now(), now() + interval '120 seconds');
UPDATE app.course_qr_token SET used_by_user = '00000000-0000-0000-0000-00000000000a', used_at = now() WHERE nonce_hash = encode(digest('s24-struct-token', 'sha256'), 'hex');
SELECT is((SELECT used_by_user FROM app.course_qr_token WHERE nonce_hash = encode(digest('s24-struct-token', 'sha256'), 'hex')), '00000000-0000-0000-0000-00000000000a'::uuid, 'an unused token may be marked used (once)');
SELECT throws_ok($$UPDATE app.course_qr_token SET used_by_user = '00000000-0000-0000-0000-00000000000b' WHERE nonce_hash = encode(digest('s24-struct-token', 'sha256'), 'hex')$$, '23514', NULL, 'a used token cannot be handed to another account');
SELECT throws_ok($$UPDATE app.course_qr_token SET used_at = NULL, used_by_user = NULL WHERE nonce_hash = encode(digest('s24-struct-token', 'sha256'), 'hex')$$, '23514', NULL, 'a used token cannot be un-used (single use is a database invariant)');
SELECT throws_ok($$UPDATE app.course_qr_token SET used_at = now() + interval '1 hour' WHERE nonce_hash = encode(digest('s24-struct-token', 'sha256'), 'hex')$$, '23514', NULL, 'nor re-dated');
SELECT lives_ok($$UPDATE app.course_qr_token SET kid = 'k2' WHERE nonce_hash = encode(digest('s24-struct-token', 'sha256'), 'hex')$$, 'control: a column the trigger does not guard is not blocked by it (the grant, not the trigger, limits the definer)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 5. Registries (FORCE RLS tables: read as service_role, which holds the grants)
-- ----------------------------------------------------------------------------
SET ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('course_pin_derive', 'course_qr_public_key_for_actor', 'course_pin_attempt_for_actor', 'marker_scan_for_actor', 'marker_cosignal_attach_for_actor',
             'facility_programme_pin_epoch_monotonic', 'course_qr_token_single_use')), 7, 'registry: all seven new functions are in private.function_inventory');
SELECT is((SELECT array_agg(function_name ORDER BY function_name) FROM private.function_inventory
           WHERE function_name IN ('course_pin_derive', 'course_qr_public_key_for_actor', 'course_pin_attempt_for_actor', 'marker_scan_for_actor', 'marker_cosignal_attach_for_actor') AND expected_edge_actor),
  ARRAY['course_pin_attempt_for_actor', 'course_qr_public_key_for_actor', 'marker_cosignal_attach_for_actor', 'marker_scan_for_actor'], 'registry: edge_actor is expected on exactly the four wrappers (not the derivation core)');
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name IN ('course_pin_derive', 'course_qr_public_key_for_actor', 'course_pin_attempt_for_actor', 'marker_scan_for_actor', 'marker_cosignal_attach_for_actor', 'facility_programme_pin_epoch_monotonic', 'course_qr_token_single_use')
             AND (expected_anon OR expected_authenticated OR expected_service_role OR expected_edge_system)), 0, 'registry: no other role is expected on any of them');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_marker\_scan\_%' AND scoped), 15, 'registry: all 15 private_definer policies are in the allow-list, each scoped');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_marker\_scan\_%' AND using_expr IS NULL AND with_check_expr IS NULL), 0, 'registry: and each carries its recorded expression');
SELECT is((SELECT count(*)::int FROM private.pii_retention_policy WHERE table_name IN ('course_qr_key', 'course_pin_alarm')), 0, 'registry: neither new table is personal (no user column), so neither is in the retention policy');
RESET ROLE;

SELECT * FROM finish();

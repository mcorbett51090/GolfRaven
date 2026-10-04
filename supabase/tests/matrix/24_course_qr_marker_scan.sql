-- 24_course_qr_marker_scan.sql
-- 0046_course_qr_marker_scan.sql, the structural invariants and the PIN derivation: the course QR's PUBLIC keys and the failure-alarm table are definer-only,
-- the daily PIN is DERIVED (HMAC-SHA256 under a Vault pepper) and the pepper is readable by NOBODY but the two derivation functions (the current pepper's, and the matcher that also knows the previous pepper), the tables a scan writes are
-- written only through the definers, and the registries (function inventory, definer policy allow-list) describe what the migration built. The edge_actor lane (the scan,
-- the PIN counters, the co-signal intake, AT(3) / AT(4) / AT(13) / AT(19)) is 24_course_qr_marker_scan_edge.sql: it has to reconnect as a real edge_gateway login.
--
-- THE TEST VECTORS below were computed OUTSIDE the database (Python hmac / hashlib, never this function) from a pepper this file BUILDS AT RUN TIME as repeat('p', 40)
-- (no secret literal lives in this file or in the repository) and the message
--   b'golfraven/course-pin/v1' + b'\x00' + facility_id.encode() + b'\x00' + 'YYYY-MM-DD'.encode() + b'\x00' + struct.pack('>I', pin_epoch)
-- reduced as int.from_bytes(mac[:4], 'big') % 10000, zero padded to 4 digits, so a change to the derivation (the label, the field order, the separators, the encoding,
-- the reduction, the key, the hash) fails here, not in production. supabase/tests/unit/course-qr-pin-vector.test.ts pins the same vectors from the TypeScript side.

SELECT plan(126);

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
SELECT has_table('app', 'course_pin_epoch_log', 'app.course_pin_epoch_log exists (WHEN each PIN epoch took effect)');
SELECT columns_are('app', 'course_pin_epoch_log', ARRAY['facility_id', 'pin_epoch', 'previous_epoch', 'effective_from'], 'the epoch log holds no user id and no PIN');
SELECT col_is_pk('app', 'course_pin_epoch_log', ARRAY['facility_id', 'pin_epoch'], 'one log row per (facility, epoch)');
SELECT has_table('private', 'course_pin_proof', 'private.course_pin_proof exists (the PIN gate passed in this transaction)');
SELECT columns_are('private', 'course_pin_proof', ARRAY['backend_pid', 'xact', 'actor_uid', 'facility_id', 'local_date', 'pin_at'], 'the proof holds the actor, the facility, the date and the instant, never the PIN');
SELECT is((SELECT bool_and(c.relrowsecurity AND c.relforcerowsecurity) FROM pg_class c WHERE c.oid IN ('app.course_pin_epoch_log'::regclass, 'private.course_pin_proof'::regclass)), true, 'both have RLS enabled AND forced');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n), (VALUES ('app.course_pin_epoch_log'), ('private.course_pin_proof')) t(n)
           WHERE has_any_column_privilege(r.n, t.n, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, t.n, 'DELETE,TRUNCATE,TRIGGER')), 0,
  'no client role and no edge role holds ANY privilege on the epoch log or the proof (every path is a definer)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid IN ('app.course_pin_epoch_log'::regclass, 'private.course_pin_proof'::regclass) AND p.polroles <> ARRAY['private_definer'::regrole::oid]), 0,
  'the epoch log and the proof have policies for private_definer ONLY');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace IN ('private'::regnamespace, 'app'::regnamespace) AND p.prosrc ~ 'course_pin_epoch_log' AND p.proname NOT IN ('course_pin_epoch_log_write', 'course_pin_epoch_at')), 0,
  'no function but the log''s trigger function (the only writer) and the epoch reader names the epoch log');
SELECT has_table('app', 'course_pin_pepper_epoch', 'app.course_pin_pepper_epoch exists (WHEN the current pepper took effect: the operator writes it, never inferred from Vault timestamps)');
SELECT columns_are('app', 'course_pin_pepper_epoch', ARRAY['effective_from', 'recorded_at'], 'the pepper epoch holds a time only: no user id, no secret');
SELECT is((SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'app.course_pin_pepper_epoch'::regclass), true, 'the pepper epoch has RLS enabled AND forced');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.course_pin_pepper_epoch', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.course_pin_pepper_epoch', 'DELETE,TRUNCATE,TRIGGER')), 0, 'no client role and no edge role holds ANY privilege on the pepper epoch');
SELECT is((has_table_privilege('service_role', 'app.course_pin_pepper_epoch', 'SELECT') AND has_table_privilege('service_role', 'app.course_pin_pepper_epoch', 'INSERT') AND NOT has_table_privilege('service_role', 'app.course_pin_pepper_epoch', 'UPDATE,DELETE')), true, 'service_role (the operator) may read and INSERT the pepper epoch, never rewrite or delete a row of it');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace IN ('private'::regnamespace, 'app'::regnamespace) AND p.prosrc ~ 'course_pin_pepper_epoch' AND p.proname <> 'course_pin_matches'), 0, 'only the matcher reads the pepper epoch');
-- the proof's lifetime is ENFORCED: a deferred constraint trigger deletes the backend's rows at COMMIT (the real-commit proof is in the rows file)
SELECT is((SELECT count(*)::int FROM pg_trigger t WHERE t.tgrelid = 'private.course_pin_proof'::regclass AND NOT t.tgisinternal AND t.tgname = 'course_pin_proof_expire_trg' AND t.tgconstraint <> 0 AND t.tgdeferrable AND t.tginitdeferred
             AND t.tgfoid = 'private.course_pin_proof_expire()'::regprocedure AND (t.tgtype & 4) = 4), 1, 'the proof table has a DEFERRABLE INITIALLY DEFERRED constraint trigger on INSERT that runs the expiry function');
-- the two trigger functions: the migrating role's loan of EXECUTE (needed once, for CREATE TRIGGER) is taken back: the ACL is EXACTLY the owner's, in both harness modes, for every role that ran the migration
SELECT is((SELECT p.proacl::text FROM pg_proc p WHERE p.oid = 'private.course_pin_epoch_log_write()'::regprocedure), '{private_definer=X/private_definer}', 'course_pin_epoch_log_write: the ACL is exactly the owner''s (no lend left for postgres or migration_owner)');
SELECT is((SELECT p.proacl::text FROM pg_proc p WHERE p.oid = 'private.course_pin_proof_expire()'::regprocedure), '{private_definer=X/private_definer}', 'course_pin_proof_expire: the ACL is exactly the owner''s (no lend left for postgres or migration_owner)');
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
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%' AND p.polroles = ARRAY['private_definer'::regrole::oid]), 22, 'the migration added exactly 22 policies, every one for private_definer only');
SELECT is((SELECT array_agg(p.polname || ' ' || coalesce(pg_get_expr(p.polqual, p.polrelid), '-') || ' / ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '-') ORDER BY p.polname) FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%'), ARRAY[
  'pd_marker_scan_alarm_insert - / (private.actor_uid() IS NOT NULL)',
  'pd_marker_scan_alarm_select (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_credit_insert - / (user_id = private.actor_uid())',
  'pd_marker_scan_credit_select (user_id = private.actor_uid()) / -',
  'pd_marker_scan_credit_update (user_id = private.actor_uid()) / (user_id = private.actor_uid())',
  'pd_marker_scan_epoch_log_insert - / true',
  'pd_marker_scan_epoch_log_select true / -',
  'pd_marker_scan_evidence_select (user_id = private.actor_uid()) / -',
  'pd_marker_scan_facility_programme_epoch (private.actor_uid() IS NOT NULL) / (private.actor_uid() IS NOT NULL)',
  'pd_marker_scan_facility_qr_read (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_facility_read (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_key_read (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_pepper_epoch_select true / -',
  'pd_marker_scan_proof_delete (backend_pid = pg_backend_pid()) / -',
  'pd_marker_scan_proof_insert - / ((backend_pid = pg_backend_pid()) AND (actor_uid = private.actor_uid()))',
  'pd_marker_scan_proof_select ((backend_pid = pg_backend_pid()) AND (actor_uid = private.actor_uid())) / -',
  'pd_marker_scan_purchase_insert - / (user_id = private.actor_uid())',
  'pd_marker_scan_purchase_select (user_id = private.actor_uid()) / -',
  'pd_marker_scan_purchase_update (user_id = private.actor_uid()) / (user_id = private.actor_uid())',
  'pd_marker_scan_token_select (private.actor_uid() IS NOT NULL) / -',
  'pd_marker_scan_token_update (private.actor_uid() IS NOT NULL) / ((used_by_user = private.actor_uid()) AND (used_at IS NOT NULL))',
  'pd_marker_scan_trail_programme_read (private.actor_uid() IS NOT NULL) / -'
],
  'the 22 policies, expression for expression (a broadened USING or WITH CHECK fails here: the token UPDATE may only mark a token used BY THE BOUND ACTOR, the purchase and credit writes are the bound actor''s own rows)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%'
             AND (coalesce(pg_get_expr(p.polqual, p.polrelid), '') || ' ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')) ~* 'current_setting|set_config'), 0,
  'HARD RULE: not one of them is keyed on a settable GUC (each is keyed on the actor BINDING, private.actor_uid())');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polname LIKE 'pd\_marker\_scan\_%'
             AND (coalesce(pg_get_expr(p.polqual, p.polrelid), '') || ' ' || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')) NOT LIKE '%private.actor_uid()%'), 4, 'every one of them names private.actor_uid() but four: the epoch log''s SELECT and INSERT (the logging trigger runs with no actor on an operator rotation), the pepper epoch''s SELECT (no personal data) and the proof''s DELETE (keyed on THIS BACKEND, never a GUC: the proof''s own expiry deletes the backend''s rows at COMMIT)');

-- ----------------------------------------------------------------------------
-- 2. The pepper: readable by nobody but the one derivation function; the function posture
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_pepper'), 2, 'the pepper: exactly TWO functions in the database name it');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_pepper'), ARRAY['course_pin_derive', 'course_pin_matches'],
  'the pepper: private.course_pin_derive (the current pepper) and private.course_pin_matches (which also reads the previous one)');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n), (VALUES
             ('private.course_pin_derive(text, date, integer)'), ('private.course_pin_from_key(text, text, date, integer)'), ('private.course_pin_matches(text, date, integer, text, timestamptz)'),
             ('private.course_pin_epoch_at(text, timestamptz)'), ('private.course_pin_epoch_log_write()'), ('private.course_pin_proof_expire()'), ('private.marker_cosignal_check(uuid, text, date, timestamptz, text, text, uuid)')) f(n)
           WHERE has_function_privilege(r.n, f.n, 'EXECUTE')), 0, 'the pepper: no role at all may EXECUTE the derivation, the pure core, the matcher, the epoch reader, the log writer or the co-signal check');
SELECT is((SELECT bool_and(p.proacl::text !~ '(^\{|,)=') FROM pg_proc p WHERE p.oid IN ('private.course_pin_derive(text, date, integer)'::regprocedure, 'private.course_pin_matches(text, date, integer, text, timestamptz)'::regprocedure,
             'private.course_pin_from_key(text, text, date, integer)'::regprocedure, 'private.course_pin_epoch_at(text, timestamptz)'::regprocedure, 'private.marker_cosignal_check(uuid, text, date, timestamptz, text, text, uuid)'::regprocedure)),
  true, 'the pepper: PUBLIC has no EXECUTE on any of them');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_derive' AND p.proname <> 'course_pin_derive'), ARRAY['course_pin_matches'],
  'the derivation is called by exactly one function: the matcher');
SELECT is((SELECT array_agg(p.proname::text ORDER BY p.proname) FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'course_pin_matches' AND p.proname <> 'course_pin_matches'), ARRAY['course_pin_attempt_for_actor', 'marker_scan_for_actor'],
  'the matcher is called by exactly two functions: the PIN gate (course_pin_attempt_for_actor) and the scan (marker_scan_for_actor)');
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
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.course_pin_from_key(text, text, date, integer)'::regprocedure, 'private.course_pin_matches(text, date, integer, text, timestamptz)'::regprocedure,
             'private.course_pin_epoch_at(text, timestamptz)'::regprocedure, 'private.course_pin_epoch_log_write()'::regprocedure, 'private.marker_cosignal_check(uuid, text, date, timestamptz, text, text, uuid)'::regprocedure)
           AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']), 5, 'the five helpers are SECURITY DEFINER too, owned by private_definer, with search_path = ''''');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.proname IN ('marker_scan_for_actor', 'marker_cosignal_attach_for_actor', 'course_pin_attempt_for_actor', 'course_qr_public_key_for_actor')
             AND p.pronargs >= 1 AND pg_get_function_identity_arguments(p.oid) ~* '(^|, )p_(user|uid|actor)'), 0, 'no `_for_actor` definer takes a user id argument: a wrong uid cannot even be expressed');

SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'catalog_roster'), 0,
  'DEPARTURE 10, pinned: the player lane consults app.facility_programme (the partner programme), NEVER the catalog roster: a programme facility outside the trail''s roster earns a credit that counts for nothing, and a roster member with no programme row cannot be bought at; keeping the two in step is the programme editor''s (S6), not the scan''s');
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
-- 3c. THE PIN IS JUDGED AT THE FIX'S INSTANT: the pure core, the previous pepper, the epoch history (M1: a rotation must not break a queued offline scan)
-- ----------------------------------------------------------------------------
-- vectors for fac_x 2030-01-02 under the pepper repeat('p', 40) / repeat('q', 40), computed OUTSIDE the database: epoch 0 9072 / 6623, epoch 1 0624 / 7648, epoch 2 7858 / 4166, epoch 3 2907 / 4549
BEGIN;
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_from_key(repeat('p', 40), 'fac_x', '2030-01-02', 0), '9072', 'the pure core: the vector under the p-pepper');
SELECT is(private.course_pin_from_key(repeat('q', 40), 'fac_x', '2030-01-02', 1), '7648', 'the pure core: the vector under another key and epoch');
SELECT throws_ok($$SELECT private.course_pin_from_key(NULL, 'fac_x', '2030-01-02', 0)$$, '22023', NULL, 'the pure core refuses a NULL key');
ROLLBACK;
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40));
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now()), true, 'matches: the current pepper''s PIN at an instant after it took effect');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9073', now()), false, 'matches: a wrong PIN is false');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 1, '9072', now()), false, 'matches: the epoch is an input (the epoch-0 PIN is not the epoch-1 PIN)');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, NULL, now()), false, 'matches: no PIN is false');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now() - interval '1 hour'), true, 'matches: with NO previous pepper an earlier instant is judged under the current one (the plain consequence of a rotation without one)');
ROLLBACK;
BEGIN;
-- a previous pepper ALONE does nothing: with no pepper_epoch row nothing says when the current one took effect, so every instant is judged under the current pepper
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40)), ('course_pin_pepper_previous', repeat('q', 40));
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '1 hour'), false, 'PEPPER ROTATION: a previous pepper with NO app.course_pin_pepper_epoch row is never used (the old pepper is not a standing second key)');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now() - interval '1 hour'), true, 'PEPPER ROTATION: ... the current pepper judges every instant');
ROLLBACK;
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40)), ('course_pin_pepper_previous', repeat('q', 40));
SET LOCAL ROLE service_role;
INSERT INTO app.course_pin_pepper_epoch (effective_from) VALUES (now() - interval '30 minutes');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '1 hour'), true, 'PEPPER ROTATION: an instant BEFORE the current pepper took effect (the operator-written effective time) is judged under the previous pepper (a queued scan still verifies)');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now() - interval '1 hour'), false, 'PEPPER ROTATION: ... and the current pepper''s PIN is not what was displayed then');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now()), true, 'PEPPER ROTATION: an instant after it is judged under the current pepper');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now()), false, 'PEPPER ROTATION: ... and the previous pepper''s PIN no longer verifies for a scan made now');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '9072', now() - interval '20 minutes'), true, 'PEPPER ROTATION: the effective time is the TABLE''s, not Vault''s created_at (the secrets were created just now, yet an instant 20 minutes ago, after the effective time, is judged under the current pepper)');
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '20 minutes'), false, 'PEPPER ROTATION: ... and the previous pepper does not verify there');
ROLLBACK;
BEGIN;
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40)), ('course_pin_pepper_previous', repeat('q', 31));
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_matches('fac_x', '2030-01-02', 0, '6623', now() - interval '1 hour'), false, 'a previous pepper under 32 bytes is ignored (it is not used)');
ROLLBACK;

-- the epoch history (an actor binding is emulated as private_definer: the table is the same one bind_actor writes)
BEGIN;
SET LOCAL ROLE service_role;
-- a SECOND programme row at fac_x with a HIGHER epoch (the rows of a facility rotate together; max is what counts, a partial rotation must not lower it)
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('trl_s24ep', 'trail', 'verified', 1);
INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('trl_s24ep', 'trail-s24ep', 'Trail S24EP', 1);
INSERT INTO app.trail_programme (trail_id, status, marker_source) VALUES ('trl_s24ep', 'live', 'any_purchase');
INSERT INTO app.facility_programme (trail_id, facility_id, participation, qr_mode, pin_epoch) VALUES ('trl_s24ep', 'fac_x', 'accepted', 'both', 3);
RESET ROLE;
SET LOCAL ROLE private_definer;
INSERT INTO private.actor_binding (backend_pid, xact, actor_uid, kind) VALUES (pg_backend_pid(), pg_current_xact_id(), '00000000-0000-0000-0000-00000000000a', 'user')
ON CONFLICT (backend_pid) DO UPDATE SET xact = EXCLUDED.xact, actor_uid = EXCLUDED.actor_uid, kind = EXCLUDED.kind;
SELECT is(private.course_pin_epoch_at('fac_x', now()), 3, 'no rotation ever logged: the CURRENT epoch, the HIGHEST over the facility''s programme rows (max, not min)');
SELECT is(private.course_pin_epoch_at('fac_nope', now()), 0, 'a facility with no programme row: epoch 0');
INSERT INTO app.course_pin_epoch_log (facility_id, pin_epoch, previous_epoch, effective_from) VALUES ('fac_x', 4, 3, now() - interval '2 hours'), ('fac_x', 5, 4, now() - interval '1 hour');
SELECT throws_ok($$SELECT private.marker_cosignal_check('00000000-0000-0000-0000-00000000000b', 'fac_x', current_date, now(), 'attested', 'f', gen_random_uuid())$$, '42501', 'marker_cosignal_check: the checked actor is not the bound actor',
  'the co-signal check reads only the BOUND actor''s evidence: another account''s uid is refused');
SELECT is(private.marker_cosignal_check('00000000-0000-0000-0000-00000000000a', 'fac_x', current_date, now(), 'attested', 'f', gen_random_uuid()), 'cosignal_invalid', 'and for the bound actor an evidence id that names no row is cosignal_invalid');
SELECT is(private.course_pin_epoch_at('fac_x', now() - interval '3 hours'), 3, 'BEFORE the first logged rotation: the epoch that rotation replaced');
SELECT is(private.course_pin_epoch_at('fac_x', now() - interval '90 minutes'), 4, 'between two rotations the same day: the first one''s epoch (live then)');
SELECT is(private.course_pin_epoch_at('fac_x', now() - interval '30 minutes'), 5, 'after the second rotation the same day: the second one''s epoch');
SELECT is(private.course_pin_epoch_at('fac_x', now()), 5, 'and now: the newest');
SELECT is(private.course_pin_epoch_at('fac_x', now() - interval '2 hours'), 4, 'the instant of a rotation belongs to the NEW epoch');
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
-- the rotation LOG: every rise of the epoch is logged once (by a trigger, so S2b's "Rotate PIN" and an operator are logged too), a non-rise is not
BEGIN;
SET LOCAL ROLE service_role;
SELECT is((SELECT count(*)::int FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x'), 0, 'the fixture facility has never rotated: no log row');
UPDATE app.facility_programme SET pin_epoch = 1 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x';
SELECT is((SELECT array_agg(pin_epoch || '<-' || previous_epoch) FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x'), ARRAY['1<-0'], 'a rotation (by an operator with no actor bound) is logged with its epoch and the one it replaced');
SELECT is((SELECT effective_from = now() FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x' AND pin_epoch = 1), true, 'and the instant it took effect');
UPDATE app.facility_programme SET pin_epoch = 1 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x';
SELECT is((SELECT count(*)::int FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x'), 1, 'writing the same epoch again logs nothing');
UPDATE app.facility_programme SET pin_epoch = 2 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x';
SELECT is((SELECT array_agg(pin_epoch ORDER BY pin_epoch) FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x'), ARRAY[1, 2], 'a second rotation is a second row (the history, not a counter)');
SELECT throws_ok($$UPDATE app.facility_programme SET pin_epoch = 1 WHERE trail_id = 'trl_t' AND facility_id = 'fac_x'$$, '23514', NULL, 'a decrease is refused and logs nothing');
SELECT is((SELECT count(*)::int FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x'), 2, '... still two rows');
ROLLBACK;
BEGIN;
SET LOCAL ROLE service_role;
INSERT INTO app.catalog_id_ledger (id, kind, status, first_catalog_version) VALUES ('trl_s24el', 'trail', 'verified', 1);
INSERT INTO app.catalog_trail (id, slug, name, catalog_version) VALUES ('trl_s24el', 'trail-s24el', 'Trail S24EL', 1);
INSERT INTO app.trail_programme (trail_id, status, marker_source) VALUES ('trl_s24el', 'live', 'any_purchase');
INSERT INTO app.facility_programme (trail_id, facility_id, participation, qr_mode) VALUES ('trl_s24el', 'fac_x', 'accepted', 'both');
UPDATE app.facility_programme SET pin_epoch = 7 WHERE facility_id = 'fac_x';
SELECT is((SELECT count(*)::int FROM app.course_pin_epoch_log WHERE facility_id = 'fac_x' AND pin_epoch = 7), 1, 'a rotation that updates SEVERAL programme rows of the facility is logged ONCE');
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
             'facility_programme_pin_epoch_monotonic', 'course_qr_token_single_use', 'course_pin_from_key', 'course_pin_matches', 'course_pin_epoch_at', 'course_pin_epoch_log_write', 'course_pin_proof_expire', 'marker_cosignal_check')), 13, 'registry: all thirteen new functions are in private.function_inventory');
SELECT is((SELECT array_agg(function_name ORDER BY function_name) FROM private.function_inventory
           WHERE function_name IN ('course_pin_derive', 'course_qr_public_key_for_actor', 'course_pin_attempt_for_actor', 'marker_scan_for_actor', 'marker_cosignal_attach_for_actor') AND expected_edge_actor),
  ARRAY['course_pin_attempt_for_actor', 'course_qr_public_key_for_actor', 'marker_cosignal_attach_for_actor', 'marker_scan_for_actor'], 'registry: edge_actor is expected on exactly the four wrappers (not the derivation core)');
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name IN ('course_pin_derive', 'course_qr_public_key_for_actor', 'course_pin_attempt_for_actor', 'marker_scan_for_actor', 'marker_cosignal_attach_for_actor', 'facility_programme_pin_epoch_monotonic', 'course_qr_token_single_use', 'course_pin_from_key', 'course_pin_matches', 'course_pin_epoch_at', 'course_pin_epoch_log_write', 'course_pin_proof_expire', 'marker_cosignal_check')
             AND (expected_anon OR expected_authenticated OR expected_service_role OR expected_edge_system)), 0, 'registry: no other role is expected on any of them');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_marker\_scan\_%' AND scoped), 22, 'registry: all 22 private_definer policies are in the allow-list, each scoped');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE 'pd\_marker\_scan\_%' AND using_expr IS NULL AND with_check_expr IS NULL), 0, 'registry: and each carries its recorded expression');
SELECT is((SELECT count(*)::int FROM private.pii_retention_policy WHERE table_name IN ('course_qr_key', 'course_pin_alarm', 'course_pin_epoch_log', 'course_pin_pepper_epoch', 'course_pin_proof')), 0, 'registry: none of the new tables holds personal data at rest (the proof is deleted at COMMIT: a real-commit cell in the rows file proves the table empty), so none is in the retention policy');
RESET ROLE;

SELECT * FROM finish();

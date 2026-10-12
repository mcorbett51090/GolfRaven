-- 86_partner_totp_hard_lock.sql
-- 0108_partner_totp_hard_lock.sql (P5 §117): the partner TOTP gets a ceiling on CONSECUTIVE failures. Before it, partner_totp_attempt reset its count at every lock: 5 guesses per
-- 15 minutes for ever (480 a day) for anyone holding a valid aal 1 session. Now consecutive_failed survives the 15-minute locks and only a success, an admin reset or a re-enrol
-- clears it, and the 20th consecutive failure sets hard_locked_at: every later code is refused BEFORE it is compared, until an admin resets the TOTP.
--
-- Proved here:
--   A  structure: the two columns, their CHECKs, that no grant moved (the verifier is still the only role that can reach them), that the five redefined functions kept owner / ACL /
--      search_path / volatility / comment, the alarm kind and its policies, the inventory notes.
--   B  THE BUG: 19 failures spread over four 15-minute locks leave consecutive_failed at 19 (the lock no longer erases the count); the 20th hard-locks.
--   C  a success clears the count (19, success, then 19 more failures are still not a hard lock); the thresholds sit at exactly 5 / 10 / 15 (soft) and 20 (hard).
--   D  the hard lock: a correct code is refused and NOT evaluated (last_step, the session's aal and mfa_until, the counters and hard_locked_at do not move), from a second session too,
--      for one person only; exactly ONE audit row and ONE alarm at the transition and none for any refusal after it (even when the alarm's minute has moved on).
--   E  the way out: an admin reset clears the hard lock and the counter, and the person can then enrol, confirm and step up again; a re-enrol and a successful confirm clear both columns;
--      confirm FAILURES are not counted toward the hard lock.
--   F  failures during a 15-minute lock are still not counted (the existing rule), and the soft lock still answers locked|900.
--
-- HOW THIS FILE RUNS. One transaction, rolled back. Fixtures are written through temporary CURRENT_USER policies (the 28 / 31 / 82 pattern); each scenario runs inside a SAVEPOINT. The
-- 15-minute wait is simulated by moving locked_until into the past. A "wrong" code is one that is not valid for any of the five steps around now, so no cell can flake on a step boundary.

\set QUIET 1
BEGIN;
SELECT plan(111);

-- ----------------------------------------------------------------------------
-- 0. Setup
-- ----------------------------------------------------------------------------
GRANT edge_partner, partner_totp_verifier, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_totp, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz86_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz86_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz86_totp ON app.partner_totp FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz86_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz86_audit ON app.audit_log FOR SELECT TO CURRENT_USER USING (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$ SELECT md5('s86:' || p_label) || md5('s86b:' || p_label) $f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c86:' || p_label) || md5('c86b:' || p_label), 'hex'), decode(md5('k86:' || p_label) || md5('k86b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at, mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n86:' || p_label) || md5('n86b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'), convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_step(p_label text, p_cols jsonb) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    otp_proof_until = CASE WHEN p_cols ? 'otp_s' THEN clock_timestamp() + ((p_cols ->> 'otp_s')::numeric * interval '1 second') ELSE s.otp_proof_until END,
    mfa_until = CASE WHEN p_cols ? 'mfa_s' THEN clock_timestamp() + ((p_cols ->> 'mfa_s')::numeric * interval '1 second') ELSE s.mfa_until END,
    aal = CASE WHEN p_cols ? 'aal' THEN (p_cols ->> 'aal')::smallint ELSE s.aal END
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
-- independent seed oracle: HMAC-SHA256(shim partner_totp_key, label || 0x00 || uid || int4send(ver)) (the 31 oracle)
CREATE FUNCTION pg_temp.seed_of(p_uid uuid, p_ver integer) RETURNS bytea LANGUAGE sql AS $f$
  SELECT public.hmac(
    convert_to('golfraven/partner-totp/v1', 'UTF8') || decode('00', 'hex') || decode(replace(p_uid::text, '-', ''), 'hex') || int4send(p_ver),
    convert_to((SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'partner_totp_key'), 'UTF8'),
    'sha256')
$f$;
CREATE FUNCTION pg_temp.hotp_at(p_seed bytea, p_delta integer DEFAULT 0) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE c text;
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  SELECT private.hotp(p_seed, floor(extract(epoch from clock_timestamp()) / 30.0)::bigint + p_delta, 6, 'sha1') INTO c;
  EXECUTE 'RESET ROLE';
  RETURN c;
END
$f$;
-- a code valid for NONE of the steps now-3 .. now+3 (the window is now-1 .. now+1; the margin means a step boundary mid-cell cannot make it right)
CREATE FUNCTION pg_temp.bad_code(p_uid uuid, p_ver integer) RETURNS text LANGUAGE sql AS $f$
  SELECT x.c FROM (SELECT lpad(g::text, 6, '0') AS c FROM generate_series(0, 20) g) x
  WHERE x.c NOT IN (SELECT pg_temp.hotp_at(pg_temp.seed_of(p_uid, p_ver), d) FROM generate_series(-3, 3) d)
  ORDER BY x.c LIMIT 1
$f$;
CREATE FUNCTION pg_temp.seed_row(p_uid uuid, p_ver integer, p_confirmed boolean, p_failed smallint, p_consec integer, p_hard boolean DEFAULT false, p_sid uuid DEFAULT NULL) RETURNS void LANGUAGE sql AS $f$
  INSERT INTO app.partner_totp (user_id, seed_version, enrolled_at, enrol_session_id, confirmed_at, last_step, failed_count, locked_until, revoked_at, created_at, consecutive_failed, hard_locked_at)
  VALUES (p_uid, p_ver, clock_timestamp(), p_sid, CASE WHEN p_confirmed THEN clock_timestamp() END, NULL, p_failed, NULL, NULL, clock_timestamp(), p_consec,
          CASE WHEN p_hard THEN clock_timestamp() END)
$f$;
CREATE FUNCTION pg_temp.verify(p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_verify_for_partner(p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after || '|' || (r.o_mfa_until IS NOT NULL)::text;
END
$f$;
CREATE FUNCTION pg_temp.enrol() RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_enrol_for_partner();
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || coalesce(r.o_seed_version::text, '');
END
$f$;
CREATE FUNCTION pg_temp.confirm(p_code text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_confirm_for_partner(p_code);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after;
END
$f$;
CREATE FUNCTION pg_temp.reset_totp(p_uid uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_totp_reset_for_partner(p_uid);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status;
END
$f$;
-- the 15-minute wait, simulated: any lock still running ends one second ago
CREATE FUNCTION pg_temp.wait_out_lock(p_uid uuid) RETURNS void LANGUAGE sql AS $f$
  UPDATE app.partner_totp SET locked_until = clock_timestamp() - interval '1 second' WHERE user_id = p_uid AND locked_until IS NOT NULL AND locked_until > clock_timestamp()
$f$;
-- N wrong codes in a row, each lock waited out; the statuses, comma-joined
CREATE FUNCTION pg_temp.fail_run(p_uid uuid, p_ver integer, p_n integer) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE v_out text := ''; i integer;
BEGIN
  FOR i IN 1..p_n LOOP
    v_out := v_out || split_part(pg_temp.verify(pg_temp.bad_code(p_uid, p_ver)), '|', 1) || ',';
    PERFORM pg_temp.wait_out_lock(p_uid);
  END LOOP;
  RETURN v_out;
END
$f$;
-- consecutive_failed, failed_count, hard-locked?, locked now?
CREATE FUNCTION pg_temp.confirm_fail_run(p_uid uuid, p_ver integer, p_n integer) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE v_out text := ''; i integer;
BEGIN
  FOR i IN 1..p_n LOOP
    v_out := v_out || split_part(pg_temp.confirm(pg_temp.bad_code(p_uid, p_ver)), '|', 1) || ',';
    PERFORM pg_temp.wait_out_lock(p_uid);
  END LOOP;
  RETURN v_out;
END
$f$;
CREATE FUNCTION pg_temp.st(p_uid uuid) RETURNS text LANGUAGE sql AS $f$
  SELECT t.consecutive_failed || ',' || t.failed_count || ',' || (t.hard_locked_at IS NOT NULL)::text || ',' || (t.locked_until IS NOT NULL AND t.locked_until > clock_timestamp())::text
  FROM app.partner_totp t WHERE t.user_id = p_uid
$f$;
CREATE FUNCTION pg_temp.aud(p_uid uuid, p_action text) RETURNS integer LANGUAGE sql AS $f$
  SELECT count(*)::int FROM app.audit_log WHERE subject_id = p_uid::text AND action = p_action
$f$;
CREATE FUNCTION pg_temp.alarms(p_uid uuid, p_kind text) RETURNS integer LANGUAGE sql AS $f$
  SELECT count(*)::int FROM app.partner_auth_alarm WHERE kind = p_kind AND bucket_key = p_uid::text
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int), pg_temp.seed_step(text, jsonb), pg_temp.seed_of(uuid, integer),
  pg_temp.hotp_at(bytea, integer), pg_temp.bad_code(uuid, integer), pg_temp.seed_row(uuid, integer, boolean, smallint, integer, boolean, uuid), pg_temp.verify(text), pg_temp.enrol(),
  pg_temp.confirm(text), pg_temp.reset_totp(uuid), pg_temp.wait_out_lock(uuid), pg_temp.fail_run(uuid, integer, integer), pg_temp.confirm_fail_run(uuid, integer, integer), pg_temp.st(uuid), pg_temp.aud(uuid, text),
  pg_temp.alarms(uuid, text) TO PUBLIC;

SELECT pg_temp.mk_cred('op', '00000000-0000-0000-0000-3000000000c1') AS c_op \gset
SELECT pg_temp.mk_cred('ad', '00000000-0000-0000-0000-4000000000d0') AS c_ad \gset
SELECT pg_temp.mk_session('op', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_op \gset
SELECT pg_temp.mk_session('opb', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_opb \gset
SELECT pg_temp.mk_session('ad', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 2) AS s_ad \gset
SELECT pg_temp.mk_session('ad1', '00000000-0000-0000-0000-4000000000d0', :'c_ad', 1) AS s_ad1 \gset
SELECT pg_temp.th('op') AS th_op, pg_temp.th('opb') AS th_opb, pg_temp.th('ad') AS th_ad, pg_temp.th('ad1') AS th_ad1, pg_temp.th('op2') AS th_op2 \gset

-- ----------------------------------------------------------------------------
-- A. Structure, privileges, and what the redefinition left alone
-- ----------------------------------------------------------------------------
SELECT is((SELECT format_type(a.atttypid, a.atttypmod) || '|' || a.attnotnull::text || '|' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
           FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = 'app.partner_totp'::regclass AND a.attname = 'consecutive_failed'),
  'integer|true|0', 'A: consecutive_failed is integer NOT NULL DEFAULT 0');
SELECT is((SELECT format_type(a.atttypid, a.atttypmod) || '|' || a.attnotnull::text || '|' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
           FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = 'app.partner_totp'::regclass AND a.attname = 'hard_locked_at'),
  'timestamp with time zone|false|', 'A: hard_locked_at is a nullable timestamptz with no default');
SELECT is((SELECT count(*)::int FROM pg_constraint WHERE conrelid = 'app.partner_totp'::regclass AND conname IN ('partner_totp_consecutive_failed_check', 'partner_totp_hard_lock_iff_twenty') AND contype = 'c'),
  2, 'A: the two CHECKs exist');
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 0::smallint, 0);
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'A: a fresh row has consecutive_failed 0 and no hard lock');
SELECT throws_like($$UPDATE app.partner_totp SET consecutive_failed = 21 WHERE user_id = '00000000-0000-0000-0000-3000000000c1'$$, '%partner_totp_consecutive_failed_check%',
  'A: consecutive_failed above 20 is refused (the cap CHECK)');
SELECT throws_like($$UPDATE app.partner_totp SET consecutive_failed = -1 WHERE user_id = '00000000-0000-0000-0000-3000000000c1'$$, '%partner_totp_consecutive_failed_check%',
  'A: a negative consecutive_failed is refused');
SELECT throws_like($$UPDATE app.partner_totp SET consecutive_failed = 20 WHERE user_id = '00000000-0000-0000-0000-3000000000c1'$$, '%partner_totp_hard_lock_iff_twenty%',
  'A: 20 consecutive failures WITHOUT hard_locked_at is refused (the two move together)');
SELECT throws_like($$UPDATE app.partner_totp SET hard_locked_at = now() WHERE user_id = '00000000-0000-0000-0000-3000000000c1'$$, '%partner_totp_hard_lock_iff_twenty%',
  'A: hard_locked_at WITHOUT 20 consecutive failures is refused');
SELECT lives_ok($$UPDATE app.partner_totp SET consecutive_failed = 20, hard_locked_at = now() WHERE user_id = '00000000-0000-0000-0000-3000000000c1'$$,
  'A: 20 with hard_locked_at is a valid row');
DELETE FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1';

SELECT is((SELECT array_agg(c.n ORDER BY c.n) FROM (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) c(n) WHERE has_table_privilege('partner_totp_verifier', 'app.partner_totp', c.n)),
  ARRAY['INSERT', 'SELECT', 'UPDATE'], 'A: partner_totp_verifier still holds table-level SELECT, INSERT and UPDATE only (the new columns come with it; no DELETE)');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_partner'), ('edge_partner_minter'),
                                          ('partner_pin_verifier'), ('partner_reauth_verifier'), ('private_definer')) r(n)
           CROSS JOIN (VALUES ('consecutive_failed'), ('hard_locked_at')) col(c)
           WHERE has_column_privilege(r.n, 'app.partner_totp', col.c, 'SELECT,INSERT,UPDATE,REFERENCES')), 0,
  'A: no role other than partner_totp_verifier (and the table owner) can SELECT, INSERT, UPDATE or REFERENCE the new columns');
SELECT is((has_column_privilege('partner_totp_verifier', 'app.partner_totp', 'consecutive_failed', 'UPDATE') AND has_column_privilege('partner_totp_verifier', 'app.partner_totp', 'hard_locked_at', 'UPDATE')
           AND has_column_privilege('partner_totp_verifier', 'app.partner_totp', 'consecutive_failed', 'SELECT') AND has_column_privilege('partner_totp_verifier', 'app.partner_totp', 'hard_locked_at', 'SELECT')),
  true, 'A: the verifier, the table''s only writer, can read and write them');
SELECT is((SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid = 'app.partner_totp'::regclass), true, 'A: FORCE ROW LEVEL SECURITY is still on');
SELECT is((SELECT count(*)::int FROM pg_policy WHERE polrelid = 'app.partner_totp'::regclass AND polname LIKE 'ptv\_%'), 3, 'A: the three ptv_* policies are untouched (no policy was added or dropped on partner_totp)');

-- the five redefined functions: owner, SECURITY DEFINER, search_path, volatility, ACL
SELECT is((SELECT array_agg(p.proname || ':' || pg_get_userbyid(p.proowner) || ':' || p.prosecdef::text || ':' || (p.proconfig = ARRAY['search_path=""'])::text || ':' || p.provolatile::text ORDER BY p.proname)
           FROM pg_proc p WHERE p.oid IN ('private.partner_totp_attempt(uuid, text)'::regprocedure, 'private.partner_totp_enrol_apply()'::regprocedure,
                                          'private.partner_totp_confirm_apply(text)'::regprocedure, 'private.partner_totp_reset_apply(uuid)'::regprocedure)),
  ARRAY['partner_totp_attempt:partner_totp_verifier:true:true:v', 'partner_totp_confirm_apply:partner_totp_verifier:true:true:v',
        'partner_totp_enrol_apply:partner_totp_verifier:true:true:v', 'partner_totp_reset_apply:partner_totp_verifier:true:true:v'],
  'A: the four verifier-owned writers are still owned by partner_totp_verifier, SECURITY DEFINER, search_path = '''', VOLATILE');
SELECT is((SELECT p.proowner::regrole::text || ':' || p.prosecdef::text || ':' || (p.proconfig = ARRAY['search_path=""'])::text || ':' || p.provolatile::text
           FROM pg_proc p WHERE p.oid = 'private.partner_totp_verify_for_partner(text)'::regprocedure),
  'private_definer:true:true:v', 'A: the step-up wrapper is still owned by private_definer, SECURITY DEFINER, search_path = '''', VOLATILE');
SELECT is((SELECT p.proacl::text FROM pg_proc p WHERE p.oid = 'private.partner_totp_attempt(uuid, text)'::regprocedure), '{partner_totp_verifier=X/partner_totp_verifier}',
  'A: partner_totp_attempt is executable by its owner ONLY (the ACL is untouched)');
SELECT is((SELECT count(*)::int FROM (VALUES ('private_definer'), ('edge_partner'), ('edge_actor'), ('edge_system'), ('service_role'), ('anon'), ('authenticated'), ('edge_gateway')) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_totp_attempt(uuid, text)'::regprocedure, 'EXECUTE')), 0, 'A: no other role can execute partner_totp_attempt');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('private_definer'), ('edge_partner'), ('edge_actor'), ('edge_system'), ('service_role'), ('anon'), ('authenticated'), ('edge_gateway')) r(n)
           CROSS JOIN (VALUES ('private.partner_totp_enrol_apply()'), ('private.partner_totp_confirm_apply(text)'), ('private.partner_totp_reset_apply(uuid)')) f(sig)
           WHERE has_function_privilege(r.n, f.sig::regprocedure, 'EXECUTE')),
  ARRAY['private_definer', 'private_definer', 'private_definer'], 'A: the enrol / confirm / reset writers are executable by private_definer ONLY');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('private_definer'), ('edge_partner'), ('edge_actor'), ('edge_system'), ('service_role'), ('anon'), ('authenticated'), ('edge_gateway')) r(n)
           WHERE has_function_privilege(r.n, 'private.partner_totp_verify_for_partner(text)'::regprocedure, 'EXECUTE') AND r.n <> 'private_definer'),
  ARRAY['edge_partner'], 'A: the step-up wrapper is executable by edge_partner alone (besides its owner)');
SELECT is((SELECT obj_description('private.partner_totp_enrol_apply()'::regprocedure, 'pg_proc') LIKE '0053 (PA-24, 6.4). Owned by partner_totp_verifier. Bumps seed_version%'
           AND obj_description('private.partner_totp_confirm_apply(text)'::regprocedure, 'pg_proc') LIKE '0053 (PA-24, 6.4). Owned by partner_totp_verifier. Confirms%'
           AND obj_description('private.partner_totp_attempt(uuid, text)'::regprocedure, 'pg_proc') IS NULL
           AND obj_description('private.partner_totp_reset_apply(uuid)'::regprocedure, 'pg_proc') IS NULL), true,
  'A: the writers'' comments are exactly what they were (enrol and confirm keep theirs; attempt and reset never had one)');
SELECT is((SELECT obj_description('private.partner_totp_verify_for_partner(text)'::regprocedure, 'pg_proc') ILIKE '%0108%hard lock%'), true, 'A: the wrapper comment names the hard lock');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'private' AND p.proname LIKE 'partner\_totp\_%'), 12,
  'A: no function was added (twelve partner_totp_* functions, as before)');

-- the alarm kind
SELECT throws_ok($$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket) VALUES ('totp_hard_locked', 'a5300000-0000-0000-0000-000000000086', '00000000-0000-0000-0000-3000000000c1', 1)$$,
  '23514', NULL, 'A: totp_hard_locked refuses a non-NULL credential_id (row CHECK)');
SELECT throws_ok($$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket) VALUES ('totp_hard_locked', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL, 'A: totp_hard_locked requires a uuid-text bucket_key');
SELECT lives_ok($$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket) VALUES ('totp_hard_locked', NULL, '00000000-0000-0000-0000-3000000000ff', 9986)$$,
  'A: totp_hard_locked accepts a NULL credential_id and a uuid bucket_key');
DELETE FROM app.partner_auth_alarm WHERE bucket_key = '00000000-0000-0000-0000-3000000000ff';
SELECT is((SELECT (pg_get_constraintdef(oid) LIKE '%totp_hard_locked%' AND pg_get_constraintdef(oid) LIKE '%totp_enrol%' AND pg_get_constraintdef(oid) LIKE '%signature_invalid%')
           FROM pg_constraint WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  true, 'A: the kind CHECK has the new kind and kept the old ones');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname IN ('pd_partner_totp_hard_locked_alarm_insert', 'pd_partner_totp_hard_locked_alarm_select') AND pol.polroles = ARRAY['private_definer'::regrole::oid]),
  2, 'A: the partner-bound INSERT and SELECT policies exist, for private_definer only');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name IN ('pd_partner_totp_hard_locked_alarm_insert', 'pd_partner_totp_hard_locked_alarm_select')
             AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)), 2, 'A: both policies are in the definer allow-list with their expressions derived');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('partner_totp_attempt', 'partner_totp_enrol_apply', 'partner_totp_confirm_apply', 'partner_totp_reset_apply', 'partner_totp_verify_for_partner')
             AND note LIKE '%§117%'), 5, 'A: the inventory notes of the five redefined functions name §117');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name = 'partner_totp_verify_for_partner' AND note LIKE '%§110%'), 1,
  'A: the step-up note still names §110 (matrix 82 reads it)');
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- B. THE BUG: the 15-minute lock no longer erases the count, and the 20th failure hard-locks
-- ----------------------------------------------------------------------------
SAVEPOINT bug;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 0::smallint, 0);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.fail_run('00000000-0000-0000-0000-3000000000c1', 1, 5), 'wrong,wrong,wrong,wrong,locked,', 'B: failures 1-4 are wrong and the 5th locks (the 15-minute lock is as it was)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '5,0,false,false',
  'B: THE BUG: after the 5th failure''s lock the count is 5, not 0 (failed_count is back to 0, consecutive_failed is not)');
SELECT is(pg_temp.fail_run('00000000-0000-0000-0000-3000000000c1', 1, 14),
  'wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,',
  'B: failures 6-19 across two more locks: wrong x4 then locked at the 10th and 15th, as before');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '19,4,false,false', 'B: 19 consecutive failures across three 15-minute locks are counted: 19, with failed_count 4 and no hard lock');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.hard_locked'), 0, 'B: no hard-lock audit row before the 20th');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.locked'), 3, 'B: the three soft locks wrote their partner.totp.locked audit rows, as before');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_hard_locked'), 0, 'B: no hard-lock alarm before the 20th');
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'hard_locked|0|false', 'B: the 20th consecutive failure answers hard_locked (retry_after 0, no mfa)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '20,0,true,true', 'B: the row is hard-locked (20, hard_locked_at set); failed_count is 0 and the ordinary 15-minute lock is also running');
SELECT is((SELECT locked_until > clock_timestamp() + interval '14 minutes' AND locked_until <= clock_timestamp() + interval '15 minutes' FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'),
  true, 'B: the 20th failure still starts the 15-minute lock (the 5th-of-its-group rule is unchanged)');
SELECT is((SELECT hard_locked_at BETWEEN clock_timestamp() - interval '1 minute' AND clock_timestamp() FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), true,
  'B: hard_locked_at is the time of the 20th failure');
ROLLBACK TO SAVEPOINT bug;

-- ----------------------------------------------------------------------------
-- C. A success clears the count; the thresholds are exactly 5 / 10 / 15 (soft) and 20 (hard)
-- ----------------------------------------------------------------------------
SAVEPOINT success_clears;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 0::smallint, 0);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.fail_run('00000000-0000-0000-0000-3000000000c1', 1, 19), 'wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,',
  'C: 19 failures across three locks (the cleared-by-success cell needs a count to clear)');
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'ok|0|true', 'C: the 20th ATTEMPT is the right code: ok (the 19 failures are not a hard lock)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'C: a success clears consecutive_failed (and failed_count)');
SELECT is(pg_temp.fail_run('00000000-0000-0000-0000-3000000000c1', 1, 19), 'wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,',
  'C: 19 MORE failures after the success are still plain wrongs and soft locks: 38 failures in all, no hard lock, because the success cleared the count');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '19,4,false,false', 'C: ... and the count is 19, not 38');
ROLLBACK TO SAVEPOINT success_clears;

SAVEPOINT thresholds;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 3::smallint, 3);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'wrong|0|false', 'C: the 4th consecutive failure is wrong');
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'locked|900|false', 'C: the 5th is the first soft lock (locked, retry_after 900)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '5,0,false,true', 'C: ... and leaves the count at 5');
ROLLBACK TO SAVEPOINT thresholds;

SAVEPOINT soft_15;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 4::smallint, 14);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'locked|900|false', 'C: the 15th consecutive failure is still a SOFT lock (locked|900), not the hard one');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '15,0,false,true', 'C: ... count 15, not hard-locked');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.locked'), 1, 'C: ... one partner.totp.locked audit row');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_locked'), 1, 'C: ... and the existing totp_locked alarm (the soft lock keeps its alarm)');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_hard_locked'), 0, 'C: ... and no hard-lock alarm');
ROLLBACK TO SAVEPOINT soft_15;

SAVEPOINT nineteen;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 3::smallint, 18);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'wrong|0|false', 'C: the 19th consecutive failure is a plain wrong (the threshold is not 19)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '19,4,false,false', 'C: ... count 19, no hard lock');
ROLLBACK TO SAVEPOINT nineteen;

SAVEPOINT keyed_on_consecutive;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 0::smallint, 19);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'hard_locked|0|false', 'C: the hard lock keys on consecutive_failed, not on failed_count (19 with failed_count 0 still locks on the next failure)');
ROLLBACK TO SAVEPOINT keyed_on_consecutive;

-- ----------------------------------------------------------------------------
-- D. The hard lock refuses without evaluating, records once, and is one person's
-- ----------------------------------------------------------------------------
SAVEPOINT hard;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 4::smallint, 19);
SELECT pg_temp.seed_row('00000000-0000-0000-0000-4000000000d0', 1, true, 0::smallint, 0);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'hard_locked|0|false', 'D: the 20th failure answers hard_locked');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.hard_locked'), 1, 'D: exactly ONE partner.totp.hard_locked audit row at the transition');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.locked') + pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.wrong'), 0,
  'D: ... and the 20th failure wrote no ordinary wrong / locked row besides');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_hard_locked'), 1, 'D: exactly ONE totp_hard_locked alarm at the transition');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_locked'), 0, 'D: ... and no soft totp_locked alarm for the same event');
SELECT is((SELECT detail::text FROM app.partner_auth_alarm WHERE kind = 'totp_hard_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'),
  '{"stage": "verify", "subject": "00000000-0000-0000-0000-3000000000c1"}', 'D: the alarm detail is the subject and the stage and nothing else');
SELECT is((SELECT credential_id IS NULL AND minute_bucket = floor(extract(epoch FROM clock_timestamp()) / 60)::bigint FROM app.partner_auth_alarm
           WHERE kind = 'totp_hard_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1'), true, 'D: ... credential_id NULL, keyed on the subject uid and the minute');
SELECT is((SELECT detail::text FROM app.audit_log WHERE subject_id = '00000000-0000-0000-0000-3000000000c1' AND action = 'partner.totp.hard_locked'), '{"stage": "verify"}', 'D: the audit detail is {"stage": "verify"}');
-- from here the 15-minute lock is waited out; only the hard lock remains
SELECT pg_temp.wait_out_lock('00000000-0000-0000-0000-3000000000c1');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '20,0,true,false', 'D: with the 15 minutes gone the row is STILL hard-locked');
SELECT hard_locked_at AS hl0, last_step IS NULL AS ls_null FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1' \gset
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'hard_locked|0|false', 'D: the CORRECT code on a hard-locked row is refused (hard_locked, no mfa)');
SELECT is((SELECT last_step IS NULL FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), true, 'D: ... it was NOT evaluated: last_step did not move');
SELECT is((SELECT aal::int || '|' || (mfa_until IS NULL)::text FROM app.partner_session WHERE token_hash = :'th_op'), '1|true', 'D: ... and the session is still aal 1 with no mfa_until');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '20,0,true,false', 'D: ... and no counter moved');
SELECT is((SELECT hard_locked_at = :'hl0'::timestamptz FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), true, 'D: ... hard_locked_at is exactly what it was');
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), -1)), 'hard_locked|0|false', 'D: the step-1 code is refused too');
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 1)), 'hard_locked|0|false', 'D: ... and the step+1 code');
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'hard_locked|0|false', 'D: a wrong code on a hard-locked row is hard_locked too (not wrong, not locked)');
-- the refusals recorded nothing; to prove the ALARM is not merely deduplicated by its minute, move the transition''s alarm to an earlier minute first
UPDATE app.partner_auth_alarm SET minute_bucket = minute_bucket - 10 WHERE kind = 'totp_hard_locked' AND bucket_key = '00000000-0000-0000-0000-3000000000c1';
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'hard_locked|0|false', 'D: another refusal (the alarm''s own minute is now in the past)');
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'hard_locked|0|false', 'D: ... and another');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_hard_locked'), 1, 'D: refusals raise NO further alarm (still exactly one)');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.hard_locked'), 1, 'D: ... and write no further hard-lock audit row (still exactly one)');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.wrong') + pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.locked'), 0,
  'D: ... and no wrong / locked audit row either: a loop of guesses cannot grow audit_log');
SELECT is(pg_temp.alarms('00000000-0000-0000-0000-3000000000c1', 'totp_locked'), 0, 'D: ... and raise no soft-lock alarm');
-- a second session of the same person
SET LOCAL ROLE private_definer;
UPDATE private.actor_binding SET xact = '0'::xid8 WHERE backend_pid = pg_backend_pid() AND xact = pg_current_xact_id();
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opb');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'hard_locked|0|false', 'D: a NEW session of the same person is refused the same way (the lock is on the person, not the session)');
-- another person is unaffected
SET LOCAL ROLE private_definer;
UPDATE private.actor_binding SET xact = '0'::xid8 WHERE backend_pid = pg_backend_pid() AND xact = pg_current_xact_id();
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-4000000000d0', 1), 0)), 'ok|0|true', 'D: another person''s TOTP is not affected by this person''s hard lock');
SELECT is(pg_temp.st('00000000-0000-0000-0000-4000000000d0'), '0,0,false,false', 'D: ... and keeps its own counters');
ROLLBACK TO SAVEPOINT hard;

-- ----------------------------------------------------------------------------
-- E. The way out: admin reset, re-enrol, confirm
-- ----------------------------------------------------------------------------
SAVEPOINT reset_path;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 3, true, 0::smallint, 20, true);
SELECT pg_temp.seed_row('00000000-0000-0000-0000-4000000000d0', 1, true, 0::smallint, 0);
SELECT pg_temp.seed_step('ad', '{"mfa_s": 240}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_ad');
RESET ROLE;
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '20,0,true,false', 'E: the target is hard-locked');
SELECT is(pg_temp.reset_totp('00000000-0000-0000-0000-3000000000c1'), 'ok', 'E: an admin''s reset of the hard-locked operator is ok (the existing reset route, A3, nothing new)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: the reset cleared the hard lock and the counter');
SELECT is((SELECT confirmed_at IS NULL AND seed_version = 4 AND last_step IS NULL AND locked_until IS NULL FROM app.partner_totp WHERE user_id = '00000000-0000-0000-0000-3000000000c1'), true,
  'E: ... with the rest of the reset as before: unconfirmed, seed_version bumped to 4, no replay step, no lock');
SELECT is(pg_temp.aud('00000000-0000-0000-0000-3000000000c1', 'partner.totp.reset'), 1, 'E: the reset is audited (the existing partner.totp.reset row)');
-- the person gets back in: a new session, an email proof, enrol, confirm, step up
SELECT pg_temp.mk_session('op2', '00000000-0000-0000-0000-3000000000c1', :'c_op', 1) AS s_op2 \gset
SELECT pg_temp.seed_step('op2', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE private_definer;
UPDATE private.actor_binding SET xact = '0'::xid8 WHERE backend_pid = pg_backend_pid() AND xact = pg_current_xact_id();
RESET ROLE;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op2');
RESET ROLE;
SELECT is(pg_temp.enrol(), 'ok|5', 'E: after the reset the operator can enrol again (seed_version 5)');
SELECT is(pg_temp.confirm(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 5), 0)), 'ok|0', 'E: ... confirm');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: ... with clean counters');
SELECT is(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 5), 1)), 'ok|0|true', 'E: ... and a step-up with the new seed works: the person is back at aal 2');
ROLLBACK TO SAVEPOINT reset_path;

SAVEPOINT reenrol_clears;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 2, false, 3::smallint, 20, true);
SELECT pg_temp.seed_step('opb', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opb');
RESET ROLE;
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '20,3,true,false', 'E: (a deliberately inconsistent unconfirmed row that carries a hard lock)');
SELECT is(pg_temp.enrol(), 'ok|3', 'E: a re-enrol of an unconfirmed row bumps the seed_version');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: ... and clears the counter, the hard lock and the 15-minute state with it');
ROLLBACK TO SAVEPOINT reenrol_clears;

SAVEPOINT reenrol_counter;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 2, false, 3::smallint, 7);
SELECT pg_temp.seed_step('opb', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opb');
RESET ROLE;
SELECT is(pg_temp.enrol(), 'ok|3', 'E: a re-enrol with a partial count (7, no hard lock)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: ... clears the partial count as well');
ROLLBACK TO SAVEPOINT reenrol_counter;

SAVEPOINT confirm_clears;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, false, 2::smallint, 7, false, :'s_opb'::uuid);
SELECT pg_temp.seed_step('opb', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opb');
RESET ROLE;
SELECT is(pg_temp.confirm(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'ok|0', 'E: a successful confirm');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: ... clears the counter (it was 7)');
ROLLBACK TO SAVEPOINT confirm_clears;

SAVEPOINT confirm_clears_hard;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, false, 0::smallint, 20, true, :'s_opb'::uuid);
SELECT pg_temp.seed_step('opb', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opb');
RESET ROLE;
SELECT is(pg_temp.confirm(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), 'ok|0', 'E: a successful confirm on a (deliberately inconsistent) row that carries a hard lock');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: ... clears the counter AND the hard lock together');
ROLLBACK TO SAVEPOINT confirm_clears_hard;

SAVEPOINT confirm_not_counted;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, false, 0::smallint, 0, false, :'s_opb'::uuid);
SELECT pg_temp.seed_step('opb', '{"otp_s": 500}'::jsonb);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opb');
RESET ROLE;
SELECT is(pg_temp.confirm_fail_run('00000000-0000-0000-0000-3000000000c1', 1, 20),
  'wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,wrong,wrong,wrong,wrong,locked,',
  'E: 20 wrong CONFIRM codes lock softly at 5, 10, 15 and 20 and never hard-lock (a confirm code is checked against a seed only the enrolling session was shown)');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '0,0,false,false', 'E: ... and the hard-lock counter is untouched by confirm failures');
ROLLBACK TO SAVEPOINT confirm_not_counted;

-- ----------------------------------------------------------------------------
-- F. Failures during a 15-minute lock are still not counted
-- ----------------------------------------------------------------------------
SAVEPOINT during_lock;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 4::smallint, 9);
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'locked|900|false', 'F: the 10th consecutive failure locks softly');
SELECT is(split_part(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), '|', 1), 'locked', 'F: a wrong code during the lock answers locked');
SELECT is(split_part(pg_temp.verify(pg_temp.hotp_at(pg_temp.seed_of('00000000-0000-0000-0000-3000000000c1', 1), 0)), '|', 1), 'locked', 'F: the CORRECT code during the lock is still refused');
SELECT is(pg_temp.st('00000000-0000-0000-0000-3000000000c1'), '10,0,false,true', 'F: ... and failures during the lock are not counted: still 10');
SELECT is((SELECT (split_part(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), '|', 2))::int BETWEEN 890 AND 900), true, 'F: the retry_after during the lock is the remaining time (not a fresh 900 or 0)');
ROLLBACK TO SAVEPOINT during_lock;

SAVEPOINT hard_is_not_soft;
SELECT pg_temp.seed_row('00000000-0000-0000-0000-3000000000c1', 1, true, 0::smallint, 20, true);
UPDATE app.partner_totp SET locked_until = clock_timestamp() + interval '10 minutes' WHERE user_id = '00000000-0000-0000-0000-3000000000c1';
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_op');
RESET ROLE;
SELECT is(pg_temp.verify(pg_temp.bad_code('00000000-0000-0000-0000-3000000000c1', 1)), 'hard_locked|0|false', 'F: a hard-locked row with a 15-minute lock still running answers hard_locked, not locked (the hard lock is checked first)');
ROLLBACK TO SAVEPOINT hard_is_not_soft;

SELECT is((SELECT count(*)::int FROM app.partner_totp) + (SELECT count(*)::int FROM app.partner_auth_alarm WHERE kind IN ('totp_hard_locked', 'totp_locked'))
          + (SELECT count(*)::int FROM app.audit_log WHERE action LIKE 'partner.totp.%'), 0, 'the scenarios left no trace (a rolled-back savepoint each)');
SELECT * FROM finish();
ROLLBACK;

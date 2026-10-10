-- 51_course_pin_alarm_list.sql
-- 0073_course_pin_alarm_list.sql (P5 §59): partner list of course_pin_alarm
-- rows (class A0, manager / operator at the facility).

\set QUIET 1
BEGIN;
SELECT plan(12);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.course_pin_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz51_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz51_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz51_alarm ON app.course_pin_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s51:' || p_label) || md5('s51b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c51:' || p_label) || md5('c51b:' || p_label), 'hex'),
          decode(md5('k51:' || p_label) || md5('k51b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n51:' || p_label) || md5('n51b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.list_n(p_facility text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.course_pin_alarm_list_for_partner(p_facility);
  EXECUTE 'RESET ROLE';
  RETURN n;
END
$f$;
CREATE FUNCTION pg_temp.list_first(p_facility text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.course_pin_alarm_list_for_partner(p_facility) LIMIT 1;
  EXECUTE 'RESET ROLE';
  IF r.o_id IS NULL THEN RETURN ''; END IF;
  RETURN r.o_facility_id || '|' || r.o_local_date::text || '|' || r.o_pin_epoch_before::text || '->' || r.o_pin_epoch_after::text || '|' || r.o_failures::text;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.list_n(text), pg_temp.list_first(text) TO PUBLIC;

SELECT ok(
  has_function_privilege('edge_partner', 'private.course_pin_alarm_list_for_partner(text)'::regprocedure, 'EXECUTE'),
  'privileges: edge_partner CAN run course_pin_alarm_list_for_partner'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'course_pin_alarm_list_for_partner'
     AND (has_function_privilege('edge_actor', p.oid, 'EXECUTE')
          OR has_function_privilege('edge_system', p.oid, 'EXECUTE')
          OR has_function_privilege('anon', p.oid, 'EXECUTE')
          OR has_function_privilege('authenticated', p.oid, 'EXECUTE')
          OR has_function_privilege('service_role', p.oid, 'EXECUTE'))),
  0,
  'privileges: nobody else may EXECUTE it'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'private' AND p.proname = 'course_pin_alarm_list_for_partner'
     AND p.prosecdef AND p.proowner = 'private_definer'::regrole
     AND p.proconfig = ARRAY['search_path=""']),
  1,
  'structure: SECURITY DEFINER / private_definer / search_path='''''
);
-- function_inventory is FORCE RLS; only service_role can SELECT (restricted harness).
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM private.function_inventory
   WHERE function_name = 'course_pin_alarm_list_for_partner' AND expected_edge_partner AND NOT expected_edge_system),
  1,
  'inventory: one edge_partner row'
);
SELECT tests.clear_actor();
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_course_pin_alarm_partner_select'),
  1,
  'structure: partner SELECT policy exists'
);

SELECT pg_temp.th('mgr') AS th_mgr, pg_temp.th('stf') AS th_stf, pg_temp.th('opy') AS th_opy \gset
SELECT pg_temp.mk_cred('mgr', '00000000-0000-0000-0000-2000000000b1') AS c_mgr \gset
SELECT pg_temp.mk_cred('stf', '00000000-0000-0000-0000-1000000000a1') AS c_stf \gset
SELECT pg_temp.mk_cred('opy', '00000000-0000-0000-0000-3000000000c1') AS c_opy \gset
SELECT pg_temp.mk_session('mgr', '00000000-0000-0000-0000-2000000000b1', :'c_mgr') AS s_mgr \gset
SELECT pg_temp.mk_session('stf', '00000000-0000-0000-0000-1000000000a1', :'c_stf') AS s_stf \gset
SELECT pg_temp.mk_session('opy', '00000000-0000-0000-0000-3000000000c1', :'c_opy') AS s_opy \gset
-- operators require aal 2 (M2); set after insert so the default-arg mk_session shape stays shared with mgr/stf
UPDATE app.partner_session SET aal = 2 WHERE id = :'s_opy'::uuid;

INSERT INTO app.course_pin_alarm (facility_id, local_date, pin_epoch_before, pin_epoch_after, failures, raised_at) VALUES
  ('fac_x', current_date - 2, 3, 4, 30, now() - interval '2 days'),
  ('fac_x', current_date - 1, 4, 5, 30, now() - interval '1 day'),
  ('fac_y', current_date - 1, 1, 2, 30, now() - interval '1 day');

SAVEPOINT mgr;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mgr');
RESET ROLE;
SELECT is(pg_temp.list_n('fac_x'), 2, 'manager at fac_x lists both alarms');
SELECT is(pg_temp.list_first('fac_x'),
  'fac_x|' || (current_date - 1)::text || '|4->5|30',
  'manager list is newest first');
SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  $$SELECT * FROM private.course_pin_alarm_list_for_partner('fac_y')$$,
  '42501',
  NULL,
  'manager at fac_x cannot list fac_y'
);
-- NULL facility: authorize passes the anywhere-role check for a manager, then the body refuses 22023
-- (empty string is a scope refusal at authorize — 42501 — before the body check).
SELECT throws_ok(
  $$SELECT * FROM private.course_pin_alarm_list_for_partner(NULL)$$,
  '22023',
  NULL,
  'NULL facility is 22023 after authorize'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT mgr;

SAVEPOINT stf;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_stf');
SELECT throws_ok(
  $$SELECT * FROM private.course_pin_alarm_list_for_partner('fac_x')$$,
  '42501',
  NULL,
  'staff cannot list course_pin_alarm'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT stf;

SAVEPOINT opy;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opy');
RESET ROLE;
SELECT is(pg_temp.list_n('fac_x'), 2, 'operator lists alarms at a facility their trail covers');
RESET ROLE;
ROLLBACK TO SAVEPOINT opy;

SELECT throws_ok(
  $$SELECT * FROM private.course_pin_alarm_list_for_partner('fac_x')$$,
  '42501',
  NULL,
  'without a partner binding the list is refused'
);

SELECT * FROM finish();
ROLLBACK;

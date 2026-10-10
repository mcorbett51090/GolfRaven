-- 55_course_qr_static_pin_cap_list.sql
-- 0077_course_qr_static_pin_cap_list.sql (P5 §63): partner list of open
-- course_qr_static_pin_cap fraud_signal rows (class A0, manager / operator).

\set QUIET 1
BEGIN;
SELECT plan(12);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.fraud_signal TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz55_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz55_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz55_fraud ON app.fraud_signal FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s55:' || p_label) || md5('s55b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c55:' || p_label) || md5('c55b:' || p_label), 'hex'),
          decode(md5('k55:' || p_label) || md5('k55b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n55:' || p_label) || md5('n55b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.list_n(p_facility text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.course_qr_static_pin_cap_list_for_partner(p_facility);
  EXECUTE 'RESET ROLE';
  RETURN n;
END
$f$;
CREATE FUNCTION pg_temp.list_first(p_facility text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.course_qr_static_pin_cap_list_for_partner(p_facility) LIMIT 1;
  EXECUTE 'RESET ROLE';
  IF r.o_id IS NULL THEN RETURN ''; END IF;
  RETURN r.o_facility_id || '|' || r.o_local_date::text || '|' || r.o_count::text;
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.list_n(text), pg_temp.list_first(text) TO PUBLIC;

SELECT ok(
  has_function_privilege('edge_partner', 'private.course_qr_static_pin_cap_list_for_partner(text)'::regprocedure, 'EXECUTE'),
  'privileges: edge_partner CAN run course_qr_static_pin_cap_list_for_partner'
);
SELECT is(
  (SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'course_qr_static_pin_cap_list_for_partner'
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
   WHERE n.nspname = 'private' AND p.proname = 'course_qr_static_pin_cap_list_for_partner'
     AND p.prosecdef AND p.proowner = 'private_definer'::regrole
     AND p.proconfig = ARRAY['search_path=""']),
  1,
  'structure: SECURITY DEFINER / private_definer / search_path='''''
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT count(*)::int FROM private.function_inventory
   WHERE function_name = 'course_qr_static_pin_cap_list_for_partner' AND expected_edge_partner AND NOT expected_edge_system),
  1,
  'inventory: one edge_partner row'
);
SELECT tests.clear_actor();
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_course_qr_cap_partner_select'),
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
UPDATE app.partner_session SET aal = 2 WHERE id = :'s_opy'::uuid;

INSERT INTO app.fraud_signal (user_id, kind, detail, created_at) VALUES
  ('00000000-0000-0000-0000-00000000000a', 'course_qr_static_pin_cap',
   jsonb_build_object('facilityId', 'fac_x', 'localDate', (current_date - 2)::text, 'count', 25),
   now() - interval '2 days'),
  ('00000000-0000-0000-0000-00000000000a', 'course_qr_static_pin_cap',
   jsonb_build_object('facilityId', 'fac_x', 'localDate', (current_date - 1)::text, 'count', 26),
   now() - interval '1 day'),
  ('00000000-0000-0000-0000-00000000000a', 'course_qr_static_pin_cap',
   jsonb_build_object('facilityId', 'fac_y', 'localDate', (current_date - 1)::text, 'count', 25),
   now() - interval '1 day'),
  ('00000000-0000-0000-0000-00000000000a', 'course_qr_static_pin_cap',
   jsonb_build_object('facilityId', 'fac_x', 'localDate', (current_date - 3)::text, 'count', 25),
   now() - interval '3 days');
-- cleared open unique index allows a second open-shaped row once cleared_at is set
UPDATE app.fraud_signal
SET cleared_at = now()
WHERE kind = 'course_qr_static_pin_cap'
  AND detail ->> 'facilityId' = 'fac_x'
  AND detail ->> 'localDate' = (current_date - 3)::text;

SAVEPOINT mgr;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mgr');
RESET ROLE;
SELECT is(pg_temp.list_n('fac_x'), 2, 'manager at fac_x lists both open cap alerts');
SELECT is(pg_temp.list_first('fac_x'),
  'fac_x|' || (current_date - 1)::text || '|26',
  'manager list is newest first');
SET LOCAL ROLE edge_partner;
SELECT throws_ok(
  $$SELECT * FROM private.course_qr_static_pin_cap_list_for_partner('fac_y')$$,
  '42501',
  NULL,
  'manager at fac_x cannot list fac_y'
);
SELECT throws_ok(
  $$SELECT * FROM private.course_qr_static_pin_cap_list_for_partner(NULL)$$,
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
  $$SELECT * FROM private.course_qr_static_pin_cap_list_for_partner('fac_x')$$,
  '42501',
  NULL,
  'staff cannot list course_qr_static_pin_cap'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT stf;

SAVEPOINT opy;
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_opy');
RESET ROLE;
SELECT is(pg_temp.list_n('fac_x'), 2, 'operator lists open cap alerts at a facility their trail covers');
RESET ROLE;
ROLLBACK TO SAVEPOINT opy;

SELECT throws_ok(
  $$SELECT * FROM private.course_qr_static_pin_cap_list_for_partner('fac_x')$$,
  '42501',
  NULL,
  'without a partner binding the list is refused'
);

SELECT * FROM finish();
ROLLBACK;

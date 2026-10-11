-- 69_partner_credential_add_notice.sql
-- 0091_partner_credential_add_notice.sql (P5 §92): notice table, alarm
-- kind credential_add, list mine / ack / reach, trigger on second cred.

\set QUIET 1
BEGIN;
SELECT plan(14);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_credential_add_notice, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz69_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz69_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz69_notice ON app.partner_credential_add_notice FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz69_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s69:' || p_label) || md5('s69b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid, p_via uuid DEFAULT NULL) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, created_via_credential_id)
  VALUES (p_uid, decode(md5('c69:' || p_label) || md5('c69b:' || p_label), 'hex'),
          decode(md5('k69:' || p_label) || md5('k69b:' || p_label), 'hex'), -7, p_via)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, 1, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n69:' || p_label) || md5('n69b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.add_second(p_sess_label text, p_cred_label text, p_uid uuid, p_via uuid) RETURNS uuid LANGUAGE plpgsql AS $f$
DECLARE v_id uuid;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  PERFORM private.bind_partner_session(pg_temp.th(p_sess_label));
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg, created_via_credential_id, aaguid)
  VALUES (p_uid, decode(md5('c69:' || p_cred_label) || md5('c69b:' || p_cred_label), 'hex'),
          decode(md5('k69:' || p_cred_label) || md5('k69b:' || p_cred_label), 'hex'), -7, p_via,
          'abababab-abab-abab-abab-abababababab'::uuid)
  RETURNING id INTO v_id;
  EXECUTE 'RESET ROLE';
  RETURN v_id;
END
$f$;
CREATE FUNCTION pg_temp.mine_cnt() RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.partner_credential_add_notice_list_mine_for_partner();
  EXECUTE 'RESET ROLE';
  RETURN n;
END
$f$;
CREATE FUNCTION pg_temp.reach_cnt() RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT count(*)::int INTO n FROM private.partner_credential_add_notice_list_reach_for_partner();
  EXECUTE 'RESET ROLE';
  RETURN n;
END
$f$;
CREATE FUNCTION pg_temp.ack(p_id uuid) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE s text;
BEGIN
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT o_status INTO s FROM private.partner_credential_add_notice_ack_for_partner(p_id);
  EXECUTE 'RESET ROLE';
  RETURN s;
END
$f$;
CREATE FUNCTION pg_temp.reach_staff_fail() RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  SET LOCAL ROLE edge_partner;
  PERFORM private.bind_partner_session(pg_temp.th('sx'));
  PERFORM * FROM private.partner_credential_add_notice_list_reach_for_partner();
  RESET ROLE;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure + inventory
-- ----------------------------------------------------------------------------
SELECT has_table('app', 'partner_credential_add_notice', 'structure: notice table exists');
SELECT ok(
  (SELECT count(*)::int = 1 FROM pg_trigger t
   JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relname = 'partner_credential' AND t.tgname = 'partner_credential_add_notice_trg'),
  'structure: AFTER INSERT trigger on partner_credential'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§92%' OR note LIKE '%credential-add%'
   FROM private.function_inventory
   WHERE function_name = 'partner_credential_add_notice_list_mine_for_partner'),
  'inventory: list_mine registered'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%credential_add%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes credential_add'
);
SELECT tests.clear_actor();

-- ----------------------------------------------------------------------------
-- 2. Behaviour: first cred no notice; second cred notice + alarm
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('sx', '00000000-0000-0000-0000-1000000000a1') AS c_sx \gset
SELECT pg_temp.mk_session('sx', '00000000-0000-0000-0000-1000000000a1', :'c_sx') AS s_sx \gset
SELECT is((SELECT count(*)::int FROM app.partner_credential_add_notice), 0,
  'first credential (no created_via) creates no notice');
SELECT pg_temp.add_second('sx', 'sx2', '00000000-0000-0000-0000-1000000000a1'::uuid, :'c_sx'::uuid) AS c_sx2 \gset
SELECT is((SELECT count(*)::int FROM app.partner_credential_add_notice WHERE credential_id = :'c_sx2'::uuid), 1,
  'second credential creates exactly one notice');
SELECT is((SELECT count(*)::int FROM app.partner_auth_alarm WHERE kind = 'credential_add' AND credential_id = :'c_sx2'::uuid), 1,
  'second credential raises credential_add alarm');
SELECT is((SELECT detail ->> 'subject' FROM app.partner_auth_alarm WHERE kind = 'credential_add' AND credential_id = :'c_sx2'::uuid),
  '00000000-0000-0000-0000-1000000000a1',
  'alarm detail names subject only');

SAVEPOINT mine_ack;
SELECT pg_temp.th('sx') AS th_sx \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_sx');
RESET ROLE;
SELECT is(pg_temp.mine_cnt(), 1, 'list_mine: subject sees one unacked notice');
SELECT is(pg_temp.ack((SELECT id FROM app.partner_credential_add_notice WHERE credential_id = :'c_sx2'::uuid)), 'ok', 'ack: subject ok');
SELECT is(pg_temp.ack((SELECT id FROM app.partner_credential_add_notice WHERE credential_id = :'c_sx2'::uuid)), 'already_acked', 'ack: already_acked');
SELECT is(pg_temp.mine_cnt(), 0, 'list_mine: empty after ack');
ROLLBACK TO SAVEPOINT mine_ack;

-- reach: re-seed notice (rollback cleared ack path data for notice row still there from before savepoint? mine_ack rollback restores unacked)
SAVEPOINT reach;
SELECT pg_temp.mk_cred('mx', '00000000-0000-0000-0000-2000000000b1') AS c_mx \gset
SELECT pg_temp.mk_session('mx', '00000000-0000-0000-0000-2000000000b1', :'c_mx') AS s_mx \gset
SELECT pg_temp.add_second('mx', 'mx2', '00000000-0000-0000-0000-2000000000b1'::uuid, :'c_mx'::uuid) AS c_mx2 \gset
SELECT pg_temp.th('mx') AS th_mx \gset
SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_mx');
RESET ROLE;
SELECT is(pg_temp.reach_cnt(), 1, 'manager@X sees staff@X unacked notice on reach list');
SELECT throws_ok($$SELECT pg_temp.reach_staff_fail()$$, '42501', NULL,
  'staff cannot call list_reach (manager|operator only)');
ROLLBACK TO SAVEPOINT reach;

SELECT * FROM finish();
ROLLBACK;

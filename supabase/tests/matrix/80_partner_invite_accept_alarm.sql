-- 80_partner_invite_accept_alarm.sql
-- 0102_partner_invite_accept_alarm.sql (P5 §108): kind invite_accept on
-- partner_auth_alarm raised when partner_invite.accepted_at first becomes
-- non-NULL (branch E accept + unbound first-accept UPDATE). Proved here:
-- kind/row CHECKs, policies, branch E ok raises one row per invite per
-- minute, quiet statuses, ON CONFLICT quiet, unbound path, inventory.

\set QUIET 1
BEGIN;
SELECT plan(22);

GRANT edge_partner, private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_credential, app.partner_session, app.partner_invite, app.partner_member, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz80_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz80_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz80_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz80_mem ON app.partner_member FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz80_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s80:' || p_label) || md5('s80b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('h80:' || p_label, 'UTF8')), 'hex')
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (p_uid, decode(md5('c80:' || p_label) || md5('c80b:' || p_label), 'hex'),
          decode(md5('k80:' || p_label) || md5('k80b:' || p_label), 'hex'), -7)
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_session(p_label text, p_uid uuid, p_cred uuid, p_aal int DEFAULT 1) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_session (token_hash, user_id, credential_id, aal, created_at, last_seen_at, expires_at,
                                   mint_kind, mint_nonce_hash, mint_authenticator_data, mint_client_data_json, mint_signature)
  VALUES (pg_temp.th(p_label), p_uid, p_cred, p_aal, now() - interval '1 hour', now(), now() + interval '7 hours', 'sign_in',
          decode(md5('n80:' || p_label) || md5('n80b:' || p_label), 'hex'), decode(repeat('04', 40), 'hex'),
          convert_to('{}', 'UTF8'), decode(repeat('05', 70), 'hex'))
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.seed_a2(p_label text) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET CONSTRAINTS ALL IMMEDIATE';
  EXECUTE 'ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg';
  UPDATE app.partner_session s SET
    pin_grant_until = clock_timestamp() + interval '55 seconds',
    reauth_until = clock_timestamp() + interval '240 seconds',
    mfa_until = clock_timestamp() + interval '240 seconds'
  WHERE s.token_hash = pg_temp.th(p_label);
  EXECUTE 'ALTER TABLE app.partner_session ENABLE TRIGGER partner_session_guard_trg';
END
$f$;
CREATE FUNCTION pg_temp.mk_inv(p_label text, p_org uuid, p_role app.partner_role, p_email text) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, expires_at, created_at)
  VALUES (
    p_org, p_role,
    CASE WHEN p_org = '10000000-0000-0000-0000-000000000001' THEN 'fac_x'
         WHEN p_org = '10000000-0000-0000-0000-000000000002' THEN 'fac_y' END,
    '00000000-0000-0000-0000-2000000000b1', p_email, pg_temp.hh(p_label),
    now() + interval '72 hours', now()
  )
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.accept_e(p_label text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  PERFORM pg_temp.seed_a2('em');
  EXECUTE 'SET LOCAL ROLE edge_partner';
  SELECT * INTO r FROM private.partner_invite_accept_for_partner(pg_temp.hh(p_label));
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || ':' || coalesce(r.o_org_id::text, '');
END
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_inv uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'invite_accept',
    NULL,
    p_inv::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('invite', p_inv::text, 'org', '10000000-0000-0000-0000-000000000002', 'role', 'staff', 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.th(text), pg_temp.hh(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_session(text, uuid, uuid, int),
  pg_temp.seed_a2(text), pg_temp.mk_inv(text, uuid, app.partner_role, text), pg_temp.accept_e(text), pg_temp.force_alarm(uuid) TO PUBLIC;

-- Confirmed mailbox at facility X (helpers staff-x has no email_confirmed_at; accept_core requires it).
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email, email_confirmed_at)
VALUES ('ee800000-0000-0000-0000-000000000009', 'em-80@example.test', now());
RESET ROLE;
INSERT INTO app.partner_member (user_id, org_id, role, invited_by)
VALUES ('ee800000-0000-0000-0000-000000000009', '10000000-0000-0000-0000-000000000001', 'staff', NULL);

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_accept', 'a5300000-0000-0000-0000-000000000080', 'a5300000-0000-0000-0000-000000000080', 1)$$,
  '23514', NULL,
  'invite_accept refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_accept', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'invite_accept requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('invite_accept', NULL, 'a5300000-0000-0000-0000-0000000000ff', 9802)$$,
  'invite_accept accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%invite_accept%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes invite_accept'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname IN ('pd_partner_invite_accept_alarm_insert', 'pd_partner_invite_accept_alarm_select')),
  2,
  'structure: partner-bound invite_accept INSERT + SELECT policies'
);
SELECT ok(
  (SELECT count(*)::int = 1 FROM pg_trigger t
   JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relname = 'partner_invite'
     AND t.tgname = 'partner_invite_accept_alarm_trg' AND NOT t.tgisinternal),
  'structure: partner_invite_accept_alarm_trg exists'
);

-- ----------------------------------------------------------------------------
-- 2. Unbound first-accept UPDATE (branch N binding shape) — before any bind
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_inv('n1', '10000000-0000-0000-0000-000000000001', 'staff', 'newbie-80@example.test') AS inv_n1 \gset
UPDATE app.partner_invite
SET accepted_at = clock_timestamp(), accepted_by = 'ee800000-0000-0000-0000-000000000009', attempts = 1
WHERE id = :'inv_n1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_n1'),
  1,
  'unbound first accept UPDATE raises invite_accept (0048 binding-NULL policies)'
);

-- ----------------------------------------------------------------------------
-- 3. Branch E accept raises alarm; quiet statuses; ON CONFLICT quiet
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_cred('em', 'ee800000-0000-0000-0000-000000000009') AS c_em \gset
SELECT pg_temp.mk_session('em', 'ee800000-0000-0000-0000-000000000009', :'c_em') AS s_em \gset
SELECT pg_temp.th('em') AS th_em \gset

SET LOCAL ROLE edge_partner;
SELECT private.bind_partner_session(:'th_em');
RESET ROLE;

SELECT pg_temp.mk_inv('e1', '10000000-0000-0000-0000-000000000002', 'staff', 'em-80@example.test') AS inv_e1 \gset
SELECT is(pg_temp.accept_e('e1'), 'ok:10000000-0000-0000-0000-000000000002',
  'branch E: confirmed member accepts facility-Y staff invite → ok');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  1,
  'accept raises one invite_accept alarm keyed on invite id'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  true,
  'invite_accept leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'invite' FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  :'inv_e1',
  'detail.invite is the invite id'
);
SELECT is(
  (SELECT detail ->> 'org' FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  '10000000-0000-0000-0000-000000000002',
  'detail.org is the invite org'
);
SELECT is(
  (SELECT detail ->> 'role' FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  'staff',
  'detail.role is the grant role'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  'ee800000-0000-0000-0000-000000000009',
  'detail.subject is accepted_by'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  'ok',
  'detail.status is ok'
);

SELECT pg_temp.mk_inv('e2', '10000000-0000-0000-0000-000000000002', 'staff', 'forwardee-80@example.test') AS inv_e2 \gset
SELECT is(split_part(pg_temp.accept_e('e2'), ':', 1), 'email_mismatch',
  'email_mismatch stays a status');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e2'),
  0,
  'email_mismatch does not raise invite_accept'
);

SELECT pg_temp.mk_inv('e3', '10000000-0000-0000-0000-000000000001', 'staff', 'em-80@example.test') AS inv_e3 \gset
SELECT is(split_part(pg_temp.accept_e('e3'), ':', 1), 'already_member',
  'already_member stays a status');
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e3'),
  0,
  'already_member does not raise invite_accept'
);

SELECT lives_ok(
  format($$SELECT pg_temp.force_alarm(%L::uuid)$$, :'inv_e1'),
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'invite_accept' AND bucket_key = :'inv_e1'),
  1,
  'ON CONFLICT keeps a single invite_accept row per minute'
);

-- ----------------------------------------------------------------------------
-- 4. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§108%' OR note LIKE '%invite_accept%'
   FROM private.function_inventory
   WHERE function_name = 'partner_invite_accept_alarm_on_update'),
  'function_inventory note mentions §108 / invite_accept'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

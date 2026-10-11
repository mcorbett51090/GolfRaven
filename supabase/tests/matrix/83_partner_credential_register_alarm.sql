-- 83_partner_credential_register_alarm.sql
-- 0105_partner_credential_register_alarm.sql (P5 §111): kind credential_register
-- on partner_auth_alarm raised when registered_credential_id first becomes
-- non-NULL on partner_invite or partner_enrolment_token (minter-lane
-- register_first). Proved here: mint-shaped kind/row CHECKs, no partner-bound
-- policies (0048 unbound), invite + enrolment first-set raise one row per
-- credential per minute, accept/consume-only stay quiet for this kind,
-- ON CONFLICT quiet, inventory.

\set QUIET 1
BEGIN;
SELECT plan(22);

GRANT private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_invite, app.partner_enrolment_token, app.partner_credential, app.partner_auth_alarm TO CURRENT_USER;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
CREATE POLICY zz83_inv ON app.partner_invite FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz83_tok ON app.partner_enrolment_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz83_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz83_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('h83:' || p_label, 'UTF8')), 'hex')
$f$;
CREATE FUNCTION pg_temp.mk_cred(p_label text, p_uid uuid) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_credential (user_id, credential_id, public_key, alg)
  VALUES (
    p_uid,
    decode(md5('c83:' || p_label) || md5('c83b:' || p_label), 'hex'),
    decode(md5('k83:' || p_label) || md5('k83b:' || p_label), 'hex'),
    -7
  )
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_inv(p_label text, p_email text) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, expires_at, created_at)
  VALUES (
    '10000000-0000-0000-0000-000000000001', 'staff', 'fac_x',
    '00000000-0000-0000-0000-2000000000b1', p_email, pg_temp.hh(p_label),
    now() + interval '72 hours', now()
  )
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.mk_tok(p_label text, p_uid uuid, p_purpose text) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at)
  VALUES (
    p_uid, p_purpose, '00000000-0000-0000-0000-4000000000d0', pg_temp.hh(p_label),
    now(), now() + interval '24 hours'
  )
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_cred uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'credential_register',
    p_cred,
    p_cred::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('credential', p_cred::text, 'subject', 'ee830000-0000-0000-0000-000000000001', 'source', 'invite', 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.hh(text), pg_temp.mk_cred(text, uuid), pg_temp.mk_inv(text, text),
  pg_temp.mk_tok(text, uuid, text), pg_temp.force_alarm(uuid) TO PUBLIC;

SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email, email_confirmed_at)
VALUES
  ('ee830000-0000-0000-0000-000000000001', 'reg-83a@example.test', now()),
  ('ee830000-0000-0000-0000-000000000002', 'reg-83b@example.test', now());
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('credential_register', NULL, 'a5300000-0000-0000-0000-000000000083', 1)$$,
  '23514', NULL,
  'credential_register refuses a NULL credential_id (mint-shaped row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('credential_register', 'a5300000-0000-0000-0000-000000000083', 'not-matching', 1)$$,
  '23514', NULL,
  'credential_register requires bucket_key = credential_id::text'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('credential_register', 'a5300000-0000-0000-0000-0000000000ff', 'a5300000-0000-0000-0000-0000000000ff', 9905)$$,
  'credential_register accepts mint-shaped credential_id + bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%credential_register%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes credential_register'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname LIKE 'pd_partner_credential_register_alarm_%'),
  0,
  'structure: no partner-bound credential_register policies (minter unbound)'
);
SELECT ok(
  (SELECT count(*)::int = 1 FROM pg_trigger t
   JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relname = 'partner_invite'
     AND t.tgname = 'partner_invite_credential_register_alarm_trg' AND NOT t.tgisinternal),
  'structure: partner_invite_credential_register_alarm_trg exists'
);
SELECT ok(
  (SELECT count(*)::int = 1 FROM pg_trigger t
   JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relname = 'partner_enrolment_token'
     AND t.tgname = 'partner_enrolment_credential_register_alarm_trg' AND NOT t.tgisinternal),
  'structure: partner_enrolment_credential_register_alarm_trg exists'
);

-- ----------------------------------------------------------------------------
-- 2. Invite path: accept-only quiet; first register raises; detail; ON CONFLICT
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_inv('i1', 'reg-83a@example.test') AS inv_i1 \gset
SELECT pg_temp.mk_cred('c1', 'ee830000-0000-0000-0000-000000000001') AS cred_c1 \gset

UPDATE app.partner_invite
SET accepted_at = clock_timestamp(), accepted_by = 'ee830000-0000-0000-0000-000000000001'
WHERE id = :'inv_i1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  0,
  'accept-only UPDATE does not raise credential_register'
);

UPDATE app.partner_invite
SET registered_credential_id = :'cred_c1'
WHERE id = :'inv_i1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  1,
  'first invite registered_credential_id UPDATE raises credential_register'
);
SELECT is(
  (SELECT credential_id::text FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  :'cred_c1',
  'credential_register stores the registered credential id'
);
SELECT is(
  (SELECT detail ->> 'source' FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  'invite',
  'detail.source is invite'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  'ee830000-0000-0000-0000-000000000001',
  'detail.subject is accepted_by'
);
SELECT is(
  (SELECT detail ->> 'invite' FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  :'inv_i1',
  'detail.invite is the invite id'
);

SELECT lives_ok(
  format($$SELECT pg_temp.force_alarm(%L::uuid)$$, :'cred_c1'),
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c1'),
  1,
  'ON CONFLICT keeps a single credential_register row per minute'
);

-- ----------------------------------------------------------------------------
-- 3. Enrolment path: consume-only quiet; first register raises
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_tok('t1', 'ee830000-0000-0000-0000-000000000002', 'admin') AS tok_t1 \gset
SELECT pg_temp.mk_cred('c2', 'ee830000-0000-0000-0000-000000000002') AS cred_c2 \gset

UPDATE app.partner_enrolment_token
SET consumed_at = clock_timestamp()
WHERE id = :'tok_t1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c2'),
  0,
  'consume-only UPDATE does not raise credential_register'
);

UPDATE app.partner_enrolment_token
SET registered_credential_id = :'cred_c2'
WHERE id = :'tok_t1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c2'),
  1,
  'first enrolment registered_credential_id UPDATE raises credential_register'
);
SELECT is(
  (SELECT detail ->> 'source' FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c2'),
  'enrolment',
  'detail.source is enrolment'
);
SELECT is(
  (SELECT detail ->> 'purpose' FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c2'),
  'admin',
  'detail.purpose is the token purpose'
);
SELECT is(
  (SELECT detail ->> 'token' FROM app.partner_auth_alarm
   WHERE kind = 'credential_register' AND bucket_key = :'cred_c2'),
  :'tok_t1',
  'detail.token is the enrolment token id'
);

-- ----------------------------------------------------------------------------
-- 4. Inventory notes
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§111%' OR note LIKE '%credential_register%'
   FROM private.function_inventory
   WHERE function_name = 'partner_invite_credential_register_alarm_on_update'),
  'function_inventory note for invite trigger mentions §111 / credential_register'
);
SELECT ok(
  (SELECT note LIKE '%§111%' OR note LIKE '%credential_register%'
   FROM private.function_inventory
   WHERE function_name = 'partner_enrolment_credential_register_alarm_on_update'),
  'function_inventory note for enrolment trigger mentions §111 / credential_register'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

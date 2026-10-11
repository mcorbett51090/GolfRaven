-- 81_partner_enrolment_accept_alarm.sql
-- 0103_partner_enrolment_accept_alarm.sql (P5 §109): kind enrolment_accept on
-- partner_auth_alarm raised when partner_enrolment_token.consumed_at first
-- becomes non-NULL (minter-lane accept). Proved here: kind/row CHECKs, no
-- partner-bound policies (0048 unbound), first consume raises one row per
-- token per minute, attempts-only stays quiet, ON CONFLICT quiet, inventory.

\set QUIET 1
BEGIN;
SELECT plan(17);

GRANT private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_enrolment_token, app.partner_auth_alarm TO CURRENT_USER;
CREATE POLICY zz81_tok ON app.partner_enrolment_token FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz81_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE FUNCTION pg_temp.hh(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT encode(sha256(convert_to('h81:' || p_label, 'UTF8')), 'hex')
$f$;
CREATE FUNCTION pg_temp.mk_tok(p_label text, p_uid uuid, p_purpose text) RETURNS uuid LANGUAGE sql AS $f$
  INSERT INTO app.partner_enrolment_token (user_id, purpose, issued_by, token_hash, created_at, expires_at)
  VALUES (
    p_uid, p_purpose, '00000000-0000-0000-0000-4000000000d0', pg_temp.hh(p_label),
    now(), now() + interval '24 hours'
  )
  RETURNING id
$f$;
CREATE FUNCTION pg_temp.force_alarm(p_tok uuid) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  EXECUTE 'SET LOCAL ROLE private_definer';
  INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket, detail)
  VALUES (
    'enrolment_accept',
    NULL,
    p_tok::text,
    floor(date_part('epoch', clock_timestamp()) / 60)::bigint,
    jsonb_build_object('token', p_tok::text, 'purpose', 'admin', 'subject', 'ee810000-0000-0000-0000-000000000001', 'status', 'ok')
  )
  ON CONFLICT (kind, bucket_key, minute_bucket) DO NOTHING;
  EXECUTE 'RESET ROLE';
END
$f$;
GRANT EXECUTE ON FUNCTION pg_temp.hh(text), pg_temp.mk_tok(text, uuid, text), pg_temp.force_alarm(uuid) TO PUBLIC;

-- Confirmed admin target (helpers seed d0; this uid is token subject only).
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id, email, email_confirmed_at)
VALUES ('ee810000-0000-0000-0000-000000000001', 'enr-81@example.test', now());
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Kind / row CHECKs + structure
-- ----------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('enrolment_accept', 'a5300000-0000-0000-0000-000000000081', 'a5300000-0000-0000-0000-000000000081', 1)$$,
  '23514', NULL,
  'enrolment_accept refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('enrolment_accept', NULL, 'not-a-uuid', 1)$$,
  '23514', NULL,
  'enrolment_accept requires uuid-text bucket_key'
);
SELECT lives_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('enrolment_accept', NULL, 'a5300000-0000-0000-0000-0000000000ff', 9803)$$,
  'enrolment_accept accepts NULL credential_id + uuid bucket_key'
);
SELECT ok(
  (SELECT pg_get_constraintdef(oid) LIKE '%enrolment_accept%'
   FROM pg_constraint
   WHERE conname = 'partner_auth_alarm_kind_check' AND conrelid = 'app.partner_auth_alarm'::regclass),
  'structure: alarm kind CHECK includes enrolment_accept'
);
SELECT is(
  (SELECT count(*)::int FROM pg_policy pol
   WHERE pol.polname LIKE 'pd_partner_enrolment_accept_alarm_%'),
  0,
  'structure: no partner-bound enrolment_accept policies (minter unbound)'
);
SELECT ok(
  (SELECT count(*)::int = 1 FROM pg_trigger t
   JOIN pg_class c ON c.oid = t.tgrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relname = 'partner_enrolment_token'
     AND t.tgname = 'partner_enrolment_accept_alarm_trg' AND NOT t.tgisinternal),
  'structure: partner_enrolment_accept_alarm_trg exists'
);

-- ----------------------------------------------------------------------------
-- 2. Attempts-only quiet; first consume raises; detail shape; ON CONFLICT
-- ----------------------------------------------------------------------------
SELECT pg_temp.mk_tok('t1', 'ee810000-0000-0000-0000-000000000001', 'admin') AS tok_t1 \gset

UPDATE app.partner_enrolment_token SET attempts = attempts + 1 WHERE id = :'tok_t1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  0,
  'attempts-only UPDATE does not raise enrolment_accept'
);

UPDATE app.partner_enrolment_token
SET consumed_at = clock_timestamp()
WHERE id = :'tok_t1';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  1,
  'first consume UPDATE raises enrolment_accept (0048 binding-NULL policies)'
);
SELECT is(
  (SELECT credential_id IS NULL FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  true,
  'enrolment_accept leaves credential_id NULL'
);
SELECT is(
  (SELECT detail ->> 'token' FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  :'tok_t1',
  'detail.token is the enrolment token id'
);
SELECT is(
  (SELECT detail ->> 'purpose' FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  'admin',
  'detail.purpose is the token purpose'
);
SELECT is(
  (SELECT detail ->> 'subject' FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  'ee810000-0000-0000-0000-000000000001',
  'detail.subject is the token user_id'
);
SELECT is(
  (SELECT detail ->> 'status' FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  'ok',
  'detail.status is ok'
);

SELECT pg_temp.mk_tok('t2', 'ee810000-0000-0000-0000-000000000001', 'recover') AS tok_t2 \gset
UPDATE app.partner_enrolment_token SET attempts = 3 WHERE id = :'tok_t2';
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t2'),
  0,
  'quiet path on a second token still raises nothing until consume'
);

SELECT lives_ok(
  format($$SELECT pg_temp.force_alarm(%L::uuid)$$, :'tok_t1'),
  'forced re-insert in the same minute is ON CONFLICT DO NOTHING'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'enrolment_accept' AND bucket_key = :'tok_t1'),
  1,
  'ON CONFLICT keeps a single enrolment_accept row per minute'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory note
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT ok(
  (SELECT note LIKE '%§109%' OR note LIKE '%enrolment_accept%'
   FROM private.function_inventory
   WHERE function_name = 'partner_enrolment_accept_alarm_on_update'),
  'function_inventory note mentions §109 / enrolment_accept'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

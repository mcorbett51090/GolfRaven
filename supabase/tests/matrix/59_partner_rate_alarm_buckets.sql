-- 59_partner_rate_alarm_buckets.sql
-- 0081_partner_rate_alarm_buckets.sql (P5 §68): IP/global alert-only rate
-- buckets on partner_auth_alarm. Proved here: kind/row CHECKs, UNIQUE
-- (kind, bucket_key, minute_bucket), EXECUTE surface, bound refuse, mint
-- writer still works, inventory.

\set QUIET 1
BEGIN;
SELECT plan(23);

GRANT edge_partner_minter, edge_partner, edge_actor, edge_system, partner_session_issuer, private_definer
  TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_auth_alarm, app.audit_log TO CURRENT_USER;
CREATE POLICY zz59_alarm ON app.partner_auth_alarm FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz59_audit ON app.audit_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

-- ----------------------------------------------------------------------------
-- 1. Shape: column, UNIQUE, CHECKs
-- ----------------------------------------------------------------------------
SELECT has_column('app', 'partner_auth_alarm', 'bucket_key', 'partner_auth_alarm has bucket_key');
SELECT is((SELECT a.attnotnull FROM pg_attribute a
           WHERE a.attrelid = 'app.partner_auth_alarm'::regclass AND a.attname = 'bucket_key'),
  true, 'bucket_key is NOT NULL');
SELECT is((SELECT a.attnotnull FROM pg_attribute a
           WHERE a.attrelid = 'app.partner_auth_alarm'::regclass AND a.attname = 'credential_id'),
  false, 'credential_id is nullable (rate kinds)');
SELECT is((SELECT count(*)::int FROM pg_constraint k
           WHERE k.conrelid = 'app.partner_auth_alarm'::regclass
             AND k.conname = 'partner_auth_alarm_kind_bucket_key_minute_bucket_key'
             AND k.contype = 'u'), 1,
  'UNIQUE (kind, bucket_key, minute_bucket)');
SELECT is((SELECT count(*)::int FROM pg_constraint k
           WHERE k.conrelid = 'app.partner_auth_alarm'::regclass
             AND k.conname = 'partner_auth_alarm_kind_credential_id_minute_bucket_key'), 0,
  'old UNIQUE (kind, credential_id, minute_bucket) is gone');

SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('rate_options_ip', 'a5300000-0000-0000-0000-000000000001', repeat('ab', 32), 1)$$,
  '23514', NULL,
  'rate kind refuses a non-NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('signature_invalid', NULL, 'orphan', 1)$$,
  '23514', NULL,
  'mint kind refuses NULL credential_id (row CHECK)'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('signature_invalid', 'a5300000-0000-0000-0000-000000000001', 'not-the-uuid', 1)$$,
  '23514', NULL,
  'mint kind requires bucket_key = credential_id::text'
);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('not_a_kind', NULL, 'global', 1)$$,
  '23514', NULL,
  'unknown kind is refused by kind CHECK'
);

INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
VALUES ('rate_options_global', NULL, 'global', 9001);
SELECT throws_ok(
  $$INSERT INTO app.partner_auth_alarm (kind, credential_id, bucket_key, minute_bucket)
    VALUES ('rate_options_global', NULL, 'global', 9001)$$,
  '23505', NULL,
  'duplicate (kind, bucket_key, minute_bucket) is refused'
);

-- ----------------------------------------------------------------------------
-- 2. EXECUTE + bound refuse + raise + mint writer
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n)
   FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'),
                ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
   WHERE has_function_privilege(r.n, 'private.partner_rate_alarm_raise(text, text, jsonb)'::regprocedure, 'EXECUTE')),
  ARRAY['edge_partner_minter'],
  'EXECUTE: only edge_partner_minter may run partner_rate_alarm_raise'
);

SELECT is(
  (SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole
   FROM pg_proc p WHERE p.oid = 'private.partner_rate_alarm_raise(text, text, jsonb)'::regprocedure),
  true,
  'partner_rate_alarm_raise is SECURITY DEFINER search_path='''' owned by private_definer'
);

SAVEPOINT sp_bound;
SELECT lives_ok($$SET LOCAL ROLE edge_actor; SELECT private.bind_actor('00000000-0000-0000-0000-00000000000a')$$,
  'setup: bind a user so partner_binding_kind() is not NULL');
RESET ROLE;
SELECT throws_ok(
  $$SET LOCAL ROLE edge_partner_minter; SELECT private.partner_rate_alarm_raise('rate_options_ip', repeat('11', 32), '{"stage":"t"}'::jsonb)$$,
  '42501', NULL,
  'partner_rate_alarm_raise refuses inside a bound transaction'
);
RESET ROLE;
ROLLBACK TO SAVEPOINT sp_bound;

SET LOCAL ROLE edge_partner_minter;
SELECT lives_ok(
  $$SELECT private.partner_rate_alarm_raise('rate_options_ip', repeat('11', 32), '{"stage":"options"}'::jsonb)$$,
  'unbound minter can raise rate_options_ip'
);
SELECT lives_ok(
  $$SELECT private.partner_rate_alarm_raise('rate_options_ip', repeat('11', 32), '{"stage":"options"}'::jsonb)$$,
  'second raise in the same minute is ON CONFLICT DO NOTHING'
);
RESET ROLE;

SELECT is(
  (SELECT count(*)::int FROM app.partner_auth_alarm
   WHERE kind = 'rate_options_ip' AND bucket_key = repeat('11', 32)),
  1,
  'one rate alarm row per (kind, bucket_key, minute)'
);
SELECT is(
  (SELECT count(*)::int FROM app.audit_log WHERE action = 'partner.rate.rate_options_ip'),
  1,
  'audit_log partner.rate.<kind> only when the alarm row is new'
);

SELECT throws_ok(
  $$SET LOCAL ROLE edge_partner_minter; SELECT private.partner_rate_alarm_raise('signature_invalid', repeat('22', 32), '{}'::jsonb)$$,
  '22023', NULL,
  'rate raiser refuses mint kinds'
);
SELECT throws_ok(
  $$SET LOCAL ROLE edge_partner_minter; SELECT private.partner_rate_alarm_raise('rate_options_ip', 'GLOBAL', '{}'::jsonb)$$,
  '22023', NULL,
  'rate raiser refuses non-lowercase / non-hex bucket_key'
);

SET LOCAL ROLE partner_session_issuer;
SELECT lives_ok(
  $$SELECT private.partner_mint_alarm_write('signature_invalid', 'a5300000-0000-0000-0000-000000000059', '{"stage":"mint"}'::jsonb)$$,
  'partner_mint_alarm_write still writes after 0081'
);
RESET ROLE;
SELECT is(
  (SELECT bucket_key = credential_id::text AND credential_id IS NOT NULL
   FROM app.partner_auth_alarm
   WHERE credential_id = 'a5300000-0000-0000-0000-000000000059'),
  true,
  'mint writer sets bucket_key = credential_id::text'
);

-- ----------------------------------------------------------------------------
-- 3. Inventory
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT expected_edge_partner_minter AND NOT expected_edge_partner AND NOT expected_edge_system
   FROM private.function_inventory WHERE function_name = 'partner_rate_alarm_raise'),
  true,
  'function_inventory: partner_rate_alarm_raise expected_edge_partner_minter=true'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

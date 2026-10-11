-- 65_partner_pin_pepper_rotate.sql
-- 0087_partner_pin_pepper_rotate.sql (P5 §77): operator partner-PIN pepper
-- rotation + dual-verify / lazy rewrap. Proved here: non_compromise
-- (previous + epoch + kid), refuse second non_compromise, verify under
-- previous then rewrap, compromise (old fails), retire_previous
-- (too_early / ok), ACL, inventory.

\set QUIET 1
BEGIN;
SELECT plan(30);

GRANT private_definer, partner_pin_verifier, edge_partner TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON vault.secrets TO CURRENT_USER;
GRANT SELECT ON vault.decrypted_secrets TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.partner_pin, app.partner_pin_pepper_epoch, app.audit_log,
  app.partner_session, app.partner_credential TO CURRENT_USER;
CREATE POLICY zz65_pin ON app.partner_pin FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz65_ppv ON app.partner_pin FOR ALL TO partner_pin_verifier USING (true) WITH CHECK (true);
CREATE POLICY zz65_epoch ON app.partner_pin_pepper_epoch FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz65_audit ON app.audit_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz65_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz65_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_insert_guard_trg;
ALTER TABLE app.partner_credential DISABLE TRIGGER partner_credential_insert_guard_trg;
ALTER TABLE app.partner_session DISABLE TRIGGER partner_session_guard_trg;

CREATE FUNCTION pg_temp.th(p_label text) RETURNS text LANGUAGE sql IMMUTABLE AS $f$
  SELECT md5('s65:' || p_label) || md5('s65b:' || p_label)
$f$;
CREATE FUNCTION pg_temp.vf(p_uid uuid, p_derived bytea, p_pepper text) RETURNS bytea LANGUAGE sql AS $f$
  SELECT public.hmac(
    convert_to('golfraven/partner-pin/v1', 'UTF8') || decode('00', 'hex')
      || decode(replace(p_uid::text, '-', ''), 'hex') || p_derived,
    convert_to(p_pepper, 'UTF8'), 'sha256')
$f$;
CREATE FUNCTION pg_temp.attempt(p_uid uuid, p_derived bytea) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE r record;
BEGIN
  EXECUTE 'SET LOCAL ROLE partner_pin_verifier';
  SELECT * INTO r FROM private.partner_pin_attempt(p_uid, p_derived);
  EXECUTE 'RESET ROLE';
  RETURN r.o_status || '|' || r.o_retry_after || '|' || r.o_newly_locked::text;
END
$f$;

\set uid '00000000-0000-0000-0000-1000000000a1'
SELECT '\x' || repeat('11', 32) AS dk_ok \gset

-- ----------------------------------------------------------------------------
-- 1. ACL + posture
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n)
   FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'),
                ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
   WHERE has_function_privilege(r.n, 'private.partner_pin_pepper_rotate(text)'::regprocedure, 'EXECUTE')),
  NULL,
  'EXECUTE: no edge/client/service_role may run partner_pin_pepper_rotate'
);

SELECT is(
  (SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole
     AND p.proacl::text = '{private_definer=X/private_definer}'
   FROM pg_proc p WHERE p.oid = 'private.partner_pin_pepper_rotate(text)'::regprocedure),
  true,
  'partner_pin_pepper_rotate is SECURITY DEFINER search_path='''' owned by private_definer with owner-only ACL'
);

SET LOCAL ROLE private_definer;
SELECT throws_ok(
  $$SELECT private.partner_pin_pepper_rotate('not_a_mode')$$,
  '22023',
  NULL,
  'bad_mode raises 22023'
);
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 2. non_compromise + dual-verify + lazy rewrap
-- ----------------------------------------------------------------------------
DELETE FROM vault.secrets WHERE name IN ('partner_pin_pepper', 'partner_pin_pepper_previous');
DELETE FROM app.partner_pin_pepper_epoch;
DELETE FROM app.partner_pin WHERE user_id = :'uid'::uuid;
INSERT INTO vault.secrets (name, secret) VALUES ('partner_pin_pepper', repeat('p', 40));

INSERT INTO app.partner_pin (user_id, salt, iterations, pepper_kid, verifier)
VALUES (
  :'uid'::uuid,
  decode(repeat('0a', 16), 'hex'),
  600000,
  'v1',
  pg_temp.vf(:'uid'::uuid, :'dk_ok'::bytea, repeat('p', 40))
);

SET LOCAL ROLE private_definer;
SELECT is(private.partner_pin_pepper_rotate('non_compromise'), 'ok', 'non_compromise returns ok');
SELECT is(private.partner_pin_pepper_rotate('non-compromise'), 'previous_exists',
  'second non_compromise (hyphen alias) refuses while previous exists');
RESET ROLE;

SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'partner_pin_pepper_previous'), 1,
  'non_compromise: partner_pin_pepper_previous exists');
SELECT is((SELECT s.secret FROM vault.secrets s WHERE s.name = 'partner_pin_pepper_previous'), repeat('p', 40),
  'non_compromise: previous holds the OLD pepper (copied in-DB)');
SELECT is((SELECT count(*)::int FROM app.partner_pin_pepper_epoch), 1,
  'non_compromise: one pepper_epoch row');
SELECT is((SELECT s.secret = repeat('p', 40) FROM vault.secrets s WHERE s.name = 'partner_pin_pepper'), false,
  'non_compromise: current pepper was replaced');
SELECT ok(
  (SELECT pepper_kid ~ '^[a-f0-9]{16}$' FROM app.partner_pin_pepper_epoch),
  'non_compromise: epoch pepper_kid is 16 hex chars'
);

SELECT is(
  (SELECT verifier FROM app.partner_pin WHERE user_id = :'uid'::uuid),
  pg_temp.vf(:'uid'::uuid, :'dk_ok'::bytea, repeat('p', 40)),
  'before rewrap: stored verifier still under previous pepper'
);

SELECT is(pg_temp.attempt(:'uid'::uuid, :'dk_ok'::bytea), 'ok|0|false',
  'dual-verify: correct derived key under previous pepper returns ok');

SELECT is(
  (SELECT verifier FROM app.partner_pin WHERE user_id = :'uid'::uuid),
  pg_temp.vf(
    :'uid'::uuid,
    :'dk_ok'::bytea,
    (SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'partner_pin_pepper')
  ),
  'lazy rewrap: verifier rewritten under CURRENT pepper'
);
SELECT is(
  (SELECT pepper_kid FROM app.partner_pin WHERE user_id = :'uid'::uuid),
  (SELECT pepper_kid FROM app.partner_pin_pepper_epoch ORDER BY effective_from DESC LIMIT 1),
  'lazy rewrap: pepper_kid updated to current epoch kid'
);

SELECT is(pg_temp.attempt(:'uid'::uuid, :'dk_ok'::bytea), 'ok|0|false',
  'after rewrap: second attempt still ok under current pepper');

SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'operator.partner_pin_pepper.rotate' AND detail->>'mode' = 'non_compromise'), 1,
  'non_compromise: one audit_log row');
SELECT ok(
  (SELECT bool_and(
     detail ? 'mode'
     AND detail ? 'effective_from'
     AND detail ? 'pepper_kid'
     AND NOT (detail::text ~* '"[a-f0-9]{64}"')
   ) FROM app.audit_log WHERE action = 'operator.partner_pin_pepper.rotate' AND detail->>'mode' = 'non_compromise'),
  'audit detail has mode + effective_from + pepper_kid and no pepper-shaped material'
);

-- previous without epoch is never tried
DELETE FROM app.partner_pin_pepper_epoch;
UPDATE app.partner_pin
SET verifier = pg_temp.vf(:'uid'::uuid, :'dk_ok'::bytea, repeat('p', 40)), pepper_kid = 'v1'
WHERE user_id = :'uid'::uuid;
SELECT is(pg_temp.attempt(:'uid'::uuid, :'dk_ok'::bytea), 'wrong|0|false',
  'previous pepper with NO epoch row is never used');

-- ----------------------------------------------------------------------------
-- 3. compromise: previous gone; old verifier fails
-- ----------------------------------------------------------------------------
DELETE FROM vault.secrets WHERE name IN ('partner_pin_pepper', 'partner_pin_pepper_previous');
DELETE FROM app.partner_pin_pepper_epoch;
INSERT INTO vault.secrets (name, secret) VALUES
  ('partner_pin_pepper', repeat('a', 40)),
  ('partner_pin_pepper_previous', repeat('b', 40));
INSERT INTO app.partner_pin_pepper_epoch (effective_from, recorded_at, pepper_kid)
VALUES (now() - interval '1 hour', now() - interval '1 hour', 'kid_comp_old');
UPDATE app.partner_pin
SET verifier = pg_temp.vf(:'uid'::uuid, :'dk_ok'::bytea, repeat('a', 40)), pepper_kid = 'v1'
WHERE user_id = :'uid'::uuid;

SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM app.partner_pin_pepper_epoch), 1, 'setup: one epoch before compromise');
SELECT is(private.partner_pin_pepper_rotate('compromise'), 'ok', 'compromise returns ok');
RESET ROLE;

SELECT is(pg_temp.attempt(:'uid'::uuid, :'dk_ok'::bytea), 'wrong|0|false',
  'compromise: old current-pepper verifier fails after rotation');
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'partner_pin_pepper_previous'), 0,
  'compromise: previous secret is absent');
SELECT is((SELECT count(*)::int FROM app.partner_pin_pepper_epoch), 1,
  'compromise: writes no new epoch row (count unchanged)');

-- ----------------------------------------------------------------------------
-- 4. retire_previous
-- ----------------------------------------------------------------------------
DELETE FROM vault.secrets WHERE name IN ('partner_pin_pepper', 'partner_pin_pepper_previous');
DELETE FROM app.partner_pin_pepper_epoch;
INSERT INTO vault.secrets (name, secret) VALUES
  ('partner_pin_pepper', repeat('c', 40)),
  ('partner_pin_pepper_previous', repeat('d', 40));
INSERT INTO app.partner_pin_pepper_epoch (effective_from, recorded_at, pepper_kid)
VALUES (now() - interval '1 day', now() - interval '1 day', 'kid_early');

SET LOCAL ROLE private_definer;
SELECT is(private.partner_pin_pepper_rotate('retire_previous'), 'too_early',
  'retire_previous: refuses before 7 days');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'partner_pin_pepper_previous'), 1,
  'retire_previous too_early: previous still present');

DELETE FROM app.partner_pin_pepper_epoch;
INSERT INTO app.partner_pin_pepper_epoch (effective_from, recorded_at, pepper_kid)
VALUES (now() - interval '8 days', now() - interval '8 days', 'kid_late');

SET LOCAL ROLE private_definer;
SELECT is(private.partner_pin_pepper_rotate('retire_previous'), 'ok',
  'retire_previous: ok when latest effective_from ≤ now() − 7 days');
SELECT is(private.partner_pin_pepper_rotate('retire_previous'), 'previous_absent',
  'retire_previous: previous_absent when already gone');
SELECT is(private.partner_pin_pepper_rotate('compromise'), 'ok', 'control: compromise ok after retire');
RESET ROLE;

DELETE FROM vault.secrets WHERE name = 'partner_pin_pepper';
SET LOCAL ROLE private_definer;
SELECT is(private.partner_pin_pepper_rotate('compromise'), 'no_pepper',
  'no_pepper when current pepper is absent');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 5. Inventory
-- ----------------------------------------------------------------------------
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(
  (SELECT expected_anon = false AND expected_authenticated = false AND expected_service_role = false
          AND expected_edge_actor = false AND expected_edge_system = false
          AND expected_edge_partner = false AND expected_edge_partner_minter = false
   FROM private.function_inventory
   WHERE schema_name = 'private' AND function_name = 'partner_pin_pepper_rotate'
     AND identity_args = 'p_mode text'),
  true,
  'function_inventory: expected_edge_* and client/service_role all false'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

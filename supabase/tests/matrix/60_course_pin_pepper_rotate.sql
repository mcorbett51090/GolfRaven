-- 60_course_pin_pepper_rotate.sql
-- 0082_course_pin_pepper_rotate.sql (P5 §69): operator course-PIN pepper
-- rotation. Proved here: non_compromise (previous + epoch + matcher under
-- both peppers), refuse second non_compromise while previous exists,
-- compromise (no epoch, previous gone, old PIN fails), retire_previous
-- (too_early before 7d / ok after), ACL (no edge/client EXECUTE), inventory.

\set QUIET 1
BEGIN;
SELECT plan(30);

GRANT private_definer TO CURRENT_USER WITH SET TRUE;
GRANT SELECT, INSERT, UPDATE, DELETE ON vault.secrets TO CURRENT_USER;
GRANT SELECT ON vault.decrypted_secrets TO CURRENT_USER;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.course_pin_pepper_epoch, app.audit_log TO CURRENT_USER;
CREATE POLICY zz60_pepper_epoch ON app.course_pin_pepper_epoch FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz60_audit ON app.audit_log FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

CREATE TEMP TABLE zz60_pin (label text PRIMARY KEY, pin text);
GRANT ALL ON zz60_pin TO private_definer;

-- ----------------------------------------------------------------------------
-- 1. ACL + posture
-- ----------------------------------------------------------------------------
SELECT is(
  (SELECT array_agg(r.n ORDER BY r.n)
   FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'),
                ('edge_system'), ('edge_signin_minter'), ('edge_partner'), ('edge_partner_minter')) r(n)
   WHERE has_function_privilege(r.n, 'private.course_pin_pepper_rotate(text)'::regprocedure, 'EXECUTE')),
  NULL,
  'EXECUTE: no edge/client/service_role may run course_pin_pepper_rotate'
);

SELECT is(
  (SELECT p.prosecdef AND p.proconfig = ARRAY['search_path=""'] AND p.proowner = 'private_definer'::regrole
     AND p.proacl::text = '{private_definer=X/private_definer}'
   FROM pg_proc p WHERE p.oid = 'private.course_pin_pepper_rotate(text)'::regprocedure),
  true,
  'course_pin_pepper_rotate is SECURITY DEFINER search_path='''' owned by private_definer with owner-only ACL'
);

SET LOCAL ROLE private_definer;
SELECT throws_ok(
  $$SELECT private.course_pin_pepper_rotate('not_a_mode')$$,
  '22023',
  NULL,
  'bad_mode raises 22023'
);
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 2. non_compromise: previous + epoch; matcher under both peppers
-- ----------------------------------------------------------------------------
DELETE FROM vault.secrets WHERE name IN ('course_pin_pepper', 'course_pin_pepper_previous');
DELETE FROM app.course_pin_pepper_epoch;
DELETE FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate';
INSERT INTO vault.secrets (name, secret) VALUES ('course_pin_pepper', repeat('p', 40));

SET LOCAL ROLE private_definer;
INSERT INTO zz60_pin VALUES ('old', private.course_pin_from_key(repeat('p', 40), 'fac_pepper_60', '2030-06-01', 0));
SELECT is(private.course_pin_pepper_rotate('non_compromise'), 'ok', 'non_compromise returns ok');
SELECT is(private.course_pin_pepper_rotate('non-compromise'), 'previous_exists',
  'second non_compromise (hyphen alias) refuses while previous exists');
RESET ROLE;

SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'course_pin_pepper_previous'), 1,
  'non_compromise: course_pin_pepper_previous exists');
SELECT is((SELECT s.secret FROM vault.secrets s WHERE s.name = 'course_pin_pepper_previous'), repeat('p', 40),
  'non_compromise: previous holds the OLD pepper (copied in-DB)');
SELECT is((SELECT count(*)::int FROM app.course_pin_pepper_epoch), 1,
  'non_compromise: one pepper_epoch row');
SELECT is((SELECT s.secret = repeat('p', 40) FROM vault.secrets s WHERE s.name = 'course_pin_pepper'), false,
  'non_compromise: current pepper was replaced');

SET LOCAL ROLE private_definer;
INSERT INTO zz60_pin VALUES (
  'new',
  private.course_pin_from_key(
    (SELECT s.decrypted_secret FROM vault.decrypted_secrets s WHERE s.name = 'course_pin_pepper'),
    'fac_pepper_60', '2030-06-01', 0
  )
);
SELECT is(
  private.course_pin_matches(
    'fac_pepper_60', '2030-06-01', 0,
    (SELECT pin FROM zz60_pin WHERE label = 'old'),
    (SELECT effective_from - interval '1 second' FROM app.course_pin_pepper_epoch ORDER BY effective_from DESC LIMIT 1)
  ),
  true,
  'non_compromise: instant before effective_from verifies under previous'
);
SELECT is(
  private.course_pin_matches(
    'fac_pepper_60', '2030-06-01', 0,
    (SELECT pin FROM zz60_pin WHERE label = 'old'),
    (SELECT effective_from + interval '1 second' FROM app.course_pin_pepper_epoch ORDER BY effective_from DESC LIMIT 1)
  ),
  false,
  'non_compromise: instant after effective_from does NOT verify under previous (old PIN)'
);
SELECT is(
  private.course_pin_matches(
    'fac_pepper_60', '2030-06-01', 0,
    (SELECT pin FROM zz60_pin WHERE label = 'new'),
    (SELECT effective_from + interval '1 second' FROM app.course_pin_pepper_epoch ORDER BY effective_from DESC LIMIT 1)
  ),
  true,
  'non_compromise: instant after effective_from verifies under current'
);
RESET ROLE;

SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate' AND detail->>'mode' = 'non_compromise'), 1,
  'non_compromise: one audit_log row (mode + effective_from only)');
SELECT ok(
  (SELECT bool_and(
     detail ? 'mode'
     AND detail ? 'effective_from'
     AND NOT (detail::text ~* 'course_pin_pepper_previous|"[a-f0-9]{64}"')
   ) FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate' AND detail->>'mode' = 'non_compromise'),
  'audit detail has mode + effective_from and no pepper-shaped material'
);

-- ----------------------------------------------------------------------------
-- 3. compromise: no epoch row; previous absent; old PIN fails
-- ----------------------------------------------------------------------------
DELETE FROM vault.secrets WHERE name IN ('course_pin_pepper', 'course_pin_pepper_previous');
DELETE FROM app.course_pin_pepper_epoch;
DELETE FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate';
INSERT INTO vault.secrets (name, secret) VALUES
  ('course_pin_pepper', repeat('a', 40)),
  ('course_pin_pepper_previous', repeat('b', 40));
INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at)
VALUES (now() - interval '1 hour', now() - interval '1 hour');

SET LOCAL ROLE private_definer;
INSERT INTO zz60_pin VALUES ('comp_old', private.course_pin_from_key(repeat('a', 40), 'fac_pepper_60', '2030-06-02', 0))
ON CONFLICT (label) DO UPDATE SET pin = EXCLUDED.pin;
SELECT is((SELECT count(*)::int FROM app.course_pin_pepper_epoch), 1, 'setup: one epoch before compromise');
SELECT is(private.course_pin_pepper_rotate('compromise'), 'ok', 'compromise returns ok');
SELECT is(
  private.course_pin_matches(
    'fac_pepper_60', '2030-06-02', 0,
    (SELECT pin FROM zz60_pin WHERE label = 'comp_old'),
    now()
  ),
  false,
  'compromise: old current-pepper PIN fails after rotation'
);
RESET ROLE;

SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'course_pin_pepper_previous'), 0,
  'compromise: previous secret is absent');
SELECT is((SELECT count(*)::int FROM app.course_pin_pepper_epoch), 1,
  'compromise: writes no new epoch row (count unchanged)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate' AND detail->>'mode' = 'compromise'), 1,
  'compromise: audit_log row with mode');

-- ----------------------------------------------------------------------------
-- 4. retire_previous: too_early before 7d; ok after; previous_absent
-- ----------------------------------------------------------------------------
DELETE FROM vault.secrets WHERE name IN ('course_pin_pepper', 'course_pin_pepper_previous');
DELETE FROM app.course_pin_pepper_epoch;
DELETE FROM app.audit_log WHERE action = 'operator.course_pin_pepper.rotate';
INSERT INTO vault.secrets (name, secret) VALUES
  ('course_pin_pepper', repeat('c', 40)),
  ('course_pin_pepper_previous', repeat('d', 40));
INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at)
VALUES (now() - interval '1 day', now() - interval '1 day');

SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_pepper_rotate('retire_previous'), 'too_early',
  'retire_previous: refuses before 7 days');
SELECT is(private.course_pin_pepper_rotate('retire-previous'), 'too_early',
  'retire-previous hyphen alias: same too_early');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'course_pin_pepper_previous'), 1,
  'retire_previous too_early: previous still present');

DELETE FROM app.course_pin_pepper_epoch;
INSERT INTO app.course_pin_pepper_epoch (effective_from, recorded_at)
VALUES (now() - interval '8 days', now() - interval '8 days');

SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_pepper_rotate('retire_previous'), 'ok',
  'retire_previous: ok when latest effective_from ≤ now() − 7 days');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'course_pin_pepper_previous'), 0,
  'retire_previous: previous secret deleted');

SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_pepper_rotate('retire_previous'), 'previous_absent',
  'retire_previous: previous_absent when already gone');
SELECT is(private.course_pin_pepper_rotate('non_compromise'), 'ok',
  'control: non_compromise ok with no previous after retire');
SELECT is(private.course_pin_pepper_rotate('non_compromise'), 'previous_exists',
  'refuse second non_compromise while previous exists (after a fresh rotation)');
RESET ROLE;

DELETE FROM vault.secrets WHERE name = 'course_pin_pepper';
SET LOCAL ROLE private_definer;
SELECT is(private.course_pin_pepper_rotate('compromise'), 'no_pepper',
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
   WHERE schema_name = 'private' AND function_name = 'course_pin_pepper_rotate'
     AND identity_args = 'p_mode text'),
  true,
  'function_inventory: expected_edge_* and client/service_role all false'
);
SELECT tests.clear_actor();

SELECT * FROM finish();
ROLLBACK;

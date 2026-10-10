-- 49_course_qr_retention_purges.sql
-- 0071_course_qr_retention_purges.sql (P5 §57): three edge_system purges for
-- course_qr_token (7 d past expires_at), course_pin_alarm (90 d past raised_at),
-- and abandoned pending purchase_evidence (awaiting.until past). Proved here:
--   1. structure / ACLs (edge_system only; InitPlan batch shape; floors in body);
--   2. purge / keep / idempotent for each class;
--   3. pending credits of abandoned purchases go; valid / held_review / live awaiting stay;
--   4. edge_actor / edge_partner / anon cannot EXECUTE.
-- Every group is its own BEGIN ... ROLLBACK. No secret: synthetic ids 5a5a4900-.

SELECT plan(30);

CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;

CREATE FUNCTION pg_temp.purge_as(p_role text, p_name text) RETURNS bigint LANGUAGE plpgsql AS $f$
DECLARE v bigint;
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', p_role);
  EXECUTE format('SELECT private.%I()', p_name) INTO v;
  RESET ROLE;
  RETURN v;
EXCEPTION WHEN OTHERS THEN
  RESET ROLE;
  RAISE;
END
$f$;

-- ----------------------------------------------------------------------------
-- 1. Structure and privileges
-- ----------------------------------------------------------------------------
SELECT is(pg_temp.can_exec('edge_system', ARRAY['purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases']), 3,
  'privileges: edge_system CAN run the three §57 purges');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases'])
        + pg_temp.can_exec('edge_partner', ARRAY['purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases'])
        + pg_temp.can_exec('anon', ARRAY['purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases'])
        + pg_temp.can_exec('authenticated', ARRAY['purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases'])
        + pg_temp.can_exec('service_role', ARRAY['purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases']), 0,
  'privileges: nobody else (edge_actor / partner / anon / authenticated / service_role) may EXECUTE them');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname IN ('purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases')
             AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig)
             AND p.prosrc ~ 'v_limit constant int := 5000' AND p.prosrc ~ '= ANY \(ARRAY\('), 3,
  'structure: all three are SECURITY DEFINER / private_definer / search_path='''' / constant 5000 / InitPlan array batch');
SELECT is((SELECT count(*)::int FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'app' AND (pol.polname LIKE 'pd\_purge\_course\_%' OR pol.polname LIKE 'pd\_purge\_abandoned\_%')), 8,
  'structure: eight purge policies (DELETE + SELECT companion for four targets)');
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name IN ('purge_course_qr_tokens', 'purge_course_pin_alarms', 'purge_abandoned_pending_purchases')
             AND expected_edge_system AND NOT expected_edge_actor AND NOT expected_service_role), 3,
  'inventory: three rows, edge_system only');

-- ----------------------------------------------------------------------------
-- 2. course_qr_token: 7 days past expires_at
-- ----------------------------------------------------------------------------
BEGIN;
INSERT INTO auth.users (id, email) VALUES ('5a5a4900-0000-0000-0000-0000000000a1', 'p49-a@purge.test') ON CONFLICT (id) DO NOTHING;
INSERT INTO app.course_qr_token (nonce_hash, facility_id, issued_by_staff, kid, issued_at, expires_at, used_by_user, used_at) VALUES
  (repeat('a1', 32), 'fac_x', '5a5a4900-0000-0000-0000-0000000000a1', 'kid49', now() - interval '10 days', now() - interval '8 days', '5a5a4900-0000-0000-0000-0000000000a1', now() - interval '8 days'),
  (repeat('a2', 32), 'fac_x', '5a5a4900-0000-0000-0000-0000000000a1', 'kid49', now() - interval '10 days', now() - interval '8 days', NULL, NULL),
  (repeat('a3', 32), 'fac_x', '5a5a4900-0000-0000-0000-0000000000a1', 'kid49', now() - interval '3 days', now() - interval '3 days' + interval '120 seconds', NULL, NULL),
  (repeat('a4', 32), 'fac_x', '5a5a4900-0000-0000-0000-0000000000a1', 'kid49', now(), now() + interval '120 seconds', NULL, NULL);
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_qr_tokens')::int >= 2, true, 'purge_course_qr_tokens deletes tokens 7+ days past expires_at (used and unused)');
SELECT is((SELECT array_agg(nonce_hash ORDER BY nonce_hash) FROM app.course_qr_token WHERE nonce_hash IN (repeat('a1', 32), repeat('a2', 32), repeat('a3', 32), repeat('a4', 32))),
  ARRAY[repeat('a3', 32), repeat('a4', 32)], '... and keeps a 3-day-old expired token and a live one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_qr_tokens')::int, 0, 'a second token purge is idempotent');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. course_pin_alarm: 90 days past raised_at
-- ----------------------------------------------------------------------------
BEGIN;
INSERT INTO app.course_pin_alarm (facility_id, local_date, pin_epoch_before, pin_epoch_after, failures, raised_at) VALUES
  ('fac_x', current_date - 200, 0, 1, 30, now() - interval '100 days'),
  ('fac_x', current_date - 10, 1, 2, 30, now() - interval '10 days'),
  ('fac_y', current_date - 200, 0, 1, 30, now() - interval '100 days');
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_alarms')::int >= 2, true, 'purge_course_pin_alarms deletes alarms raised more than 90 days ago');
SELECT is((SELECT count(*)::int FROM app.course_pin_alarm WHERE raised_at < now() - interval '90 days'), 0, '... none of the old ones remain');
SELECT is((SELECT count(*)::int FROM app.course_pin_alarm WHERE raised_at > now() - interval '30 days'), 1, '... and keeps the 10-day-old one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_course_pin_alarms')::int, 0, 'a second alarm purge is idempotent');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. abandoned pending purchases (+ their pending credits)
-- ----------------------------------------------------------------------------
BEGIN;
INSERT INTO auth.users (id, email) VALUES
  ('5a5a4900-0000-0000-0000-0000000000b1', 'p49-b@purge.test'),
  ('5a5a4900-0000-0000-0000-0000000000b2', 'p49-c@purge.test')
ON CONFLICT (id) DO NOTHING;
-- abandoned pending (until in the past)
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, cosignal, local_date, status) VALUES
  ('5a5a4900-0000-0000-0000-00000000a001', '5a5a4900-0000-0000-0000-0000000000b1', 'fac_x', 'trl_t', 'course_qr', 'rotating', 'tok:old',
   jsonb_build_object('awaiting', jsonb_build_object('from', (now() - interval '10 days')::text, 'to', (now() - interval '9 days')::text, 'until', (now() - interval '2 days')::text)),
   current_date - 10, 'pending'),
  ('5a5a4900-0000-0000-0000-00000000a002', '5a5a4900-0000-0000-0000-0000000000b1', 'fac_x', 'trl_t', 'staff_scan', NULL, 'offline:x',
   jsonb_build_object('awaiting', jsonb_build_object('from', (now() - interval '10 days')::text, 'to', (now() - interval '9 days')::text, 'until', (now() - interval '1 day')::text)),
   current_date - 10, 'pending');
-- live awaiting (until in the future) — keep
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, cosignal, local_date, status) VALUES
  ('5a5a4900-0000-0000-0000-00000000a003', '5a5a4900-0000-0000-0000-0000000000b1', 'fac_x', 'trl_t', 'course_qr', 'rotating', 'tok:live',
   jsonb_build_object('awaiting', jsonb_build_object('from', (now() - interval '1 hour')::text, 'to', (now() + interval '1 hour')::text, 'until', (now() + interval '6 days')::text)),
   current_date, 'pending');
-- valid / held_review — never purge
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, cosignal, local_date, status) VALUES
  ('5a5a4900-0000-0000-0000-00000000a004', '5a5a4900-0000-0000-0000-0000000000b2', 'fac_x', 'trl_t', 'course_qr', 'rotating', 'tok:valid',
   jsonb_build_object('awaiting', jsonb_build_object('from', (now() - interval '10 days')::text, 'to', (now() - interval '9 days')::text, 'until', (now() - interval '2 days')::text)),
   current_date - 10, 'valid'),
  ('5a5a4900-0000-0000-0000-00000000a005', '5a5a4900-0000-0000-0000-0000000000b2', 'fac_x', 'trl_t', 'course_qr', 'static_pin', 'pin:x',
   jsonb_build_object('awaiting', jsonb_build_object('from', (now() - interval '10 days')::text, 'to', (now() - interval '9 days')::text, 'until', (now() - interval '2 days')::text)),
   current_date - 10, 'held_review');
-- pending without awaiting — keep (not this purge's class)
INSERT INTO app.purchase_evidence (id, user_id, facility_id, trail_id, method, qr_variant, ref_id, cosignal, local_date, status) VALUES
  ('5a5a4900-0000-0000-0000-00000000a006', '5a5a4900-0000-0000-0000-0000000000b2', 'fac_x', 'trl_t', 'receipt', NULL, 'rcpt:x',
   '{}'::jsonb, current_date - 10, 'pending');
INSERT INTO app.marker_credit (id, user_id, trail_id, facility_id, purchase_evidence_id, status) VALUES
  ('5a5a4900-0000-0000-0000-00000000c001', '5a5a4900-0000-0000-0000-0000000000b1', 'trl_t', 'fac_x', '5a5a4900-0000-0000-0000-00000000a001', 'pending'),
  ('5a5a4900-0000-0000-0000-00000000c002', '5a5a4900-0000-0000-0000-0000000000b1', 'trl_t', 'fac_x', '5a5a4900-0000-0000-0000-00000000a002', 'pending'),
  ('5a5a4900-0000-0000-0000-00000000c003', '5a5a4900-0000-0000-0000-0000000000b1', 'trl_t', 'fac_x', '5a5a4900-0000-0000-0000-00000000a003', 'pending'),
  ('5a5a4900-0000-0000-0000-00000000c004', '5a5a4900-0000-0000-0000-0000000000b2', 'trl_t', 'fac_x', '5a5a4900-0000-0000-0000-00000000a004', 'credited');
GRANT edge_system TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SELECT is(pg_temp.purge_as('edge_system', 'purge_abandoned_pending_purchases')::int, 2, 'purge_abandoned_pending_purchases deletes exactly the two abandoned pending purchases');
SELECT is((SELECT count(*)::int FROM app.purchase_evidence WHERE id IN ('5a5a4900-0000-0000-0000-00000000a001', '5a5a4900-0000-0000-0000-00000000a002')), 0, '... those rows are gone');
SELECT is((SELECT count(*)::int FROM app.marker_credit WHERE id IN ('5a5a4900-0000-0000-0000-00000000c001', '5a5a4900-0000-0000-0000-00000000c002')), 0, '... and their pending credits are gone');
SELECT is((SELECT array_agg(id::text ORDER BY id::text) FROM app.purchase_evidence WHERE id IN (
  '5a5a4900-0000-0000-0000-00000000a003', '5a5a4900-0000-0000-0000-00000000a004',
  '5a5a4900-0000-0000-0000-00000000a005', '5a5a4900-0000-0000-0000-00000000a006')),
  ARRAY['5a5a4900-0000-0000-0000-00000000a003', '5a5a4900-0000-0000-0000-00000000a004', '5a5a4900-0000-0000-0000-00000000a005', '5a5a4900-0000-0000-0000-00000000a006'],
  '... keeps live awaiting, valid, held_review, and pending-without-awaiting');
SELECT is((SELECT count(*)::int FROM app.marker_credit WHERE id IN ('5a5a4900-0000-0000-0000-00000000c003', '5a5a4900-0000-0000-0000-00000000c004')), 2,
  '... keeps the live-awaiting pending credit and the credited one');
SELECT is(pg_temp.purge_as('edge_system', 'purge_abandoned_pending_purchases')::int, 0, 'a second abandoned-pending purge is idempotent');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 5. Role refusals (real calls)
-- ----------------------------------------------------------------------------
BEGIN;
GRANT edge_actor TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.purge_course_qr_tokens()$$, '42501', NULL, 'edge_actor cannot run purge_course_qr_tokens');
SELECT throws_ok($$SELECT private.purge_course_pin_alarms()$$, '42501', NULL, 'edge_actor cannot run purge_course_pin_alarms');
SELECT throws_ok($$SELECT private.purge_abandoned_pending_purchases()$$, '42501', NULL, 'edge_actor cannot run purge_abandoned_pending_purchases');
ROLLBACK;

BEGIN;
GRANT edge_partner TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
SET LOCAL ROLE edge_partner;
SELECT throws_ok($$SELECT private.purge_course_qr_tokens()$$, '42501', NULL, 'edge_partner cannot run purge_course_qr_tokens');
SELECT throws_ok($$SELECT private.purge_abandoned_pending_purchases()$$, '42501', NULL, 'edge_partner cannot run purge_abandoned_pending_purchases');
ROLLBACK;

BEGIN;
SET LOCAL ROLE anon;
SELECT throws_ok($$SELECT private.purge_course_pin_alarms()$$, '42501', NULL, 'anon cannot run purge_course_pin_alarms');
ROLLBACK;

-- floors in the bodies
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_course_qr_tokens' AND p.prosrc ~ 'interval ''7 days'''), 1, 'token purge body carries the 7-day floor');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_course_pin_alarms' AND p.prosrc ~ 'interval ''90 days'''), 1, 'alarm purge body carries the 90-day floor');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.proname = 'purge_abandoned_pending_purchases' AND p.prosrc ~ 'awaiting' AND p.prosrc ~ 'until'), 1, 'abandoned-pending purge body keys on awaiting.until');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_course_qr_token' AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%7 days%'), 1, 'token DELETE policy repeats the 7-day floor');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_course_pin_alarm' AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%90 days%'), 1, 'alarm DELETE policy repeats the 90-day floor');
SELECT is((SELECT count(*)::int FROM pg_policy pol WHERE pol.polname = 'pd_purge_abandoned_pending_purchase' AND pg_get_expr(pol.polqual, pol.polrelid) LIKE '%awaiting%'), 1, 'purchase DELETE policy repeats the awaiting floor');

SELECT * FROM finish();

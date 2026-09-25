-- 14_me_export.sql
-- build plan §4.7.1a inventory ("me-export") — task instruction: "the
-- same row set delete_my_data treats as personal, discovered from the
-- same pii_retention_policy registry... so the two can't drift." This
-- file is the export-side companion to 09_delete_my_data.sql: it proves
-- `private.export_my_data` (0021) stays in lockstep with the SAME
-- registry 09's own first test already proves is complete, and that it
-- is actor-scoped (never leaks another player's rows).

BEGIN;
SELECT plan(11);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ============================================================================
-- Registry sync: every delete_row/set_null-classified `app.` table has a
-- key present in export_my_data's own result (even if its array is
-- empty) — the SAME structural guarantee 09's own first test makes for
-- delete_my_data, restated for the export function's own output shape.
-- ============================================================================
SELECT is(
  (
    SELECT count(*)::int
    FROM (SELECT DISTINCT table_name FROM private.pii_retention_policy WHERE schema_name = 'app' AND action IN ('delete_row', 'set_null')) t
    WHERE NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) ? t.table_name)
  ),
  0,
  'every delete_row/set_null-classified app.* table has a key in export_my_data''s own jsonb result'
);

-- Every `special`-classified table this file knows to check (the same
-- six export_my_data's own bespoke block reads) is ALSO present.
SELECT is(
  (
    SELECT count(*)::int
    FROM unnest(ARRAY['attestation', 'entitlement', 'fraud_signal', 'audit_log', 'partner_invite', 'receipt_fingerprint']) t(table_name)
    WHERE NOT (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) ? t.table_name)
  ),
  0,
  'every special-cased table (attestation/entitlement/fraud_signal/audit_log/partner_invite/receipt_fingerprint) has a key in the export'
);

-- ============================================================================
-- Content: player A's own seeded rows (supabase/tests/helpers.sql) show
-- up, by id, in the corresponding array.
-- ============================================================================
SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'evidence') @>
    jsonb_build_array(jsonb_build_object('id', '30000000-0000-0000-0000-000000000001')),
  'player A''s export includes her own seeded evidence row (30000000-...-0001)'
);

SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'device') @>
    jsonb_build_array(jsonb_build_object('id', '20000000-0000-0000-0000-000000000001')),
  'player A''s export includes her own seeded device row'
);

SELECT ok(
  (private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'push_token') @>
    jsonb_build_array(jsonb_build_object('device_id', '20000000-0000-0000-0000-000000000001', 'expo_token', 'ExponentPushToken[test]')),
  'player A''s export includes her own seeded push_token row'
);

-- ============================================================================
-- Cross-user isolation: player A's export NEVER contains player B's rows
-- (§4.7.7 mandatory must-fail-cell shape, restated for the export
-- function — "Player A reads B's plays through any view -> 0 rows").
-- ============================================================================
SELECT is(
  jsonb_array_length(private.export_my_data('00000000-0000-0000-0000-00000000000b'::uuid) -> 'evidence'),
  0,
  'precondition: player B has no seeded evidence rows'
);

SELECT ok(
  NOT ((private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'device') @>
    jsonb_build_array(jsonb_build_object('id', '20000000-0000-0000-0000-000000000002'))),
  'player A''s export never includes a device id that is not her own'
);

-- Every row returned for evidence/device/push_token under actor A really
-- does carry A's own id — not merely "A's known row is present", but
-- "nothing else snuck in" for these three representative tables.
SELECT is(
  (SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'evidence') e WHERE (e ->> 'user_id') <> '00000000-0000-0000-0000-00000000000a'),
  0,
  'every evidence row in player A''s export carries her own user_id'
);
SELECT is(
  (SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) -> 'device') d WHERE (d ->> 'user_id') <> '00000000-0000-0000-0000-00000000000a'),
  0,
  'every device row in player A''s export carries her own user_id'
);

-- ============================================================================
-- Access control: no client role reaches this function directly (same
-- posture as private.delete_my_data — 09_delete_my_data.sql's own
-- access-control cells).
-- ============================================================================
SELECT tests.authenticate_as('authenticated', jsonb_build_object('sub', '00000000-0000-0000-0000-00000000000a'));
SELECT throws_ok(
  $$ SELECT private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) $$,
  '42501',
  NULL,
  'authenticated cannot call private.export_my_data directly (permission denied)'
);

SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok(
  $$ SELECT private.export_my_data('00000000-0000-0000-0000-00000000000a'::uuid) $$,
  '42501',
  NULL,
  'anon cannot call private.export_my_data directly (permission denied)'
);

SELECT * FROM finish();
ROLLBACK;

-- 22_device_first_attested.sql
-- 0043: app.device.first_attested_at is a STICKY mark that an `attested` verdict was once recorded on the device, stamped only by the trigger
-- app.device_first_attested_stamp when `integrity_last ->> 'grade'` is 'attested'. The no-attestation rule (Edge:
-- supabase/functions/_shared/rewards/attestation-evidence.ts) reads it so an Android device that attested at ACTIVATION cannot later claim it cannot
-- attest, even after a later `failed` / `unattestable` verdict overwrites integrity_last. The service_role lane (what the trigger normalises) runs
-- here; the edge_actor lane (the real recordDeviceVerdict / hasAttestedVerdictOnDevice statements under an edge_gateway login) is
-- 22_device_first_attested_edge.sql, which has to reconnect.

BEGIN;
SELECT plan(34);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- Devices (user A from helpers.sql): a1 the main subject, a2 never attested, a3 a row written the way a pre-0043 database holds it.
INSERT INTO app.device (id, user_id, platform) VALUES
  ('22000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000000a', 'android'),
  ('22000000-0000-0000-0000-0000000000a2', '00000000-0000-0000-0000-00000000000a', 'android');
INSERT INTO app.device (id, user_id, platform, integrity_last) VALUES
  ('22000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-00000000000a', 'android', '{"grade":"attested","at":"2026-01-01T00:00:00Z"}'::jsonb);

-- ============================================================================
-- 1. Schema and registry
-- ============================================================================
SELECT has_column('app', 'device', 'first_attested_at', 'device.first_attested_at exists');
SELECT col_type_is('app', 'device', 'first_attested_at', 'timestamp with time zone', 'and is a timestamptz');
SELECT col_is_null('app', 'device', 'first_attested_at', 'and is nullable (NULL = never attested)');
SELECT has_trigger('app', 'device', 'device_first_attested_stamp_trg', 'the stamping trigger exists');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE schema_name = 'app' AND function_name = 'device_first_attested_stamp'), 1, 'the trigger function has its registry row');
SELECT is((SELECT count(*)::int FROM pg_trigger WHERE tgrelid = 'app.device'::regclass AND tgname = 'device_attest_counter_monotonic_trg'), 1, 'control: the 0038 counter trigger is still in place (0043 replaced nothing)');

-- ============================================================================
-- 2. Stamping
-- ============================================================================
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'a new device is unstamped');
UPDATE app.device SET integrity_last = '{"grade":"unattestable"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'an `unattestable` verdict does not stamp');
UPDATE app.device SET integrity_last = '{"grade":"failed"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'a `failed` verdict does not stamp');
UPDATE app.device SET integrity_last = '{"grade":"attested","at":"2026-10-03T00:00:00Z"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'an `attested` verdict stamps the device, with now()');

-- ============================================================================
-- 3. Sticky: a later verdict does not erase it, and no statement clears or moves it
-- ============================================================================
UPDATE app.device SET integrity_last = '{"grade":"failed"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT integrity_last ->> 'grade' FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), 'failed', 'the later verdict DID overwrite integrity_last (this is why a sticky mark is needed)');
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, '... and the stamp is still there, unmoved, after a `failed` verdict');
UPDATE app.device SET integrity_last = '{"grade":"unattestable"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at IS NOT NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, '... and after an `unattestable` one');
UPDATE app.device SET first_attested_at = NULL WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'a statement that clears the stamp is undone (service_role has UPDATE here; the trigger decides by content, not by role)');
UPDATE app.device SET first_attested_at = now() - interval '2 days' WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'moving the stamp EARLIER is undone');
UPDATE app.device SET first_attested_at = now() + interval '2 days', integrity_last = '{"grade":"failed"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'moving it LATER in the same statement as a verdict is undone');
UPDATE app.device SET last_seen = now() WHERE id = '22000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT first_attested_at = now() FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a1'), true, 'an unrelated UPDATE leaves it alone');

-- ============================================================================
-- 4. Only a verdict can set it
-- ============================================================================
UPDATE app.device SET first_attested_at = now() WHERE id = '22000000-0000-0000-0000-0000000000a2';
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a2'), true, 'assigning the column on a never-attested device stamps nothing');
UPDATE app.device SET first_attested_at = now(), integrity_last = '{"grade":"unattestable"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a2';
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a2'), true, '... not even next to a non-attested verdict');
UPDATE app.device SET integrity_last = NULL WHERE id = '22000000-0000-0000-0000-0000000000a2';
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a2'), true, 'a NULL integrity_last (no verdict) stamps nothing and does not error');
SELECT is((SELECT first_attested_at IS NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a3'), true, 'a row written before 0043 with an `attested` integrity_last carries no stamp (no backfill: the Edge read treats integrity_last as evidence too)');
UPDATE app.device SET integrity_last = '{"grade":"attested"}'::jsonb WHERE id = '22000000-0000-0000-0000-0000000000a3';
SELECT is((SELECT first_attested_at IS NOT NULL FROM app.device WHERE id = '22000000-0000-0000-0000-0000000000a3'), true, '... and its next attested verdict stamps it');

-- ============================================================================
-- 5. Posture: nothing was broadened
-- ============================================================================
SELECT is(has_column_privilege('edge_actor', 'app.device', 'first_attested_at', 'UPDATE'), false, 'edge_actor holds NO UPDATE on first_attested_at (only the trigger writes it)');
SELECT is(has_column_privilege('edge_actor', 'app.device', 'first_attested_at', 'INSERT'), false, 'edge_actor holds NO INSERT on first_attested_at');
SELECT is(has_column_privilege('edge_actor', 'app.device', 'first_attested_at', 'SELECT'), true, 'edge_actor reads it through its existing table-level SELECT');
SELECT is(has_column_privilege('edge_actor', 'app.device', 'integrity_last', 'UPDATE'), true, 'control: edge_actor still holds the UPDATE on integrity_last it always had (the verdict write)');
SELECT is((SELECT count(*)::int FROM pg_policies WHERE schemaname = 'app' AND tablename = 'device' AND 'edge_actor' = ANY (roles) AND cmd = 'UPDATE'), 1, 'edge_actor still has exactly one UPDATE policy on app.device (0043 added none)');
SELECT is((SELECT c.relforcerowsecurity AND c.relrowsecurity FROM pg_class c WHERE c.relnamespace = 'app'::regnamespace AND c.relname = 'device'), true, 'app.device keeps ENABLE and FORCE ROW LEVEL SECURITY');
SELECT is((SELECT has_function_privilege('edge_actor', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE') OR has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('service_role', p.oid, 'EXECUTE')
          FROM pg_proc p WHERE p.pronamespace = 'app'::regnamespace AND p.proname = 'device_first_attested_stamp'), false, 'the trigger function is EXECUTEd by no role');
SELECT is((SELECT p.prosecdef FROM pg_proc p WHERE p.pronamespace = 'app'::regnamespace AND p.proname = 'device_first_attested_stamp'), false, 'and is SECURITY INVOKER');

-- ============================================================================
-- 6. Export (0044: the column IS exported: a timestamp about the account's own device, which the no-attestation rule acts on)
-- ============================================================================
SELECT is((SELECT d -> 'first_attested_at' = to_jsonb(first_attested_at) AND d ->> 'first_attested_at' IS NOT NULL
             FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-00000000000a') -> 'device') d, app.device a
            WHERE d ->> 'id' = '22000000-0000-0000-0000-0000000000a1' AND a.id = '22000000-0000-0000-0000-0000000000a1'), true,
  'GET /v1/me/export carries first_attested_at for a stamped device, exactly as the column serialises (an ISO-8601 string, like first_seen)');
SELECT is((SELECT jsonb_typeof(d -> 'first_attested_at') FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-00000000000a') -> 'device') d WHERE d ->> 'id' = '22000000-0000-0000-0000-0000000000a2'), 'null',
  'a device that never attested exports first_attested_at as JSON null (the key is present, not omitted)');
SELECT is((SELECT jsonb_typeof(d -> 'first_seen') FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-00000000000a') -> 'device') d WHERE d ->> 'id' = '22000000-0000-0000-0000-0000000000a2'), 'string',
  'control: the other timestamps keep serialising as strings (same null handling: a timestamptz is a string or JSON null)');
SELECT is((SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('00000000-0000-0000-0000-00000000000b') -> 'device') d WHERE d ->> 'id' LIKE '22000000-%'), 0,
  'another account''s export carries none of these devices');

SELECT * FROM finish();
ROLLBACK;

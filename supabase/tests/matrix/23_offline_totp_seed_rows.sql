-- 23_offline_totp_seed_rows.sql
-- 0045: the rows 23_offline_totp_seed_edge.sql COMMITTED (pg_prove runs it first, in file order), read back as service_role, then exported and deleted.
-- ⛔ WATCH (the silent class edge_actor introduces): under RLS an UPDATE or DELETE with no matching policy affects ZERO rows and raises nothing, so every "it
-- was written / it was pruned" claim in the edge file is proven HERE by reading the row back.
-- The edge file recorded step `cur` (the 10-minute step of ITS clock) on PA's a001 at fac_x by staff-x, rotated a002 to version 2 and recorded a version-2 step
-- on it, and seeded one OLD row (step cur - 50) on a001 and one on PB's b001; steps are therefore matched within +-1 of this file's own clock.
-- This file also CLEANS UP everything the edge file left (the ee230000- accounts, staff-x's own device).

\set QUIET 1
SELECT plan(23);
SELECT floor(extract(epoch FROM clock_timestamp()) / 600)::bigint AS cur \gset
SET ROLE service_role;
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE device_id = 'ee230000-0000-0000-0000-00000000a001' AND step BETWEEN :cur - 1 AND :cur + 1 AND seed_version = 1
           AND facility_id = 'fac_x' AND user_id = 'ee230000-0000-0000-0000-0000000000a0'), 1, 'phase 2: the recorded row is there, with the facility and the DEVICE OWNER''s user id (not the staff member''s)');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE user_id = '00000000-0000-0000-0000-1000000000a1'), 0, 'phase 2: no row carries the staff member''s id');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE device_id = 'ee230000-0000-0000-0000-00000000a001' AND step < :cur - 20), 0, 'PRUNE: a001''s OLD row (far behind the clock) was deleted by the record call ...');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE device_id = 'ee230000-0000-0000-0000-00000000b001' AND step < :cur - 20), 1, '... and PB''s device''s old row was NOT (the prune is scoped to the ONE device the call named)');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE device_id = 'ee230000-0000-0000-0000-00000000a002' AND seed_version = 2 AND step BETWEEN :cur - 1 AND :cur + 1), 1, 'phase 2: a002''s version-2 step is there');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE device_id = 'ee230000-0000-0000-0000-00000000a002' AND seed_version = 1), 0, 'phase 2: and the rotated-out version-1 step never was');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000a002'), 2, 'phase 2: a002 is at version 2 (the committed rotation)');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000a001'), 1, 'phase 2: a001 is at version 1 (every rolled-back rotation left nothing)');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000b001'), 1, 'phase 2: PB''s device is untouched by PA''s rotation attempts');
-- export
SELECT is((SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys((private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid) -> 'offline_code_step') -> 0) k),
  ARRAY['device_id', 'facility_id', 'seed_version', 'step', 'used_at', 'user_id'], 'export: the offline_code_step block is exactly these columns');
SELECT is(jsonb_array_length(private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid) -> 'offline_code_step'), 2, 'export: PA''s two rows (a001 step cur, a002 version 2 step cur)');
SELECT is((SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid) -> 'offline_code_step') e
           WHERE e ->> 'device_id' = 'ee230000-0000-0000-0000-00000000a001' AND (e ->> 'seed_version')::int = 1 AND e ->> 'facility_id' = 'fac_x' AND (e ->> 'step')::bigint BETWEEN :cur - 1 AND :cur + 1), 1,
  'export: and a001''s row is among them');
SELECT is((SELECT (d -> 'offline_seed_version')::int FROM jsonb_array_elements(private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid) -> 'device') d WHERE d ->> 'id' = 'ee230000-0000-0000-0000-00000000a002'), 2, 'export: the device block carries offline_seed_version');
SELECT is((SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid) -> 'offline_code_step') e WHERE e ->> 'device_id' NOT IN ('ee230000-0000-0000-0000-00000000a001', 'ee230000-0000-0000-0000-00000000a002')), 0, 'export: only PA''s OWN devices'' rows');
SELECT is((SELECT count(*)::int FROM jsonb_array_elements(private.export_my_data('ee230000-0000-0000-0000-0000000000b0'::uuid) -> 'offline_code_step') e WHERE e ->> 'device_id' <> 'ee230000-0000-0000-0000-00000000b001'), 0, 'export: PB''s export holds nothing of PA''s');
SELECT is((private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid)::text ~* ('add40558091437161f58c7fad32608775b39e7f79910f980924d6f26a10ddc04|552d171b816981be928316aac6d6b0fe598bdc69f9d46b2974ea9ab620d96e5e|05960b88294025ee5f4cccdc81c40999bd88a7bb915b2034f40c30ee708192fe')), false,
  'export: PA''s WHOLE export contains none of her seeds (none is stored; the export never derives one)');
SELECT is((private.export_my_data('ee230000-0000-0000-0000-0000000000a0'::uuid)::text ~* 'offline_seed_key|shim-test-only'), false, 'export: nor the derivation key');
-- delete: PA's rows go with the account; PB's stay
SELECT lives_ok($$SELECT private.delete_my_data('ee230000-0000-0000-0000-0000000000a0')$$, 'delete: delete_my_data(PA) completes (its fail-closed post-condition re-reads the replay table under the _r policy)');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE user_id = 'ee230000-0000-0000-0000-0000000000a0'), 0, 'delete: none of PA''s replay rows remain');
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE user_id = 'ee230000-0000-0000-0000-0000000000b0'), 1, 'delete: PB''s row is untouched');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = 'ee230000-0000-0000-0000-0000000000a0'), 0, 'delete: and PA''s devices are gone (the replay rows would have gone with them by cascade)');
-- cleanup
SELECT lives_ok($$SELECT private.delete_my_data('ee230000-0000-0000-0000-0000000000b0')$$, 'cleanup: delete_my_data(PB)');
DELETE FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000f001';
SELECT is((SELECT count(*)::int FROM app.offline_code_step WHERE user_id::text LIKE 'ee230000-%' OR device_id::text LIKE 'ee230000-%'), 0, 'cleanup: no replay row of this file survives');
RESET ROLE;

SELECT * FROM finish();

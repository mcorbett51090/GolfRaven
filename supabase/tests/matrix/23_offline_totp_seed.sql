-- 23_offline_totp_seed.sql
-- 0045_offline_totp_seed.sql, the structural invariants and the derivation: the seed is DERIVED (HMAC-SHA256 of label || user || device || version under a
-- Vault key K), K is readable by NOBODY but the one derivation function, the replay table and the device column are locked down, and the registries
-- (function inventory, definer policy allowlist, retention / export policy) describe what the migration built. The edge_actor lane (provisioning, rotation,
-- the staff-lane replay record, deletion and export of a real row) is 23_offline_totp_seed_edge.sql: it has to reconnect as a real edge_gateway login.
--
-- THE TEST VECTORS below were computed OUTSIDE the database (Python hmac / hashlib, never this function) from the shim's K
-- ('shim-test-only-offline-seed-key-...', supabase/tests/shim.sql) and the message
--   b'golfraven/offline-seed/v1' + b'\x00' + uuid.bytes(user) + uuid.bytes(device) + struct.pack('>I', version)
-- so a change to the derivation (the label, the field order, the encoding, the key, the hash) fails here, not in production. The key is a shim constant:
-- no secret lives in this file.

SELECT plan(63);

-- ----------------------------------------------------------------------------
-- 0. Structure: the device column and the replay table
-- ----------------------------------------------------------------------------
SELECT has_column('app', 'device', 'offline_seed_version', 'app.device.offline_seed_version exists');
SELECT col_type_is('app', 'device', 'offline_seed_version', 'integer', 'and is an integer');
SELECT col_not_null('app', 'device', 'offline_seed_version', 'and is NOT NULL');
SELECT col_default_is('app', 'device', 'offline_seed_version', '1', 'and defaults to 1 (version 1 is the first seed)');
SELECT is((SELECT count(*)::int FROM pg_attribute a WHERE a.attrelid = 'app.device'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND a.attname ~* '(^|_)(seed|secret|totp)(_|$)' AND a.attname <> 'offline_seed_version'), 0,
  'no per-device seed is STORED on app.device (the only seed-named column is the version counter)');
SELECT has_table('app', 'offline_code_step', 'app.offline_code_step exists');
SELECT columns_are('app', 'offline_code_step', ARRAY['user_id', 'device_id', 'seed_version', 'step', 'facility_id', 'used_at'],
  'the replay table has exactly these columns: no seed, no code, no staff identity');
SELECT col_is_pk('app', 'offline_code_step', ARRAY['device_id', 'seed_version', 'step'], 'the replay key is (device, seed version, step): a step of one seed can be recorded once');
SELECT is((SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'app.offline_code_step'::regclass), true, 'app.offline_code_step has RLS enabled AND forced');
SELECT is((SELECT c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'app.device'::regclass), true, 'app.device keeps FORCE ROW LEVEL SECURITY');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'app.offline_code_step'::regclass AND k.contype = 'f' AND k.confrelid = 'auth.users'::regclass AND k.confdeltype = 'c'), 1,
  'the replay table references auth.users ON DELETE CASCADE (a personal table, classified below)');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'app.offline_code_step'::regclass AND k.contype = 'f' AND k.confrelid = 'app.device'::regclass AND k.confdeltype = 'c' AND k.condeferrable), 1,
  'and app.device ON DELETE CASCADE, deferrable like every app-internal FK (0014)');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.offline_code_step', 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.offline_code_step', 'DELETE,TRUNCATE,TRIGGER')), 0,
  'no client role and no edge role holds ANY privilege on the replay table (every path is a definer)');
SELECT is((SELECT c.relacl::text !~ '(^\{|,)=' FROM pg_class c WHERE c.oid = 'app.offline_code_step'::regclass), true, 'PUBLIC holds nothing on the replay table');
SELECT is(has_table_privilege('service_role', 'app.offline_code_step', 'SELECT'), true, 'service_role may READ the replay table (diagnostics) ...');
SELECT is(has_table_privilege('service_role', 'app.offline_code_step', 'INSERT,UPDATE,DELETE'), false, '... and may not write it: only the record definer inserts, only the prune / delete_my_data delete');
SELECT is(has_column_privilege('edge_actor', 'app.device', 'offline_seed_version', 'UPDATE') OR has_column_privilege('edge_actor', 'app.device', 'offline_seed_version', 'INSERT'), false,
  'edge_actor can neither INSERT nor UPDATE app.device.offline_seed_version (only private.offline_seed_for_actor rotates it)');
SELECT is(has_column_privilege('private_definer', 'app.device', 'offline_seed_version', 'UPDATE'), true, 'private_definer holds the one column grant the rotation needs');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated')) r(n) WHERE has_column_privilege(r.n, 'app.device', 'offline_seed_version', 'UPDATE,INSERT')), 0, 'no client role writes the version either');

-- ----------------------------------------------------------------------------
-- 1. K: readable by nobody but private_definer; the three functions' posture
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_table_privilege(r.n, 'vault.decrypted_secrets', 'SELECT') OR has_any_column_privilege(r.n, 'vault.decrypted_secrets', 'SELECT') OR has_table_privilege(r.n, 'vault.secrets', 'SELECT') AND r.n <> 'service_role'), 0,
  'K: no client or edge role (service_role aside, which holds the raw shim table for harness seeding only) can read the Vault: the decrypted view or the secrets table');
SELECT is(has_column_privilege('edge_actor', 'vault.decrypted_secrets', 'decrypted_secret', 'SELECT') OR has_schema_privilege('edge_actor', 'vault', 'USAGE'), false, 'K: edge_actor has no USAGE on the vault schema and cannot select the decrypted secret');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'offline_seed_key'), 1, 'K: exactly ONE function in the database names the key: the derivation');
SELECT is((SELECT p.proname FROM pg_proc p WHERE p.pronamespace = 'private'::regnamespace AND p.prosrc ~ 'offline_seed_key'), 'offline_seed_derive', 'K: and it is private.offline_seed_derive');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.offline_seed_derive(uuid, uuid, integer)', 'EXECUTE')), 0, 'K: no role at all may EXECUTE the derivation core');
SELECT is((SELECT p.proacl::text !~ '(^\{|,)=' FROM pg_proc p WHERE p.oid = 'private.offline_seed_derive(uuid, uuid, integer)'::regprocedure), true, 'K: PUBLIC has no EXECUTE on the derivation core');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE')), ARRAY['edge_actor'], 'only edge_actor may EXECUTE offline_seed_for_actor');
SELECT is((SELECT array_agg(r.n ORDER BY r.n) FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE')), NULL, 'NO listed role may EXECUTE offline_code_record_step_for_actor (0047, X9: owner-only primitive; its proofs call it as private_definer: 23_offline_totp_seed_record.sql)');
SELECT is((SELECT count(*)::int FROM pg_proc p WHERE p.oid IN ('private.offline_seed_derive(uuid, uuid, integer)'::regprocedure, 'private.offline_seed_for_actor(uuid, boolean)'::regprocedure,
             'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)'::regprocedure)
           AND p.prosecdef AND p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""']), 3,
  'all three are SECURITY DEFINER, owned by private_definer, with search_path = ''''');

-- ----------------------------------------------------------------------------
-- 2. The derivation against OUTSIDE test vectors (run as private_definer: the owner is the only role that may call the core)
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE private_definer;
SELECT is(encode(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1), 'hex'),
  'add40558091437161f58c7fad32608775b39e7f79910f980924d6f26a10ddc04', 'vector: (user A, device 1, version 1)');
SELECT is(encode(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 2), 'hex'),
  '552d171b816981be928316aac6d6b0fe598bdc69f9d46b2974ea9ab620d96e5e', 'vector: the SAME user and device at version 2 is a different seed (rotation)');
SELECT is(encode(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a002', 1), 'hex'),
  '05960b88294025ee5f4cccdc81c40999bd88a7bb915b2034f40c30ee708192fe', 'vector: another DEVICE of the same user is a different seed');
SELECT is(encode(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000b0', 'ee230000-0000-0000-0000-00000000a001', 1), 'hex'),
  'b6f77d66aeadd39dd8cfcbed98a198de66bffc280c8dae56e9d3f4be059ab290', 'vector: another USER on the same device id is a different seed');
SELECT is(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1),
  private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1), 'deterministic: the same inputs give the same seed');
SELECT is(octet_length(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1)), 32, 'the seed is 32 bytes (HMAC-SHA-256, and RFC 6238''s SHA-256 key length)');
SELECT throws_ok($$SELECT private.offline_seed_derive(NULL, 'ee230000-0000-0000-0000-00000000a001', 1)$$, '22023', NULL, 'a NULL user is refused');
SELECT throws_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', NULL, 1)$$, '22023', NULL, 'a NULL device is refused');
SELECT throws_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 0)$$, '22023', NULL, 'version 0 is refused');
SELECT throws_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', NULL)$$, '22023', NULL, 'a NULL version is refused');
ROLLBACK;

-- 2b. K missing / too short: the derivation FAILS CLOSED (55000) and names no key material
BEGIN;
DELETE FROM vault.secrets WHERE name = 'offline_seed_key';
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1)$$, '55000',
  'offline_seed_derive: the offline seed key is not provisioned in Vault', 'no K in the Vault: 55000, with a message that names no key');
ROLLBACK;
BEGIN;
UPDATE vault.secrets SET secret = repeat('k', 31) WHERE name = 'offline_seed_key';
SET LOCAL ROLE private_definer;
SELECT throws_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1)$$, '55000', NULL, 'a 31-byte K is refused (the minimum is 32 bytes)');
ROLLBACK;
BEGIN;
UPDATE vault.secrets SET secret = repeat('k', 32) WHERE name = 'offline_seed_key';
SET LOCAL ROLE private_definer;
SELECT lives_ok($$SELECT private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1)$$, 'a 32-byte K is accepted');
SELECT isnt(encode(private.offline_seed_derive('ee230000-0000-0000-0000-0000000000a0', 'ee230000-0000-0000-0000-00000000a001', 1), 'hex'), 'add40558091437161f58c7fad32608775b39e7f79910f980924d6f26a10ddc04',
  'and a different K gives a different seed (the key really is an input)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. The monotonic version trigger (service_role can UPDATE the column: the trigger is the guard for every role)
-- ----------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE service_role;
INSERT INTO auth.users (id) VALUES ('ee230000-0000-0000-0000-0000000000c0');
INSERT INTO app.device (id, user_id, platform) VALUES ('ee230000-0000-0000-0000-00000000c001', 'ee230000-0000-0000-0000-0000000000c0', 'android');
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000c001'), 1, 'a new device starts at seed version 1');
UPDATE app.device SET offline_seed_version = 5 WHERE id = 'ee230000-0000-0000-0000-00000000c001';
SELECT is((SELECT offline_seed_version FROM app.device WHERE id = 'ee230000-0000-0000-0000-00000000c001'), 5, 'the version may go UP');
SELECT throws_ok($$UPDATE app.device SET offline_seed_version = 4 WHERE id = 'ee230000-0000-0000-0000-00000000c001'$$, '23514', NULL, 'the version never goes DOWN (a lower one would revive a rotated-out seed)');
SELECT lives_ok($$UPDATE app.device SET offline_seed_version = 5 WHERE id = 'ee230000-0000-0000-0000-00000000c001'$$, 'the same value is not a decrease');
SELECT throws_ok($$UPDATE app.device SET offline_seed_version = 0 WHERE id = 'ee230000-0000-0000-0000-00000000c001'$$, '23514', NULL, 'and the CHECK refuses 0');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. Registries (FORCE RLS tables: read as service_role, which holds the grants)
-- ----------------------------------------------------------------------------
SET ROLE service_role;
SELECT is((SELECT action::text FROM private.pii_retention_policy WHERE schema_name = 'app' AND table_name = 'offline_code_step' AND column_name = 'user_id'), 'delete_row',
  'registry: offline_code_step.user_id is classified delete_row (a personal table, deleted with the account)');
SELECT is((SELECT action::text FROM private.pii_export_policy WHERE schema_name = 'app' AND table_name = 'offline_code_step'), 'export', 'registry: and exported to its subject');
SELECT is((SELECT count(*)::int FROM private.function_inventory WHERE function_name IN ('offline_seed_derive', 'offline_seed_for_actor', 'offline_code_record_step_for_actor', 'device_offline_seed_version_monotonic', 'offline_code_bound_staff')), 5,
  'registry: all five new functions are in private.function_inventory');
SELECT is((SELECT array_agg(function_name ORDER BY function_name) FROM private.function_inventory
           WHERE function_name LIKE 'offline_%' AND expected_edge_actor), ARRAY['offline_seed_for_actor'], 'registry: edge_actor is expected on exactly ONE wrapper since 0047 (X9 revoked the recorder)');
SELECT is((SELECT count(*)::int FROM private.function_inventory
           WHERE function_name LIKE 'offline_%' AND (expected_anon OR expected_authenticated OR expected_service_role OR expected_edge_system)), 0, 'registry: no other role is expected on any of them');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE '%offline_code%' AND scoped), 6, 'registry: all six private_definer policies are in the allow-list, each scoped');
SELECT is((SELECT count(*)::int FROM private.definer_policy_allowlist WHERE policy_name LIKE '%offline_code%' AND using_expr IS NULL AND with_check_expr IS NULL), 0, 'registry: and each carries its recorded expression');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'app.offline_code_step'::regclass AND p.polroles <> ARRAY['private_definer'::regrole::oid]), 0,
  'the replay table has policies for private_definer ONLY (no client or edge role has one)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'app.offline_code_step'::regclass), 9, 'and exactly the five the migration names plus the four 0056 adds for the partner lane (insert, select, prune, prune companion: all keyed on the partner binding)');

-- ----------------------------------------------------------------------------
-- 5. The registered inventory still matches the live grants (the standalone check is tools/db/verify-function-inventory.mjs)
-- ----------------------------------------------------------------------------
SELECT is((SELECT has_function_privilege('edge_actor', 'private.offline_seed_for_actor(uuid, boolean)', 'EXECUTE')
             AND NOT has_function_privilege('edge_actor', 'private.offline_code_record_step_for_actor(uuid, integer, bigint, text)', 'EXECUTE')), true, 'edge_actor holds EXECUTE on the provisioning wrapper and (0047, X9) NOT on the replay recorder');
SELECT is((SELECT count(*)::int FROM pg_trigger t WHERE t.tgrelid = 'app.device'::regclass AND t.tgname = 'device_offline_seed_version_monotonic_trg' AND NOT t.tgisinternal), 1, 'the monotonic trigger exists on app.device');

-- ----------------------------------------------------------------------------
-- 6. Gate follow-up: the device policy is keyed on the actor binding, never a settable GUC; the pseudonym-key validator checks the secret's NAME
-- ----------------------------------------------------------------------------
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_function_privilege(r.n, 'private.offline_code_bound_staff()', 'EXECUTE')), 0, 'the policy predicate: no role may EXECUTE private.offline_code_bound_staff');
SELECT is((SELECT pg_get_expr(p.polqual, p.polrelid) FROM pg_policy p WHERE p.polrelid = 'app.device'::regclass AND p.polname = 'pd_offline_code_device_select'), 'private.offline_code_bound_staff()',
  'pd_offline_code_device_select is keyed on the actor-binding predicate: its expression names no current_setting() and no GUC');
SET ROLE service_role;
SELECT throws_ok($$SELECT private.validate_and_register_pseudonym_hmac_id('a0000000-1111-0000-0000-0000000000f1')$$, '23514', NULL,
  'NIT-1: the Vault id of offline_seed_key (a >= 32-byte secret, but not a pseudonym_hmac key) can NOT be registered as a pseudonym key');
BEGIN;
SELECT lives_ok($$SELECT private.validate_and_register_pseudonym_hmac_id('a0000000-1111-0000-0000-000000000001')$$, 'control: a real pseudonym_hmac_v1 id still registers');
ROLLBACK;
RESET ROLE;
SELECT is((SELECT p.proowner = 'private_definer'::regrole AND p.proconfig = ARRAY['search_path=""'] AND p.prosecdef AND p.prosrc LIKE '%name LIKE ''pseudonym_hmac%''%'
             AND has_function_privilege('service_role', p.oid, 'EXECUTE') AND has_function_privilege('edge_actor', p.oid, 'EXECUTE')
             AND NOT has_function_privilege('anon', p.oid, 'EXECUTE') AND NOT has_function_privilege('authenticated', p.oid, 'EXECUTE')
           FROM pg_proc p WHERE p.oid = 'private.validate_and_register_pseudonym_hmac_id(uuid)'::regprocedure), true,
  'the replaced validator keeps its owner (private_definer), search_path = '''', SECURITY DEFINER and its ACL (service_role, edge_actor), and carries the name predicate');

SELECT * FROM finish();

-- 17_attest_key_registration.sql
-- App Attest KEY REGISTRATION, database side (0034_attest_key_registration.sql): app.register_attest_key, the
-- one-way counter trigger's single legitimate exception (a key replaced by a never-before-used key), the
-- retired-key list, the audit row, and the privileges around them. The service_role lane (what the Edge Function
-- uses today) runs here; the edge_actor lane (private.register_attest_key_for_actor under a real edge_gateway
-- login) is 17_attest_key_registration_edge.sql, which has to reconnect.
--
-- WHAT THE TYPESCRIPT DECIDES, AND THIS FILE DOES NOT: whether an attestation is genuine (Apple's chain, the
-- nonce, the app id, the aaguid ...) is verified in supabase/functions/_shared/rewards/app-attest-registration.ts
-- (unit tests) before the function below is ever reached. What this file proves is what the DATABASE enforces
-- independently of its caller: a key id must be the hash of its key; only the caller's own iOS device; the same or
-- a retired key is refused; a counter can fall only for a new key, by content and not by role.
--
-- Public keys here are 65 arbitrary bytes starting 0x04: the database checks the SHAPE (and key id = hash of key),
-- not that the point is on the curve (the verifier proved that).

BEGIN;
SELECT plan(97);

SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ---------------------------------------------------------------------------
-- Fixtures and helpers (session-local)
-- ---------------------------------------------------------------------------
-- A public key / key id for "n", and the hash the retired list stores.
CREATE FUNCTION pg_temp.pk(n int) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$ SELECT decode('04' || repeat(lpad(to_hex(n), 2, '0'), 64), 'hex') $$;
CREATE FUNCTION pg_temp.kid(n int) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT encode(sha256(pg_temp.pk(n)), 'base64') $$;
CREATE FUNCTION pg_temp.kh(n int) RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT encode(sha256(convert_to(pg_temp.kid(n), 'UTF8')), 'hex') $$;

-- Player A and B come from helpers.sql. Devices: A1 ios (the main subject), A2 ios (a counter with no key), A3 android,
-- B1 ios (someone else's), A4 ios (the FIFO cap), A5 ios (the hand-written-replacement cells).
INSERT INTO app.device (id, user_id, platform) VALUES
  ('17000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000000a', 'ios'),
  ('17000000-0000-0000-0000-0000000000a2', '00000000-0000-0000-0000-00000000000a', 'ios'),
  ('17000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-00000000000a', 'android'),
  ('17000000-0000-0000-0000-0000000000a4', '00000000-0000-0000-0000-00000000000a', 'ios'),
  ('17000000-0000-0000-0000-0000000000a5', '00000000-0000-0000-0000-00000000000a', 'ios'),
  ('17000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-00000000000b', 'ios');
UPDATE app.device SET attest_counter = 5 WHERE id = '17000000-0000-0000-0000-0000000000a2';

-- ============================================================================
-- 1. Schema
-- ============================================================================
SELECT has_column('app', 'device', 'attest_registered_at', 'device.attest_registered_at exists');
SELECT has_column('app', 'device', 'attest_retired_key_hashes', 'device.attest_retired_key_hashes exists');
SELECT is((SELECT attest_registered_at IS NULL AND attest_retired_key_hashes = '{}' FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), true,
  'a new device has no registered key and no retired keys');
SELECT throws_ok($$UPDATE app.device SET attest_registered_at = now() WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, '23514', NULL,
  'a "registered" device must carry a key id and a public key (device_attest_registered_needs_key)');
SELECT throws_ok(
  format($$UPDATE app.device SET attest_retired_key_hashes = %L::text[] WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, (SELECT array_agg(pg_temp.kh(n))::text FROM generate_series(1, 17) n)),
  '23514', NULL, 'the retired list is capped at 16 (device_attest_retired_cap)');

-- ============================================================================
-- 2. Privileges: who may call it
-- ============================================================================
SELECT is(has_function_privilege('service_role', 'app.register_attest_key(uuid, uuid, text, bytea)', 'EXECUTE'), true, 'service_role may call app.register_attest_key');
SELECT is(has_function_privilege('private_definer', 'app.register_attest_key(uuid, uuid, text, bytea)', 'EXECUTE'), true, 'private_definer may call it (the edge wrapper runs it)');
SELECT is(has_function_privilege('anon', 'app.register_attest_key(uuid, uuid, text, bytea)', 'EXECUTE'), false, 'anon may NOT call it');
SELECT is(has_function_privilege('authenticated', 'app.register_attest_key(uuid, uuid, text, bytea)', 'EXECUTE'), false, 'authenticated may NOT call it');
SELECT is(has_function_privilege('edge_actor', 'app.register_attest_key(uuid, uuid, text, bytea)', 'EXECUTE'), false, 'edge_actor may NOT call it directly (only through the bound-actor wrapper)');
SELECT is(has_function_privilege('edge_system', 'app.register_attest_key(uuid, uuid, text, bytea)', 'EXECUTE'), false, 'edge_system may NOT call it');
SELECT is(has_function_privilege('edge_actor', 'private.register_attest_key_for_actor(uuid, text, bytea)', 'EXECUTE'), true, 'edge_actor may call the bound-actor wrapper');
SELECT is(has_function_privilege('service_role', 'private.register_attest_key_for_actor(uuid, text, bytea)', 'EXECUTE'), false, 'service_role has no business with the wrapper (it has the app function)');
SELECT is(has_function_privilege('anon', 'private.register_attest_key_for_actor(uuid, text, bytea)', 'EXECUTE')
          OR has_function_privilege('authenticated', 'private.register_attest_key_for_actor(uuid, text, bytea)', 'EXECUTE')
          OR has_function_privilege('edge_system', 'private.register_attest_key_for_actor(uuid, text, bytea)', 'EXECUTE'), false, 'neither client role nor edge_system may call the wrapper');
SELECT is((SELECT prosecdef AND pg_get_userbyid(proowner) = 'private_definer' AND 'search_path=""' = ANY (proconfig) FROM pg_proc WHERE oid = 'private.register_attest_key_for_actor(uuid, text, bytea)'::regprocedure),
  true, 'the wrapper is SECURITY DEFINER, owned by private_definer, search_path pinned empty');
SELECT is((SELECT NOT prosecdef FROM pg_proc WHERE oid = 'app.register_attest_key(uuid, uuid, text, bytea)'::regprocedure), true, 'the app function is invoker-rights (the shape of app.activate_*), not a definer');

-- ============================================================================
-- 3. First registration
-- ============================================================================
SELECT is(app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a1', pg_temp.kid(1), pg_temp.pk(1)), 'registered',
  'first registration returns registered');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), pg_temp.kid(1), 'the key id is stored');
SELECT is((SELECT attest_public_key FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), pg_temp.pk(1), 'the public key is stored');
SELECT is((SELECT attest_registered_at IS NOT NULL FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), true, 'attest_registered_at is set (the verifier is handed a key only because of this)');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), 0::bigint, 'the counter starts at 0');
SELECT is((SELECT attest_retired_key_hashes FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), '{}'::text[], 'nothing is retired by a first registration');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE action = 'device.attest_key_registered' AND subject_id = '17000000-0000-0000-0000-0000000000a1' AND actor_user_id = '00000000-0000-0000-0000-00000000000a'),
  1, 'the registration is audited, against the account');
SELECT is((SELECT detail->>'newKeySha256Prefix' FROM app.audit_log WHERE action = 'device.attest_key_registered' AND subject_id = '17000000-0000-0000-0000-0000000000a1'),
  left(pg_temp.kh(1), 16), 'the audit row carries a 16-hex PREFIX of the key hash');
SELECT is((SELECT position(pg_temp.kid(1) IN detail::text) = 0 AND position(encode(pg_temp.pk(1), 'hex') IN detail::text) = 0 FROM app.audit_log WHERE action = 'device.attest_key_registered' AND subject_id = '17000000-0000-0000-0000-0000000000a1'),
  true, 'the audit row carries neither the key id nor the key');
SELECT is((SELECT (detail->'oldKeySha256Prefix') = 'null'::jsonb FROM app.audit_log WHERE action = 'device.attest_key_registered' AND subject_id = '17000000-0000-0000-0000-0000000000a1'),
  true, 'a first registration has no old key');

-- The same key again: refused, nothing changes, no second audit row.
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a1', pg_temp.kid(1), pg_temp.pk(1))$$,
  '55000', NULL, 'registering the same key again is refused (55000)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE subject_id = '17000000-0000-0000-0000-0000000000a1'), 1, 'the refused repeat wrote no audit row');

-- A device whose counter advanced with no key: a first registration leaves the counter alone.
SELECT is(app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', pg_temp.kid(2), pg_temp.pk(2)), 'registered', 'a keyless device registers');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a2'), 5::bigint, 'a first registration leaves the counter exactly as it was');

-- ============================================================================
-- 4. The counter, monotonic per key
-- ============================================================================
UPDATE app.device SET attest_counter = 7 WHERE id = '17000000-0000-0000-0000-0000000000a1';
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), 7::bigint, 'control: the counter still advances');
SELECT throws_ok($$UPDATE app.device SET attest_counter = 3 WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, '23514', NULL, 'the counter cannot fall under the same key (23514)');
SELECT throws_ok($$UPDATE app.device SET attest_counter = 0 WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, '23514', NULL, 'not even to 0');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), 7::bigint, 'and it did not move');

-- ============================================================================
-- 5. Re-registration (a reinstall): a NEW key replaces the old one
-- ============================================================================
SELECT is(app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a1', pg_temp.kid(3), pg_temp.pk(3)), 'replaced', 're-registration with a new key returns replaced');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), pg_temp.kid(3), 'the new key id is stored');
SELECT is((SELECT attest_public_key FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), pg_temp.pk(3), 'the new public key is stored');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), 0::bigint, 'the counter restarts at 0 for the NEW key (the old one had reached 7)');
SELECT is((SELECT attest_retired_key_hashes FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), ARRAY[pg_temp.kh(1)], 'the old key is retired');
SELECT is((SELECT detail->>'counterBefore' FROM app.audit_log WHERE action = 'device.attest_key_replaced' AND subject_id = '17000000-0000-0000-0000-0000000000a1'), '7', 'the replacement is audited with the counter the old key had reached');
SELECT is((SELECT detail->>'oldKeySha256Prefix' FROM app.audit_log WHERE action = 'device.attest_key_replaced' AND subject_id = '17000000-0000-0000-0000-0000000000a1'), left(pg_temp.kh(1), 16), 'the audit row names the old key by hash prefix');
SELECT is((SELECT attest_registered_at IS NOT NULL FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), true, 'the replacement is registered');

-- Anti-replay stays intact: the OLD key cannot come back (so its counter cannot be restarted either).
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a1', pg_temp.kid(1), pg_temp.pk(1))$$,
  '23514', NULL, 'a retired key cannot be registered again (23514)');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), pg_temp.kid(3), 'and the device kept its current key');

-- The same key twice in a row after a replacement is still 55000, not a counter reset.
UPDATE app.device SET attest_counter = 4 WHERE id = '17000000-0000-0000-0000-0000000000a1';
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a1', pg_temp.kid(3), pg_temp.pk(3))$$,
  '55000', NULL, 'registering the CURRENT key again cannot reset its counter');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a1'), 4::bigint, 'the counter is where it was');

-- ============================================================================
-- 6. The trigger decides by CONTENT: direct writes, any role
-- ============================================================================
-- (A5 gets key 20 through the function, counter 9.)
SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a5', pg_temp.kid(20), pg_temp.pk(20));
UPDATE app.device SET attest_counter = 9 WHERE id = '17000000-0000-0000-0000-0000000000a5';
-- (a) a new key, counter 0, but the old key NOT retired: refused.
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0 WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(21), pg_temp.pk(21)),
  '23514', NULL, 'direct: a new key with counter 0 but the old key not retired is refused');
-- (b) the old key retired, a new key, but the counter not 0 and lower than before: refused.
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 3, attest_retired_key_hashes = ARRAY[%L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(21), pg_temp.pk(21), pg_temp.kh(20)),
  '23514', NULL, 'direct: a replacement that starts above 0 but below the old counter is refused');
-- (c) the SAME key with the counter reset to 0 and the key "retired": refused (the key did not change).
SELECT throws_ok(format($$UPDATE app.device SET attest_counter = 0, attest_retired_key_hashes = ARRAY[%L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kh(20)),
  '23514', NULL, 'direct: retiring the current key while keeping it and resetting the counter is refused');
-- (d) a NEW key whose public key did not change: refused.
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(21), pg_temp.kh(20)),
  '23514', NULL, 'direct: a changed key id over the same public key is refused');
-- (e) the new key was ALREADY retired in the old row: refused.
UPDATE app.device SET attest_retired_key_hashes = ARRAY[pg_temp.kh(22)] WHERE id = '17000000-0000-0000-0000-0000000000a5';
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(22), pg_temp.pk(22), pg_temp.kh(22), pg_temp.kh(20)),
  '23514', NULL, 'direct: replacing with a key that is already on the retired list is refused');
-- (e2) the same, but the writer DROPS the new key's entry from the retired list in the same statement ("forgetting" it): refused,
-- because the OLD row's list is checked too, not only the one being written.
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(22), pg_temp.pk(22), pg_temp.kh(20)),
  '23514', NULL, 'direct: replacing with a retired key while dropping its entry from the list in the same statement is refused');
-- (f) the new key retired in the SAME statement: refused.
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(23), pg_temp.pk(23), pg_temp.kh(20), pg_temp.kh(23)),
  '23514', NULL, 'direct: a key retired in the same statement it is installed is refused');
-- (g) no key before: a counter cannot fall to 0 by "installing" a first key.
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a5'), 9::bigint, 'none of the refused statements moved the counter');
-- (h) the legitimate shape, hand-written: allowed, because it is decided by content and not by who wrote it.
SELECT lives_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(21), pg_temp.pk(21), pg_temp.kh(22), pg_temp.kh(20)),
  'direct: a replacement that retires the old key and installs a never-used one may restart at 0 (content, not role)');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a5'), 0::bigint, 'and it did');

-- ============================================================================
-- 7. The retired list keeps the newest 16
-- ============================================================================
SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a4', pg_temp.kid(100), pg_temp.pk(100));
SELECT count(app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a4', pg_temp.kid(n), pg_temp.pk(n))) FROM generate_series(101, 119) AS n;
SELECT is((SELECT cardinality(attest_retired_key_hashes) FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a4'), 16, 'after 19 replacements the list holds 16');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a4'), pg_temp.kid(119), 'the current key is the last one registered');
SELECT is((SELECT attest_retired_key_hashes[16] FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a4'), pg_temp.kh(118), 'the newest retired key is last');
SELECT is((SELECT attest_retired_key_hashes[1] FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a4'), pg_temp.kh(103), 'the oldest 3 have been dropped (FIFO): 100, 101, 102');
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a4', pg_temp.kid(110), pg_temp.pk(110))$$, '23514', NULL, 'a key still on the list cannot return');
SELECT lives_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a4', pg_temp.kid(100), pg_temp.pk(100))$$,
  'a key that has aged off the list can (the documented bound of the history; a key can only be attested once by Apple, so this needs a fresh attestation anyway)');

-- ============================================================================
-- 7b. The retired list only grows, by exactly the replaced key (0036): a hand-written replacement may not FORGET an entry
-- ============================================================================
-- A5 now holds key 21 (counter 0, retired [22, 20] from cell (h) above). Raise its counter (an increase: the trigger lets it
-- through), then try replacements to a never-used key 24 that each leave a DIFFERENT list behind. Only the exact append is accepted.
UPDATE app.device SET attest_counter = 6 WHERE id = '17000000-0000-0000-0000-0000000000a5';
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(24), pg_temp.pk(24), pg_temp.kh(21)),
  '23514', NULL, 'direct: a replacement that forgets BOTH earlier retired entries is refused (0036)');
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(24), pg_temp.pk(24), pg_temp.kh(20), pg_temp.kh(21)),
  '23514', NULL, 'direct: a replacement that forgets ONE earlier retired entry is refused (0036)');
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(24), pg_temp.pk(24), pg_temp.kh(20), pg_temp.kh(22), pg_temp.kh(21)),
  '23514', NULL, 'direct: the right entries in the wrong order are refused (FIFO order is part of the contract)');
SELECT throws_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L, %L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(24), pg_temp.pk(24), pg_temp.kh(22), pg_temp.kh(20), pg_temp.kh(21), pg_temp.kh(99)),
  '23514', NULL, 'direct: an extra, unrelated entry smuggled into the list is refused');
SELECT is((SELECT attest_counter FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a5'), 6::bigint, 'none of the refused statements moved the counter or the list');
SELECT lives_ok(format($$UPDATE app.device SET attest_key_id = %L, attest_public_key = %L, attest_counter = 0, attest_retired_key_hashes = ARRAY[%L, %L, %L] WHERE id = '17000000-0000-0000-0000-0000000000a5'$$, pg_temp.kid(24), pg_temp.pk(24), pg_temp.kh(22), pg_temp.kh(20), pg_temp.kh(21)),
  'direct: the exact append (old list, then the replaced key) is accepted');
SELECT is((SELECT attest_retired_key_hashes FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a5'), ARRAY[pg_temp.kh(22), pg_temp.kh(20), pg_temp.kh(21)], 'and the list is exactly that');

-- AT THE CAP (A4: key 100, 16 retired entries after section 7). A helper attempts a hand-written replacement to key 130 whose
-- list is built from the row's CURRENT list by `mode`, and answers 'ok' or the SQLSTATE the trigger raised (each attempt is its own
-- subtransaction, so a refusal changes nothing).
CREATE FUNCTION pg_temp.replace_at_cap(p_mode text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
  v_dev uuid := '17000000-0000-0000-0000-0000000000a4';
  v_old text[];
  v_oldhash text;
  v_new text[];
BEGIN
  SELECT attest_retired_key_hashes, encode(sha256(convert_to(attest_key_id, 'UTF8')), 'hex') INTO v_old, v_oldhash FROM app.device WHERE id = v_dev;
  v_new := CASE p_mode
    WHEN 'fifo'          THEN v_old[2:16] || v_oldhash                          -- the oldest drops, the rest keep order
    WHEN 'drop_newest'   THEN v_old[1:15] || v_oldhash                          -- 16 entries, but the wrong one dropped
    WHEN 'forget_middle' THEN v_old[1:7] || v_old[9:16] || v_oldhash            -- 16 entries, a middle one forgotten
    WHEN 'swap'          THEN (v_old[2:16] || v_oldhash)[2:2] || (v_old[2:16] || v_oldhash)[1:1] || (v_old[2:16] || v_oldhash)[3:16]
    WHEN 'no_old_hash'   THEN v_old[2:16] || encode(sha256('x'::bytea), 'hex')  -- the replaced key is not on the list at all
  END;
  UPDATE app.device SET attest_key_id = pg_temp.kid(130), attest_public_key = pg_temp.pk(130), attest_counter = 0, attest_retired_key_hashes = v_new WHERE id = v_dev;
  RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE;
END
$f$;
UPDATE app.device SET attest_counter = 7 WHERE id = '17000000-0000-0000-0000-0000000000a4';
SELECT is(pg_temp.replace_at_cap('drop_newest'), '23514', 'at the cap: dropping the NEWEST entry instead of the oldest is refused');
SELECT is(pg_temp.replace_at_cap('forget_middle'), '23514', 'at the cap: forgetting a middle entry (still 16 long) is refused');
SELECT is(pg_temp.replace_at_cap('swap') || pg_temp.replace_at_cap('no_old_hash'), '2351423514', 'at the cap: a reordered list, and one that omits the replaced key, are refused');
SELECT is(pg_temp.replace_at_cap('fifo'), 'ok', 'at the cap: the exact FIFO result (oldest dropped, replaced key appended) is accepted');
SELECT is((SELECT cardinality(attest_retired_key_hashes) FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a4'), 16, 'and the list is still 16 long');
SELECT is((SELECT attest_retired_key_hashes[16] FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a4'), pg_temp.kh(100), 'with the replaced key (100) last');

-- ============================================================================
-- 8. Argument validation and ownership
-- ============================================================================
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000b1', pg_temp.kid(5), pg_temp.pk(5))$$,
  'P0002', NULL, 'another user''s device is P0002 (the caller is A, the device is B''s)');
SELECT is((SELECT attest_key_id IS NULL FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000b1'), true, 'and B''s device was not touched');
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-00000000dead', pg_temp.kid(5), pg_temp.pk(5))$$,
  'P0002', NULL, 'a nonexistent device is the same P0002 (no existence oracle)');
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a3', pg_temp.kid(6), pg_temp.pk(6))$$,
  '22023', NULL, 'an Android device cannot hold an App Attest key (22023)');
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', pg_temp.kid(7), pg_temp.pk(8))$$,
  '22023', NULL, 'a key id that is not the hash of the key is refused (22023)');
SELECT throws_ok(format($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', %L, %L)$$, encode(sha256('\x04'::bytea), 'base64'), '\x04'::bytea),
  '22023', NULL, 'a public key that is not 65 bytes is refused');
SELECT throws_ok(format($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', %L, %L)$$,
    encode(sha256(decode('02' || repeat('ab', 64), 'hex')), 'base64'), decode('02' || repeat('ab', 64), 'hex')),
  '22023', NULL, 'a 65-byte key that is not an UNCOMPRESSED point (first byte not 0x04) is refused');
SELECT throws_ok(format($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', %L, %L)$$, 'not-a-key-id', pg_temp.pk(9)),
  '22023', NULL, 'a malformed key id is refused');
SELECT throws_ok($$SELECT app.register_attest_key(NULL, '17000000-0000-0000-0000-0000000000a2', pg_temp.kid(9), pg_temp.pk(9))$$, '22023', NULL, 'a NULL user is refused');
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', pg_temp.kid(9), NULL)$$, '22023', NULL, 'a NULL key is refused');
SELECT is((SELECT attest_key_id FROM app.device WHERE id = '17000000-0000-0000-0000-0000000000a2'), pg_temp.kid(2), 'none of the refused calls changed the device');

-- ============================================================================
-- 9. Who can read or write the new columns
-- ============================================================================
SELECT tests.authenticate_as('authenticated', tests.claims('00000000-0000-0000-0000-00000000000a'::uuid));
SELECT throws_ok($$UPDATE app.device SET attest_registered_at = now() WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, '42501', NULL, 'authenticated cannot write attest_registered_at');
SELECT throws_ok($$UPDATE app.device SET attest_retired_key_hashes = '{}' WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, '42501', NULL, 'authenticated cannot write attest_retired_key_hashes');
SELECT throws_ok($$UPDATE app.device SET attest_public_key = NULL WHERE id = '17000000-0000-0000-0000-0000000000a1'$$, '42501', NULL, 'authenticated cannot write attest_public_key');
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', pg_temp.kid(30), pg_temp.pk(30))$$, '42501', 'permission denied for function register_attest_key', 'authenticated cannot call the function');
SELECT is((SELECT count(*)::int FROM information_schema.columns WHERE table_schema = 'api' AND table_name = 'my_device' AND column_name IN ('attest_public_key', 'attest_registered_at', 'attest_retired_key_hashes')),
  0, 'api.my_device exposes none of the key columns');
SELECT tests.authenticate_as('anon', '{}'::jsonb);
SELECT throws_ok($$SELECT app.register_attest_key('00000000-0000-0000-0000-00000000000a', '17000000-0000-0000-0000-0000000000a2', pg_temp.kid(30), pg_temp.pk(30))$$, '42501', 'permission denied for schema app', 'anon cannot call the function (no USAGE on schema app)');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- ============================================================================
-- 10. Export and deletion
-- ============================================================================
-- The export names explicit columns: none of the new ones, and not the public key.
SELECT is((SELECT (private.export_my_data('00000000-0000-0000-0000-00000000000a')::text) !~ '(attest_registered_at|attest_retired_key_hashes|attest_public_key)'), true,
  'GET /v1/me/export does not carry the new key columns or the public key');
-- Deletion: a throw-away account with a registered key.
INSERT INTO auth.users (id) VALUES ('17000000-0000-0000-0000-00000000f001');
INSERT INTO app.profile (user_id, handle) VALUES ('17000000-0000-0000-0000-00000000f001', 'attest_key_f1');
INSERT INTO app.device (id, user_id, platform) VALUES ('17000000-0000-0000-0000-0000000f0d01', '17000000-0000-0000-0000-00000000f001', 'ios');
SELECT app.register_attest_key('17000000-0000-0000-0000-00000000f001', '17000000-0000-0000-0000-0000000f0d01', pg_temp.kid(40), pg_temp.pk(40));
SELECT app.register_attest_key('17000000-0000-0000-0000-00000000f001', '17000000-0000-0000-0000-0000000f0d01', pg_temp.kid(41), pg_temp.pk(41));
SELECT lives_ok($$SELECT private.delete_my_data('17000000-0000-0000-0000-00000000f001')$$, 'delete_my_data works for an account with a registered (and replaced) key');
SELECT is((SELECT count(*)::int FROM app.device WHERE user_id = '17000000-0000-0000-0000-00000000f001'), 0, 'the device (and its key) is gone');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '17000000-0000-0000-0000-00000000f001'), 0, 'the audit rows no longer name the account (actor redacted)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE subject_id = '17000000-0000-0000-0000-0000000f0d01' AND actor_user_id IS NULL AND action IN ('device.attest_key_registered', 'device.attest_key_replaced')), 2,
  'the two audit rows survive with the actor redacted (hash prefixes and a device id that no longer exists)');

SELECT * FROM finish();
ROLLBACK;

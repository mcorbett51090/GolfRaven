-- 17_signin_providers.sql
-- 0035_signin_providers.sql, the CORE (service_role) lane and the structural invariants: sign-in method linking and
-- unlinking under the §3.4 rules, the envelope-encrypted provider grant, the durable revocation queue (§7.8, Apple
-- 5.1.1(v)), the Vault KEK reader, and the OTP-proof failure counter (§4.7 item 8). The edge_actor / edge_system lane is
-- 18_signin_providers_edge.sql (it must reconnect as a real edge_gateway login, so it is its own file).
--
-- No secret in this file: the KEK it seeds into the Vault stand-in is generated at run time (gen_random_bytes), the
-- "ciphertexts" are filler bytes (the database never decrypts), and every id is a synthetic constant.
--
-- Every group is its own BEGIN ... ROLLBACK except the session-reuse group (needs a real COMMIT, the P3a follow-up 1
-- style, see 12_guc_session_reuse.sql), which cleans up after itself.

SELECT plan(150);

-- ----------------------------------------------------------------------------
-- 0. Structure
-- ----------------------------------------------------------------------------
SELECT is((SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'private.signin_revocation_queue'::regclass), true,
  'structure: private.signin_revocation_queue has RLS enabled AND forced');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'private.signin_revocation_queue'::regclass AND k.contype = 'f'), 0,
  'registry classification: the queue has NO foreign key at all (so none to auth.users): it is not a personal row, and there is nothing for pii_retention_policy to classify');
SELECT is((SELECT count(*)::int FROM information_schema.columns WHERE table_schema = 'private' AND table_name = 'signin_revocation_queue' AND (column_name ILIKE '%user%' OR column_name ILIKE '%uid%' OR column_name ILIKE '%email%' OR column_name ILIKE '%handle%')), 0,
  'registry classification: the queue has no column that names a user, an email or a handle (a future one fails here)');
-- (read as service_role: the registries are FORCE RLS and only service_role has a policy/grant on them; under HARNESS_MODE=restricted the
-- harness role itself would read zero rows and these two cells would pass or fail for the wrong reason)
SET ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.pii_retention_policy WHERE table_name = 'signin_revocation_queue'), 0, 'registry classification: the queue is in no retention registry (nothing personal to retain)');
SELECT is((SELECT action::text FROM private.pii_export_policy WHERE schema_name = 'app' AND table_name = 'signin_provider_token'), 'exclude',
  'export: app.signin_provider_token stays EXCLUDED from the data export (0022): nothing exports a provider grant');
SELECT is((SELECT count(*)::int FROM private.pii_export_policy WHERE table_name = 'signin_provider_token'), 1, 'export: ... and the registry row is visible to this probe (so the cell above is not a vacuous NULL)');
RESET ROLE;
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system')) r(n)
           WHERE has_table_privilege(r.n, 'private.signin_revocation_queue', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
              OR has_any_column_privilege(r.n, 'private.signin_revocation_queue', 'SELECT,INSERT,UPDATE,REFERENCES')), 0,
  'structure: no role but private_definer holds ANY privilege on the revocation queue');
SELECT is(has_table_privilege('private_definer', 'private.signin_revocation_queue', 'SELECT,INSERT,UPDATE,DELETE'), true, 'structure: private_definer does hold what the queue definers need');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('edge_actor'), ('edge_system'), ('edge_gateway')) r(n)
           WHERE has_any_column_privilege(r.n, 'app.signin_provider_token', 'INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.n, 'app.signin_provider_token', 'DELETE,TRUNCATE')), 0,
  'structure: no client or edge role can write app.signin_provider_token (every write is a private_definer function)');
SELECT is(has_column_privilege('edge_actor', 'app.signin_provider_token', 'refresh_token_ciphertext', 'SELECT') OR has_column_privilege('edge_actor', 'app.signin_provider_token', 'dek_wrapped', 'SELECT'), false,
  'structure: edge_actor still cannot read the ciphertext or the wrapped DEK (0031 column grant: user_id, provider only)');
SELECT is(has_column_privilege('private_definer', 'auth.identities', 'email', 'SELECT') OR has_table_privilege('private_definer', 'auth.identities', 'UPDATE'), false,
  'structure: private_definer holds only the narrow auth.identities slice 0035 grants (no UPDATE, no generated email column)');
SELECT is((SELECT bool_and(has_column_privilege('private_definer', 'auth.identities', c, 'SELECT')) FROM unnest(ARRAY['user_id', 'provider', 'provider_id', 'identity_data', 'created_at']) c)
          AND (SELECT bool_and(has_column_privilege('private_definer', 'auth.identities', c, 'INSERT')) FROM unnest(ARRAY['provider_id', 'user_id', 'identity_data', 'provider', 'last_sign_in_at']) c)
          AND has_table_privilege('private_definer', 'auth.identities', 'DELETE'), true,
  'structure (F8): every auth.identities privilege 0035 needs is held by private_definer (the migration RAISEs itself if a GRANT only warned)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'app.signin_provider_token'::regclass AND (p.polroles @> ARRAY[0]::oid[])), 0,
  'structure: no PUBLIC policy on app.signin_provider_token (FORCE RLS still admits nobody but the named roles)');
SELECT is((SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'app.signin_provider_token'::regclass), true, 'structure: app.signin_provider_token keeps FORCE ROW LEVEL SECURITY');
SELECT is(has_function_privilege('authenticated', 'private.signin_unlink_identity(uuid, text)', 'EXECUTE')
          OR has_function_privilege('anon', 'private.signin_link_identity(uuid, text, text, text, boolean, boolean)', 'EXECUTE')
          OR has_function_privilege('authenticated', 'private.get_signin_token_kek(text)', 'EXECUTE')
          OR has_function_privilege('anon', 'private.claim_signin_revocations(uuid[], integer, integer)', 'EXECUTE'), false,
  'structure: no client role can EXECUTE a sign-in definer');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND (p.proname LIKE 'signin\_%' OR p.proname LIKE '%\_signin\_%')
             AND NOT (p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig))), 0,
  'structure: every sign-in function is SECURITY DEFINER, owned by private_definer, with search_path = ''''');

-- ----------------------------------------------------------------------------
-- fixtures for the groups below (inside each group's own transaction, rolled back)
--   U1 (u1@signin.test, email identity)            the actor in most cells
--   U2 (u2@signin.test, email + google identities) "someone else"
-- ----------------------------------------------------------------------------

-- ----------------------------------------------------------------------------
-- 1. The Vault KEK reader
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok($$INSERT INTO vault.secrets (name, secret) VALUES ('siwa_token_kek_t1', encode(gen_random_bytes(32), 'base64'))$$, 'kek: seed a run-time-random KEK t1 into the Vault stand-in');
SELECT is((SELECT o_kek_id FROM private.get_signin_token_kek(NULL)), 't1', 'kek: NULL asks for the newest key (only t1 exists)');
SELECT is((SELECT length(o_kek_b64) FROM private.get_signin_token_kek('t1')), 44, 'kek: a named key comes back as 44 base64 characters (32 bytes)');
SELECT lives_ok($$INSERT INTO vault.secrets (name, secret, created_at) VALUES ('siwa_token_kek_t2', encode(gen_random_bytes(32), 'base64'), now() + interval '1 minute')$$, 'kek: seed a NEWER key t2');
SELECT is((SELECT o_kek_id FROM private.get_signin_token_kek(NULL)), 't2', 'kek: NULL now returns the NEWEST key (wraps new DEKs)');
SELECT is((SELECT o_kek_id FROM private.get_signin_token_kek('t1')), 't1', 'kek: the OLD key is still reachable by id (unwraps stored DEKs)');
SELECT throws_ok($$SELECT * FROM private.get_signin_token_kek('nope')$$, 'P0002', NULL, 'kek: an unknown key id is P0002');
SELECT throws_ok($$SELECT * FROM private.get_signin_token_kek('BAD ID;--')$$, '22023', NULL, 'kek: a malformed key id is refused before it is looked up');
SELECT lives_ok($$INSERT INTO vault.secrets (name, secret) VALUES ('siwa_token_kek_short', 'too-short')$$, 'kek: seed a malformed secret');
SELECT throws_ok($$SELECT * FROM private.get_signin_token_kek('short')$$, '22023', NULL, 'kek: a Vault secret that is not a base64 32-byte key is refused (and never echoed in the message)');
SELECT is((SELECT count(*)::int FROM vault.secrets WHERE name = 'siwa_token_kek_x'), 0, 'kek: (control) the key id is only ever matched, never created by the reader');
RESET ROLE;
SELECT tests.authenticate_as('authenticated', '{"sub":"00000000-0000-0000-0000-000000000001"}'::jsonb);
SELECT throws_ok($$SELECT * FROM private.get_signin_token_kek('t1')$$, '42501', NULL, 'kek: a client role cannot call the KEK reader');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 2. Methods, linking (the §3.4 rules at the database), tokens
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a0000-0000-0000-0000-000000000001', 'u1@signin.test'),
  ('5a5a0000-0000-0000-0000-000000000002', 'u2@signin.test'),
  ('5a5a0000-0000-0000-0000-000000000003', 'u3@signin.test');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('u1@signin.test', '5a5a0000-0000-0000-0000-000000000001', '{"email":"u1@signin.test","email_verified":true}', 'email'),
  ('u2@signin.test', '5a5a0000-0000-0000-0000-000000000002', '{"email":"u2@signin.test","email_verified":true}', 'email'),
  ('g-sub-2', '5a5a0000-0000-0000-0000-000000000002', '{"email":"u2@signin.test","email_verified":true}', 'google'),
  ('u3@signin.test', '5a5a0000-0000-0000-0000-000000000003', '{"email":"u3@signin.test","email_verified":true}', 'email');

SELECT is((SELECT count(*)::int FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000001')), 1, 'methods: U1 has exactly one method');
SELECT is((SELECT o_provider FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000001')), 'email', 'methods: ... the email identity');
SELECT is((SELECT o_has_token FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000001')), false, 'methods: ... with no stored provider grant');
SELECT is((SELECT count(*)::int FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000002')), 2, 'methods: U2 has two (email and google), U1''s call never returned them');
SELECT throws_ok($$SELECT * FROM private.signin_methods(NULL)$$, '22023', NULL, 'methods: a NULL user id is refused');
SELECT is((SELECT count(*)::int FROM private.signin_methods('5a5a0000-0000-0000-0000-0000000000ff')), 0, 'methods: an unknown user has no methods (no error, no oracle)');

SELECT is(private.signin_find_account_by_email('U2@Signin.TEST '), '5a5a0000-0000-0000-0000-000000000002'::uuid, 'find by email: case-insensitive and trimmed (one account per verified email, rule 1)');
SELECT is(private.signin_find_account_by_email('nobody@signin.test'), NULL, 'find by email: no match is NULL');
SELECT is(private.signin_find_account_by_email(NULL), NULL, 'find by email: NULL is NULL');
SELECT is(private.signin_find_account_by_email('   '), NULL, 'find by email: blank is NULL');

SELECT is(private.signin_link_identity('5a5a0000-0000-0000-0000-000000000001', 'apple', 'a-sub-1', 'u1@signin.test', true, false), true, 'link: apple links to U1 (returns true: created)');
SELECT is((SELECT count(*)::int FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000001')), 2, 'link: U1 now has two methods');
SELECT is(private.signin_link_identity('5a5a0000-0000-0000-0000-000000000001', 'apple', 'a-sub-1', 'u1@signin.test', true, false), false, 'link: the SAME identity again is false, not an error (idempotent capture re-run)');
SELECT is((SELECT count(*)::int FROM auth.identities WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 2, 'link: ... and created no duplicate row');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a0000-0000-0000-0000-000000000002', 'apple', 'a-sub-1', 'u2@signin.test', true, false)$$, '23505', NULL,
  'link: another account''s apple identity can NEVER be linked (never moved: one account per identity)');
SELECT is((SELECT user_id::text FROM auth.identities WHERE provider = 'apple' AND provider_id = 'a-sub-1'), '5a5a0000-0000-0000-0000-000000000001', 'link: ... and it still belongs to U1');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a0000-0000-0000-0000-000000000001', 'apple', 'a-sub-OTHER', 'x@y.test', true, false)$$, '23505', NULL,
  'link: a second, DIFFERENT apple identity on the same account is refused (one Apple per account)');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a0000-0000-0000-0000-000000000001', 'email', 'x', 'x@y.test', true, false)$$, '22023', NULL, 'link: an email identity is never created here (GoTrue''s own OTP sign-in does that)');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a0000-0000-0000-0000-0000000000ff', 'apple', 'a-sub-9', NULL, false, false)$$, 'P0002', NULL, 'link: an unknown user is P0002');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a0000-0000-0000-0000-000000000003', 'apple', '', NULL, false, false)$$, '22023', NULL, 'link: an empty subject is refused');
SELECT throws_ok($$SELECT private.signin_link_identity('5a5a0000-0000-0000-0000-000000000003', 'apple', repeat('x', 300), NULL, false, false)$$, '22023', NULL, 'link: an over-long subject is refused');
-- the private-relay address is its own email (rule 3): recorded as given, flagged, and a relay account never matches a real one.
SELECT is(private.signin_link_identity('5a5a0000-0000-0000-0000-000000000003', 'apple', 'a-sub-3', 'abc123@privaterelay.appleid.com', true, true), true, 'relay: an Apple private-relay identity links from the signed-in account');
SELECT is((SELECT o_is_private_relay FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000003') WHERE o_provider = 'apple'), true, 'relay: ... and is reported as a relay address');
SELECT is((SELECT o_email FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000003') WHERE o_provider = 'apple'), 'abc123@privaterelay.appleid.com', 'relay: ... with the relay address as ITS OWN email (not U3''s real one)');
SELECT is(private.signin_find_account_by_email('abc123@privaterelay.appleid.com'), NULL, 'relay: the relay address does not match any account email, so it never triggers the existing-account OTP-proof path');

-- store_token
SELECT throws_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000002', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 't1')$$, 'P0002', NULL,
  'store: a token needs a LINKED identity of that provider (U2 has no apple identity)');
SELECT throws_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode('abcd', 'hex'), decode(repeat('cd', 70), 'hex'), 't1')$$, '22023', NULL, 'store: a too-short ciphertext is refused');
SELECT throws_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ab', 40), 'hex'), decode('cdcd', 'hex'), 't1')$$, '22023', NULL, 'store: a too-short wrapped DEK is refused');
SELECT throws_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 'BAD ID')$$, '22023', NULL, 'store: a malformed kek id is refused');
SELECT lives_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 't1')$$, 'store: the envelope is stored for U1''s linked apple identity');
SELECT is((SELECT o_has_token FROM private.signin_methods('5a5a0000-0000-0000-0000-000000000001') WHERE o_provider = 'apple'), true, 'store: ... methods now reports a revocable grant');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 1, 'store: exactly one grant row for U1');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000002'), 0, 'store: ... and none for U2');
SELECT lives_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 't1')$$, 'store: storing the SAME envelope again is a no-op upsert');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE token_fingerprint = md5(decode(repeat('ab', 40), 'hex'))), 0, 'store: ... that queued no revocation (nothing was superseded)');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok($$SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ee', 40), 'hex'), decode(repeat('ff', 70), 'hex'), 't2')$$, 'store: a re-capture with a DIFFERENT token replaces the stored one');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE source = 'replaced' AND status = 'pending' AND provider = 'apple' AND token_fingerprint = md5(decode(repeat('ab', 40), 'hex'))), 1, 'store: ... and the SUPERSEDED refresh token is queued for revocation (it stays valid at the provider until revoked)');
SELECT is((SELECT encode(refresh_token_ciphertext, 'hex') FROM private.signin_revocation_queue WHERE source = 'replaced' AND token_fingerprint = md5(decode(repeat('ab', 40), 'hex'))), repeat('ab', 40), 'store: ... the queue row holds the OLD envelope, not the new one');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT kek_id FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 't2', 'store: the stored row carries the new kek id');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. Unlinking (rule 4) and the revocation queue
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a0000-0000-0000-0000-000000000001', 'u1@signin.test'),
  ('5a5a0000-0000-0000-0000-000000000002', 'u2@signin.test');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('u1@signin.test', '5a5a0000-0000-0000-0000-000000000001', '{"email":"u1@signin.test"}', 'email'),
  ('a-sub-1', '5a5a0000-0000-0000-0000-000000000001', '{"email":"u1@signin.test"}', 'apple'),
  ('u2@signin.test', '5a5a0000-0000-0000-0000-000000000002', '{"email":"u2@signin.test"}', 'email'),
  ('g-sub-2', '5a5a0000-0000-0000-0000-000000000002', '{"email":"u2@signin.test"}', 'google');
SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 't1');
SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000002', 'google', decode(repeat('12', 40), 'hex'), decode(repeat('34', 70), 'hex'), 't1');

SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000001', 'google')$$, 'P0002', NULL,
  'unlink: ANOTHER account''s method cannot be unlinked through this account (U2 has google, U1 does not)');
SELECT is((SELECT count(*)::int FROM auth.identities WHERE user_id = '5a5a0000-0000-0000-0000-000000000002' AND provider = 'google'), 1, 'unlink: ... and U2''s google identity is untouched');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000002'), 1, 'unlink: ... and so is its grant');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000001', 'facebook')$$, '22023', NULL, 'unlink: an unknown provider is refused');
SELECT is((SELECT count(*)::int FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000001', 'apple')), 1, 'unlink: apple unlinks while the email method remains, and returns the queue id of its revocation');
SELECT is((SELECT count(*)::int FROM auth.identities WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 1, 'unlink: the apple identity is gone');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 0, 'unlink: the grant row is gone');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE source = 'unlink' AND provider = 'apple' AND status = 'pending' AND refresh_token_ciphertext IS NOT NULL AND token_fingerprint = md5(decode(repeat('ab', 40), 'hex'))), 1,
  'unlink: the provider grant was queued for revocation (pending, with its envelope) BEFORE the row was deleted');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000001', 'email')$$, '55000', NULL,
  'unlink: the LAST method cannot be unlinked (the Edge code answers 422 last_sign_in_method)');
SELECT is((SELECT count(*)::int FROM auth.identities WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 1, 'unlink: ... and it is still there');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000001', 'apple')$$, 'P0002', NULL, 'unlink: unlinking a method that is not linked is P0002 (and the retry never loses a queued row)');
SELECT is((SELECT count(*)::int FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000002', 'email')), 0, 'unlink: an email method with no grant unlinks while google remains, and queues nothing');
SELECT throws_ok($$SELECT * FROM private.signin_unlink_identity('5a5a0000-0000-0000-0000-000000000002', 'google')$$, '55000', NULL, 'unlink: ... and now google is the last method');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000002'), 1, 'unlink: ... its grant is untouched by the refused unlink');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. DELETE /v1/me: enqueue before delete; the queue outlives the account; claim / complete / purge
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a0000-0000-0000-0000-000000000001', 'u1@signin.test'),
  ('5a5a0000-0000-0000-0000-000000000002', 'u2@signin.test');
INSERT INTO app.profile (user_id, handle) VALUES ('5a5a0000-0000-0000-0000-000000000001', 'signin_u1'), ('5a5a0000-0000-0000-0000-000000000002', 'signin_u2');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('u1@signin.test', '5a5a0000-0000-0000-0000-000000000001', '{"email":"u1@signin.test"}', 'email'),
  ('a-sub-1', '5a5a0000-0000-0000-0000-000000000001', '{"email":"u1@signin.test"}', 'apple'),
  ('g-sub-1', '5a5a0000-0000-0000-0000-000000000001', '{"email":"u1@signin.test"}', 'google'),
  ('u2@signin.test', '5a5a0000-0000-0000-0000-000000000002', '{"email":"u2@signin.test"}', 'email'),
  ('a-sub-2', '5a5a0000-0000-0000-0000-000000000002', '{"email":"u2@signin.test"}', 'apple');
SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 't1');
SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000001', 'google', decode(repeat('12', 40), 'hex'), decode(repeat('34', 70), 'hex'), 't1');
SELECT private.signin_store_token('5a5a0000-0000-0000-0000-000000000002', 'apple', decode(repeat('56', 40), 'hex'), decode(repeat('78', 70), 'hex'), 't1');

SELECT is((SELECT count(*)::int FROM private.signin_enqueue_revocations('5a5a0000-0000-0000-0000-000000000001')), 2, 'enqueue: both of U1''s provider grants are queued');
SELECT is((SELECT count(*)::int FROM private.signin_enqueue_revocations('5a5a0000-0000-0000-0000-000000000001')), 2, 'enqueue: a retry returns the SAME two pending rows (idempotent)');
SELECT (array_agg(o_queue_id ORDER BY o_provider))[1] AS q_apple, (array_agg(o_queue_id ORDER BY o_provider))[2] AS q_google FROM private.signin_enqueue_revocations('5a5a0000-0000-0000-0000-000000000001') \gset
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE token_fingerprint IN (md5(decode(repeat('ab', 40), 'hex')), md5(decode(repeat('12', 40), 'hex')), md5(decode(repeat('56', 40), 'hex')))), 2, 'enqueue: ... and created no duplicate (U2''s grant is not queued)');
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE source = 'account_delete' AND status = 'pending' AND id IN (:'q_apple'::uuid, :'q_google'::uuid)), 2, 'enqueue: both rows are pending, source account_delete');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.signin_enqueue_revocations('5a5a0000-0000-0000-0000-0000000000ff')), 0, 'enqueue: an account with no grant queues nothing');
SELECT throws_ok($$SELECT * FROM private.signin_enqueue_revocations(NULL)$$, '22023', NULL, 'enqueue: a NULL user id is refused');

-- the deletion itself, as the Edge code runs it after the provider was told: the grant row goes, the queue row stays.
SELECT lives_ok($$SELECT private.delete_my_data('5a5a0000-0000-0000-0000-000000000001')$$, 'delete: private.delete_my_data (unchanged) removes the account');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '5a5a0000-0000-0000-0000-000000000001'), 0, 'delete: the grant rows are gone');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE status = 'pending' AND id IN (:'q_apple'::uuid, :'q_google'::uuid)), 2, 'delete: ... the queue rows OUTLIVE the account (the revocation retries for 72 h without any personal row)');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- claim
SELECT throws_ok($$SELECT * FROM private.claim_signin_revocations(NULL, 0, 60)$$, '22023', NULL, 'claim: a zero limit is refused');
SELECT throws_ok($$SELECT * FROM private.claim_signin_revocations(NULL, 10, 5)$$, '22023', NULL, 'claim: a lease under 30 s is refused');
SELECT is((SELECT count(*)::int FROM private.claim_signin_revocations(ARRAY['00000000-0000-0000-0000-00000000dead']::uuid[], 10, 60)), 0, 'claim: an unknown queue id claims nothing');
-- \gset fails unless exactly ONE row comes back, so the next two cells are also the proof that the limit of 1 is honoured
-- with two pending rows present.
SELECT o_id AS claimed_id, (octet_length(o_ciphertext) > 0 AND octet_length(o_dek_wrapped) > 0 AND o_kek_id = 't1') AS claimed_ok
FROM private.claim_signin_revocations(ARRAY[:'q_apple'::uuid, :'q_google'::uuid], 1, 60) \gset
SELECT pass('claim: the limit of 1 is honoured (\gset saw exactly one row)');
SELECT is(:'claimed_ok'::boolean, true, 'claim: the claimed row carries its envelope for the Edge code to decrypt');
SELECT is((SELECT count(*)::int FROM private.claim_signin_revocations(ARRAY[:'q_apple'::uuid, :'q_google'::uuid], 10, 60)), 1, 'claim: the leased row is NOT handed out again; the other pending one is');
SELECT is((SELECT count(*)::int FROM private.claim_signin_revocations(ARRAY[:'q_apple'::uuid, :'q_google'::uuid], 10, 60)), 0, 'claim: ... and now both are leased, so a second worker gets nothing');
SELECT is(private.complete_signin_revocation(:'claimed_id'::uuid, 'retry', 'vendor_5xx', 30), 'pending', 'complete: a retry keeps the row pending');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT attempts FROM private.signin_revocation_queue WHERE id = :'claimed_id'::uuid), 1, 'complete: ... attempts counted');
SELECT is((SELECT last_error FROM private.signin_revocation_queue WHERE id = :'claimed_id'::uuid), 'vendor_5xx', 'complete: ... the short error code recorded');
SELECT is((SELECT next_attempt_at > now() FROM private.signin_revocation_queue WHERE id = :'claimed_id'::uuid), true, 'complete: ... and the next attempt pushed out');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(private.complete_signin_revocation(:'claimed_id'::uuid, 'retry', 'Bearer ey.SECRET text with spaces', 30), 'pending', 'complete: an error string that is not a short code is accepted but NOT stored verbatim');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT last_error FROM private.signin_revocation_queue WHERE id = :'claimed_id'::uuid), 'unclassified', 'complete: ... it becomes ''unclassified'' (a provider response could echo a token)');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT throws_ok($$SELECT private.complete_signin_revocation('00000000-0000-0000-0000-00000000dead', 'revoked', NULL, 30)$$, 'P0002', NULL, 'complete: an unknown queue row is P0002');
SELECT throws_ok($$SELECT private.complete_signin_revocation(gen_random_uuid(), 'maybe', NULL, 30)$$, '22023', NULL, 'complete: an outcome other than revoked / retry is refused');
SELECT is(private.complete_signin_revocation(:'claimed_id'::uuid, 'revoked', NULL, 30), 'revoked', 'complete: revoked closes the row');
SELECT is(private.complete_signin_revocation(:'claimed_id'::uuid, 'retry', 'again', 30), 'revoked', 'complete: ... and a late duplicate completion is idempotent (stays revoked)');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT refresh_token_ciphertext IS NULL AND dek_wrapped IS NULL AND kek_id IS NULL AND status = 'revoked' AND completed_at IS NOT NULL FROM private.signin_revocation_queue WHERE id = :'claimed_id'::uuid), true,
  'complete: a finished row holds NO credential material (the CHECK makes a pending row without one, and a finished row with one, impossible)');
SELECT throws_ok($$UPDATE private.signin_revocation_queue SET refresh_token_ciphertext = '\x00' WHERE status = 'revoked'$$, '23514', NULL, 'complete: ... and the CHECK refuses to put material back on a finished row');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- 72 h expiry
RESET ROLE;
SET LOCAL ROLE private_definer;
UPDATE private.signin_revocation_queue SET expires_at = now() - interval '1 minute', next_attempt_at = now() - interval '1 minute' WHERE status = 'pending' AND id IN (:'q_apple'::uuid, :'q_google'::uuid);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is((SELECT count(*)::int FROM private.claim_signin_revocations(ARRAY[:'q_apple'::uuid, :'q_google'::uuid], 10, 60)), 0, 'expiry: a row past its 72 h is not claimed');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE status = 'expired' AND refresh_token_ciphertext IS NULL AND last_error = 'expired_unrevoked' AND id IN (:'q_apple'::uuid, :'q_google'::uuid)), 1, 'expiry: ... it is marked expired, its credential material is wiped, and the give-up is recorded');
-- purge
SELECT is((SELECT count(*)::int FROM private.signin_revocation_queue WHERE status <> 'pending' AND id IN (:'q_apple'::uuid, :'q_google'::uuid)), 2, 'purge: two finished rows (revoked, expired) exist');
UPDATE private.signin_revocation_queue SET completed_at = now() - interval '40 days' WHERE status = 'expired' AND id IN (:'q_apple'::uuid, :'q_google'::uuid);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT throws_ok($$SELECT private.purge_signin_revocation_queue(interval '1 hour')$$, '22023', NULL, 'purge: an age under a day is refused');
SELECT is(private.purge_signin_revocation_queue(interval '30 days'), 1, 'purge: only the finished row OLDER than the age is deleted (the recent revoked one stays)');
SELECT throws_ok($$SELECT * FROM private.signin_revocation_queue$$, '42501', NULL, 'queue: service_role cannot read the queue table directly (only through the definers)');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4b. Re-enqueueing never resets a queued row; the purge never touches a pending one
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES ('5a5a0000-0000-0000-0000-0000000000b2', 'u4b@signin.test');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('u4b@signin.test', '5a5a0000-0000-0000-0000-0000000000b2', '{"email":"u4b@signin.test"}', 'email'),
  ('a-sub-4b', '5a5a0000-0000-0000-0000-0000000000b2', '{"email":"u4b@signin.test"}', 'apple');
SELECT private.signin_store_token('5a5a0000-0000-0000-0000-0000000000b2', 'apple', decode(repeat('9a', 40), 'hex'), decode(repeat('9b', 70), 'hex'), 't1');
SELECT o_queue_id AS q4b FROM private.signin_enqueue_revocations('5a5a0000-0000-0000-0000-0000000000b2') \gset
SELECT is((SELECT count(*)::int FROM private.claim_signin_revocations(ARRAY[:'q4b']::uuid[], 5, 60)), 1, 're-enqueue: the new row is claimable');
SELECT is(private.complete_signin_revocation(:'q4b'::uuid, 'retry', 'vendor_5xx', 600), 'pending', 're-enqueue: one failed attempt recorded');
SELECT is((SELECT o_queue_id FROM private.signin_enqueue_revocations('5a5a0000-0000-0000-0000-0000000000b2')), :'q4b'::uuid, 're-enqueue: a retried DELETE /v1/me gets the SAME queue row back (idempotent)');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT attempts FROM private.signin_revocation_queue WHERE id = :'q4b'::uuid), 1, 're-enqueue: ... and did NOT reset its attempt count');
SELECT is((SELECT last_error FROM private.signin_revocation_queue WHERE id = :'q4b'::uuid), 'vendor_5xx', 're-enqueue: ... nor its recorded error');
SELECT is((SELECT next_attempt_at > now() + interval '5 minutes' FROM private.signin_revocation_queue WHERE id = :'q4b'::uuid), true, 're-enqueue: ... nor its backed-off next attempt (a re-enqueue cannot hurry a retry)');
UPDATE private.signin_revocation_queue SET created_at = now() - interval '60 days' WHERE id = :'q4b'::uuid;
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(private.purge_signin_revocation_queue(interval '1 day'), 0, 'purge: a PENDING row is never purged, however old');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is((SELECT status FROM private.signin_revocation_queue WHERE id = :'q4b'::uuid), 'pending', 'purge: ... it is still pending');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 5. The OTP-proof failure counter (§4.7 item 8: 5 failed proofs per target email per hour)
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(private.peek_signin_otp_failures(encode(digest('a@x.test', 'sha256'), 'hex')), 0, 'otp: no attempts yet for a fresh email hash');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 1, 'otp: the first reservation is attempt 1');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 2, 'otp: ... then 2');
SELECT is(private.peek_signin_otp_failures(encode(digest('a@x.test', 'sha256'), 'hex')), 2, 'otp: peek reads the count without moving it');
SELECT is(private.peek_signin_otp_failures(encode(digest('a@x.test', 'sha256'), 'hex')), 2, 'otp: ... twice');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('b@x.test', 'sha256'), 'hex')), 1, 'otp: a different target email has its own bucket');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 3, 'otp: the first email continues at 3');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 4, 'otp: 4');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 5, 'otp: 5 (the cap)');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), -1, 'otp: at the cap a reservation is REFUSED (-1): the cap check and the increment are one statement (F3)');
SELECT is(private.peek_signin_otp_failures(encode(digest('a@x.test', 'sha256'), 'hex')), 5, 'otp: ... and the refused reservation did not move the count');
SELECT is(private.release_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 4, 'otp: a release gives one attempt back (a proof that succeeded is not a failure)');
SELECT is(private.reserve_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')), 5, 'otp: ... and the freed attempt can be taken again');
SELECT lives_ok($$SELECT private.release_signin_otp_attempt(encode(digest('a@x.test', 'sha256'), 'hex')) FROM generate_series(1, 7)$$, 'otp: releasing more than was reserved does not raise');
SELECT is(private.peek_signin_otp_failures(encode(digest('a@x.test', 'sha256'), 'hex')), 0, 'otp: ... and the count never goes below zero');
SELECT throws_ok($$SELECT private.peek_signin_otp_failures('not-a-hash')$$, '22023', NULL, 'otp: only a sha256 hex may name a bucket (no email address ever lands in a bucket key)');
SELECT throws_ok($$SELECT private.reserve_signin_otp_attempt('A@X.TEST')$$, '22023', NULL, 'otp: ... for the reservation as well');
SELECT throws_ok($$SELECT private.release_signin_otp_attempt('A@X.TEST')$$, '22023', NULL, 'otp: ... and the release');
SELECT is((SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key LIKE 'signin-otp-fail:%' AND bucket_key LIKE '%@%'), 0, 'otp: no bucket key contains an address');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 6. Session reuse of the GUC window (P3a follow-up 1): a REAL commit, then the same connection keeps working
-- ----------------------------------------------------------------------------
SELECT gen_random_uuid()::text AS reuse_uid \gset
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES (:'reuse_uid', 'reuse-' || substr(md5(random()::text), 1, 12) || '@signin.test');
INSERT INTO auth.identities (provider_id, user_id, identity_data, provider) VALUES
  ('reuse-' || substr(md5(random()::text), 1, 12), :'reuse_uid', '{}', 'email');
SELECT private.signin_link_identity(:'reuse_uid', 'apple', 'reuse-sub-' || substr(md5(random()::text), 1, 12), NULL, false, false);
SELECT private.signin_store_token(:'reuse_uid', 'apple', decode(repeat('ab', 40), 'hex'), decode(repeat('cd', 70), 'hex'), 't1');
-- leave the window PLANTED with the user's id at the COMMIT: this is the state a pooled connection is left in (the value
-- reverts to the '' placeholder, not to NULL and not to the last user)
SELECT set_config('app.signin.target_user_id', :'reuse_uid', true);
COMMIT;
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT is(nullif(current_setting('app.signin.target_user_id', true), ''), NULL, 'reuse: after the COMMIT the window GUC reads empty (the leftover '''' placeholder), not the last user');
SELECT is((SELECT count(*)::int FROM private.signin_methods(:'reuse_uid')), 2, 'reuse: the next call on the reused connection works (nullif form: the placeholder raises nothing)');
SELECT is((SELECT o_has_token FROM private.signin_methods(:'reuse_uid') WHERE o_provider = 'apple'), true, 'reuse: ... and still sees exactly the named user''s grant');
SELECT is(nullif(current_setting('app.signin.target_user_id', true), ''), NULL, 'reuse: the definer closes the window again when it returns');
RESET ROLE;
-- a hand-planted window opens nothing for an ordinary role (no policy applies to it) and a non-uuid value raises nothing
SELECT lives_ok($$SELECT set_config('app.signin.target_user_id', 'not-a-uuid', true)$$, 'reuse: plant a non-uuid window value on the connection');
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok(format('SELECT * FROM private.signin_methods(%L)', :'reuse_uid'), 'reuse: a planted NON-uuid window value raises nothing (text compare, not a cast)');
SELECT is((SELECT count(*)::int FROM private.signin_methods(:'reuse_uid')), 2, 'reuse: ... and the definer overwrites it with the user it was asked about (a planted value widens nothing)');
-- cleanup of what this group committed (service_role has DELETE on auth.identities in the shim and on the grant table; the auth.users row stays, as every harness file leaves its users)
SELECT lives_ok(format('SELECT private.delete_my_data(%L)', :'reuse_uid'), 'cleanup: delete_my_data removes the committed grant row');
DELETE FROM auth.identities WHERE user_id = :'reuse_uid';
COMMIT;

-- No finish(): the rows pgTAP keeps in a temp table are discarded by each group's ROLLBACK (16_edge_role.sql says the same);
-- pg_prove checks the plan against the TAP lines actually printed.

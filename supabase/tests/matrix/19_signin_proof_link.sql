-- 19_signin_proof_link.sql
-- 0039_signin_proof_bound_link.sql, the structural invariants and the harness-role lane: the private.signin_email_proof table (FORCE RLS, no
-- edge grant, scoped private_definer policies, TTL / cross-account / hash CHECKs, FK cascade), its registry classification, what service_role
-- and the client roles can and cannot execute, the purge, and private.delete_my_data removing the account's proofs. 0041 (PR #35) adds the minter role edge_signin_minter (attributes, membership, the nothing-else
-- privilege proof), the session binding's column grant and the narrowed stale-row window (N2). The edge lane (the minter as
-- edge_signin_minter, the redeemer as a bound edge_actor, every refusal) is 19_signin_proof_link_edge.sql: it must reconnect as a real edge_gateway
-- login, so it is its own file.
--
-- No secret in this file: ids are synthetic constants starting 5a5a1900-, the hashes are sha256 of fixed strings.
-- Every group is its own BEGIN ... ROLLBACK except the session-reuse group, which commits and cleans up after itself.

SELECT plan(78);

-- ----------------------------------------------------------------------------
-- 0. Structure
-- ----------------------------------------------------------------------------
SELECT is((SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_class c WHERE c.oid = 'private.signin_email_proof'::regclass), true,
  'structure: private.signin_email_proof has RLS enabled AND forced');
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a WHERE a.attrelid = 'private.signin_email_proof'::regclass AND a.attnum > 0 AND NOT a.attisdropped),
  ARRAY['caller_user_id', 'consumed_at', 'created_at', 'email_hash', 'expires_at', 'id', 'provider', 'session_id', 'sub_hash', 'target_user_id'],
  'structure: the proof holds two user ids, a provider, two HASHES, the (0041) session id and three timestamps: no address and no provider subject is a column');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'private.signin_email_proof'::regclass AND k.contype = 'f' AND k.confrelid = 'auth.users'::regclass AND k.confdeltype = 'c'), 2,
  'structure: both user ids are foreign keys to auth.users ON DELETE CASCADE (an Auth user deletion takes the proofs with it)');
SELECT is((SELECT count(*)::int FROM (VALUES ('anon'), ('authenticated'), ('service_role'), ('edge_gateway'), ('edge_actor'), ('edge_system'), ('edge_signin_minter')) r(n)
           WHERE has_table_privilege(r.n, 'private.signin_email_proof', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              OR has_any_column_privilege(r.n, 'private.signin_email_proof', 'SELECT,INSERT,UPDATE,REFERENCES')), 0,
  'structure: no role but private_definer holds ANY privilege on the proof table (no edge grant of any kind, in either mode)');
SELECT is(has_table_privilege('private_definer', 'private.signin_email_proof', 'SELECT,INSERT,DELETE'), true, 'structure: private_definer holds what the proof definers need');
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a WHERE a.attrelid = 'private.signin_email_proof'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'UPDATE')),
  ARRAY['consumed_at'], 'structure: ... UPDATE only on consumed_at (the target, the hashes and the expiry can never be rewritten)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'private.signin_email_proof'::regclass), 4, 'structure: exactly four policies on the proof table');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = 'private.signin_email_proof'::regclass AND p.polroles <> ARRAY[(SELECT oid FROM pg_roles WHERE rolname = 'private_definer')]), 0,
  'structure: ... every one applies to private_definer ALONE (no PUBLIC policy, no edge or client policy)');
SELECT is((SELECT count(*)::int FROM pg_constraint k WHERE k.conrelid = 'private.signin_email_proof'::regclass AND k.contype = 'c' AND k.conname IN ('signin_email_proof_ttl', 'signin_email_proof_cross_account')), 2,
  'structure: the TTL cap (<= 10 minutes) and the caller <> target constraints exist');
SELECT is(has_column_privilege('private_definer', 'auth.users', 'last_sign_in_at', 'SELECT'), true,
  'structure: private_definer holds SELECT (last_sign_in_at) on auth.users, the corroboration column (the migration RAISEs itself if the GRANT only warned)');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'private' AND p.proname IN ('signin_record_email_proof', 'signin_link_identity_with_proof_for_actor', 'purge_signin_email_proofs')
             AND p.prosecdef AND pg_get_userbyid(p.proowner) = 'private_definer' AND 'search_path=""' = ANY (p.proconfig)), 3,
  'structure: the three functions are SECURITY DEFINER, owned by private_definer, with search_path = ''''');

-- function privileges, per role, by name (the inventory check proves the same against the manifest; these are the behaviours)
CREATE FUNCTION pg_temp.can_exec(p_role text, p_names text[]) RETURNS int LANGUAGE sql STABLE AS $f$
  SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'private' AND p.proname = ANY (p_names) AND has_function_privilege(p_role, p.oid, 'EXECUTE')
$f$;
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_record_email_proof']), 0, 'privileges: edge_system can NOT mint a proof any more (0041, L1: the drain, queue, import and retention lanes run as edge_system)');
SELECT is(pg_temp.can_exec('edge_signin_minter', ARRAY['signin_record_email_proof']), 1, 'privileges: edge_signin_minter CAN mint a proof (the one role that can, 0041)');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['signin_record_email_proof']), 0, 'privileges: edge_actor can NOT mint a proof (the per-user lane never writes the proof table)');
SELECT is(pg_temp.can_exec('service_role', ARRAY['signin_record_email_proof']), 0, 'privileges: service_role (the legacy lane) can not mint either: nothing in legacy uses the proof path');
SELECT is(pg_temp.can_exec('anon', ARRAY['signin_record_email_proof', 'signin_link_identity_with_proof_for_actor', 'purge_signin_email_proofs'])
        + pg_temp.can_exec('authenticated', ARRAY['signin_record_email_proof', 'signin_link_identity_with_proof_for_actor', 'purge_signin_email_proofs']), 0,
  'privileges: no client role can execute any of the three');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['signin_link_identity_with_proof_for_actor']), 1, 'privileges: edge_actor CAN redeem a proof (through the bound-actor definer)');
SELECT is(pg_temp.can_exec('edge_system', ARRAY['signin_link_identity_with_proof_for_actor']) + pg_temp.can_exec('service_role', ARRAY['signin_link_identity_with_proof_for_actor']) + pg_temp.can_exec('edge_signin_minter', ARRAY['signin_link_identity_with_proof_for_actor']), 0,
  'privileges: neither edge_system, service_role nor the minter can redeem: the link is only ever the bound user''s');
SELECT is(pg_temp.can_exec('service_role', ARRAY['purge_signin_email_proofs']) + pg_temp.can_exec('edge_system', ARRAY['purge_signin_email_proofs']), 2, 'privileges: the purge is system work (service_role, edge_system)');
SELECT is(pg_temp.can_exec('edge_actor', ARRAY['purge_signin_email_proofs']) + pg_temp.can_exec('edge_signin_minter', ARRAY['purge_signin_email_proofs']), 0, 'privileges: ... and never edge_actor, nor the minter');

-- 0041: the minter role, by what the catalog says
SELECT is((SELECT r.rolcanlogin OR r.rolsuper OR r.rolbypassrls OR r.rolinherit OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication FROM pg_roles r WHERE r.rolname = 'edge_signin_minter'), false,
  'minter: edge_signin_minter is NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION');
SELECT is((SELECT count(*)::int FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid WHERE m.rolname = 'edge_signin_minter'), 0,
  'minter: it is a member of NO role (nothing to inherit or SET into)');
SELECT is((SELECT count(*)::int FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
           WHERE r.rolname = 'edge_signin_minter' AND m.rolname = 'edge_gateway' AND am.set_option AND NOT am.inherit_option AND NOT am.admin_option), 1,
  'minter: edge_gateway is a SET TRUE, INHERIT FALSE, non-admin member (exactly as edge_actor / edge_system, 0030)');
SELECT is((SELECT count(*)::int FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
           WHERE r.rolname = 'edge_signin_minter' AND m.rolname <> 'edge_gateway' AND (am.set_option OR am.inherit_option)), 0,
  'minter: no other role can SET ROLE to it or inherit from it (edge_actor and edge_system included)');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname IN ('app', 'api', 'private') AND has_function_privilege('edge_signin_minter', p.oid, 'EXECUTE')), 1,
  'minter: it can execute exactly ONE function in app / api / private (signin_record_email_proof)');
SELECT is((SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
             AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
             AND (has_any_column_privilege('edge_signin_minter', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege('edge_signin_minter', c.oid, 'DELETE,TRUNCATE,TRIGGER'))), 0,
  'minter: it holds NO privilege on any table, view or column, in any schema (extension-owned relations, such as postgis'' own PUBLIC views, are exempt, as in check 12)');
SELECT is((SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT LIKE 'pg\_temp%' AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('edge_signin_minter', c.oid, 'USAGE,SELECT,UPDATE') ELSE false END), 0,
  'minter: ... nor on any sequence');
SELECT is((SELECT count(*)::int FROM pg_namespace n WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%' AND has_schema_privilege('edge_signin_minter', n.oid, 'CREATE')), 0,
  'minter: it can CREATE in no schema');
SELECT is((SELECT count(*)::int FROM pg_namespace n WHERE n.nspname IN ('app', 'api', 'auth', 'storage', 'vault') AND has_schema_privilege('edge_signin_minter', n.oid, 'USAGE')), 0,
  'minter: its only schema privilege of substance is USAGE on private: no USAGE on app, api, auth, storage or vault');
SELECT is(has_schema_privilege('edge_signin_minter', 'private', 'USAGE'), true, 'minter: ... and USAGE on private (name resolution for the one function)');
SELECT is((SELECT count(*)::int FROM pg_policy p WHERE (SELECT oid FROM pg_roles WHERE rolname = 'edge_signin_minter') = ANY (p.polroles)), 0, 'minter: no RLS policy names it');
SELECT is(to_regprocedure('private.signin_record_email_proof(uuid, uuid, text, text, text)'), NULL::regprocedure, 'minter: the 0039 five-argument minter (a JavaScript hash, no session, edge_system EXECUTE) is gone');
SELECT is((SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'private' AND p.proname = 'signin_record_email_proof'), 1, 'minter: ... and there is exactly one function of that name');
SELECT is((SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a WHERE a.attrelid = 'auth.sessions'::regclass AND a.attnum > 0 AND NOT a.attisdropped AND has_column_privilege('private_definer', a.attrelid, a.attnum, 'SELECT')),
  ARRAY['created_at', 'id', 'user_id'], 'session binding: private_definer reads exactly (id, user_id, created_at) of auth.sessions, nothing else');
SELECT is((SELECT count(*)::int FROM pg_roles r JOIN pg_class c ON c.oid = 'auth.sessions'::regclass
           WHERE r.rolname IN ('anon', 'authenticated', 'edge_gateway', 'edge_actor', 'edge_system', 'edge_signin_minter') AND (has_any_column_privilege(r.rolname, c.oid, 'SELECT,INSERT,UPDATE,REFERENCES') OR has_table_privilege(r.rolname, c.oid, 'DELETE,TRUNCATE,TRIGGER'))), 0,
  'session binding: no client or edge role (the minter included) can read or write auth.sessions: the session id is a secret only verifyOtp''s caller holds');
SELECT is((SELECT count(*)::int FROM pg_indexes WHERE schemaname = 'private' AND tablename = 'signin_email_proof' AND indexname = 'signin_email_proof_session_uidx' AND indexdef LIKE 'CREATE UNIQUE INDEX%'), 1,
  'session binding: one session, one proof (a UNIQUE index on session_id)');

-- registries (read as service_role: the registries are FORCE RLS, and under HARNESS_MODE=restricted the harness role would read zero rows)
SET ROLE service_role;
SELECT is((SELECT count(*)::int FROM private.pii_retention_policy WHERE schema_name = 'private' AND table_name = 'signin_email_proof' AND action = 'delete_row' AND column_name IN ('caller_user_id', 'target_user_id')), 2,
  'registry: both user-id columns are classified in pii_retention_policy (delete_row)');
SELECT is((SELECT action::text FROM private.pii_export_policy WHERE schema_name = 'private' AND table_name = 'signin_email_proof'), 'exclude', 'registry: ... and the table is EXCLUDED from the data export');
SELECT is((SELECT count(*)::int FROM private.pii_export_policy WHERE table_name = 'signin_email_proof'), 1, 'registry: ... and the registry row is visible to this probe (so the cell above is not a vacuous NULL)');
RESET ROLE;

-- ----------------------------------------------------------------------------
-- 1. Constraints (rows written as private_definer, the only role with anything on the table; the INSERT policy wants the id in the GUC)
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a1900-0000-0000-0000-00000000000a', 'p19-a@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000b', 'p19-b@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000c', 'p19-c@signin.test');
RESET ROLE;
SET LOCAL ROLE private_definer;
CREATE FUNCTION pg_temp.put(p_id uuid, p_caller uuid, p_target uuid, p_email_hash text, p_provider text, p_sub_hash text, p_created interval, p_ttl interval, p_consumed boolean DEFAULT false) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM set_config('app.signin.proof_id', p_id::text, true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at, consumed_at)
  VALUES (p_id, p_caller, p_target, p_email_hash, p_provider, p_sub_hash, now() + p_created, now() + p_created + p_ttl, CASE WHEN p_consumed THEN now() + p_created ELSE NULL END);
END
$f$;
SELECT lives_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f1', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), interval '0', interval '5 minutes')$$,
  'constraints: a 5 minute proof between two different accounts is accepted');
SELECT lives_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f2', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), interval '0', interval '10 minutes')$$,
  'constraints: ... and 10 minutes is the ceiling');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f3', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), interval '0', interval '10 minutes 1 second')$$,
  '23514', NULL, 'constraints: a proof that lives longer than 10 minutes is refused by the table itself');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f4', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), interval '0', interval '0')$$,
  '23514', NULL, 'constraints: ... and one that expires at or before its creation');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f5', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000a', repeat('a', 64), 'apple', repeat('b', 64), interval '0', interval '5 minutes')$$,
  '23514', NULL, 'constraints: a proof is cross-account: caller = target is refused');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f6', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', 'not-a-hash', 'apple', repeat('b', 64), interval '0', interval '5 minutes')$$,
  '23514', NULL, 'constraints: the email hash must be 64 lowercase hex characters');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f7', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('B', 64), interval '0', interval '5 minutes')$$,
  '23514', NULL, 'constraints: ... and so must the subject hash (upper case is refused)');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f8', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'facebook', repeat('b', 64), interval '0', interval '5 minutes')$$,
  '23514', NULL, 'constraints: only apple and google are providers');
SELECT throws_ok($$SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000f9', '5a5a1900-0000-0000-0000-0000000000ff', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), interval '0', interval '5 minutes')$$,
  '23503', NULL, 'constraints: a caller that is not an account is refused (FK to auth.users)');

-- policy scoping: the INSERT policy wants the row's id in the GUC
SELECT throws_ok($$INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at)
  VALUES ('5a5a1900-0000-0000-0000-0000000000e1', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes')$$,
  '42501', NULL, 'policy: an INSERT whose id is not the one in app.signin.proof_id is refused (the GUC was set to another id above)');
SELECT throws_ok($q$DO $b$ BEGIN PERFORM set_config('app.signin.proof_id', '', true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at)
  VALUES ('5a5a1900-0000-0000-0000-0000000000e2', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes'); END $b$$q$,
  '42501', NULL, 'policy: ... and so is an INSERT with the GUC empty');
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 2. RLS scoping of private_definer's reads, updates and deletes
--    P1 live (A -> B), P2 live (C -> B), P3 stale (A -> C, expired 2 h ago), P4 live and consumed (C -> A)
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a1900-0000-0000-0000-00000000000a', 'p19-a@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000b', 'p19-b@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000c', 'p19-c@signin.test');
RESET ROLE;
SET LOCAL ROLE private_definer;
CREATE FUNCTION pg_temp.put(p_id uuid, p_caller uuid, p_target uuid, p_created interval, p_ttl interval, p_consumed boolean DEFAULT false) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM set_config('app.signin.proof_id', p_id::text, true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at, consumed_at)
  VALUES (p_id, p_caller, p_target, repeat('a', 64), 'apple', repeat('b', 64), now() + p_created, now() + p_created + p_ttl, CASE WHEN p_consumed THEN now() + p_created ELSE NULL END);
END
$f$;
CREATE FUNCTION pg_temp.consume(p_id uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  UPDATE private.signin_email_proof SET consumed_at = now() WHERE id = p_id;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$f$;
CREATE FUNCTION pg_temp.del_by_id(p_id uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  DELETE FROM private.signin_email_proof WHERE id = p_id;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$f$;
CREATE FUNCTION pg_temp.del_all() RETURNS text[] LANGUAGE plpgsql AS $f$
DECLARE v text[];
BEGIN
  WITH d AS (DELETE FROM private.signin_email_proof RETURNING id) SELECT array_agg(id::text ORDER BY id) INTO v FROM d;
  RETURN v;
END
$f$;
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000a1', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000b', interval '0', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000a2', '5a5a1900-0000-0000-0000-00000000000c', '5a5a1900-0000-0000-0000-00000000000b', interval '0', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000a3', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000c', interval '-125 minutes', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000a4', '5a5a1900-0000-0000-0000-00000000000c', '5a5a1900-0000-0000-0000-00000000000a', interval '0', interval '5 minutes', true);
SELECT set_config('app.signin.proof_id', '', true);
SELECT set_config('app.delete_my_data.target_user_id', '', true);

SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_email_proof), NULL::text[],
  'select (0041, N2): with no window open private_definer sees NOTHING, not even the stale proof (any private_definer code used to see the stale ones)');
SELECT set_config('app.signin.proof_purge', 'on', true);
SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_email_proof), ARRAY['5a5a1900-0000-0000-0000-0000000000a3'],
  'select (0041, N2): ... the purge window shows the stale proof, and ONLY the stale one (a live proof is never visible to the purge)');
SELECT set_config('app.signin.proof_purge', 'yes', true);
SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_email_proof), NULL::text[],
  'select (0041, N2): ... and only the exact value ''on'' opens it');
SELECT set_config('app.signin.proof_purge', '', true);
SELECT set_config('app.signin.proof_id', '5a5a1900-0000-0000-0000-0000000000a1', true);
SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_email_proof), ARRAY['5a5a1900-0000-0000-0000-0000000000a1'],
  'select: the proof-id window shows exactly that one proof');
SELECT set_config('app.signin.proof_id', '', true);
SELECT set_config('app.delete_my_data.target_user_id', '5a5a1900-0000-0000-0000-00000000000b', true);
SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_email_proof), ARRAY['5a5a1900-0000-0000-0000-0000000000a1', '5a5a1900-0000-0000-0000-0000000000a2'],
  'select: the delete window for B shows the proofs B is the TARGET of, not C -> A');
SELECT set_config('app.delete_my_data.target_user_id', '5a5a1900-0000-0000-0000-00000000000a', true);
SELECT is((SELECT array_agg(id::text ORDER BY id) FROM private.signin_email_proof), ARRAY['5a5a1900-0000-0000-0000-0000000000a1', '5a5a1900-0000-0000-0000-0000000000a3', '5a5a1900-0000-0000-0000-0000000000a4'],
  'select: ... and for A the proofs A is the CALLER of or the target of');
SELECT set_config('app.delete_my_data.target_user_id', '', true);

-- UPDATE: only consumed_at, only the proof named in the GUC
SELECT throws_ok($$UPDATE private.signin_email_proof SET expires_at = expires_at + interval '1 hour'$$, '42501', NULL, 'update: expires_at is not updatable (column privilege): a proof cannot be extended');
SELECT throws_ok($$UPDATE private.signin_email_proof SET target_user_id = caller_user_id$$, '42501', NULL, 'update: ... nor retargeted');
SELECT is(pg_temp.consume('5a5a1900-0000-0000-0000-0000000000a1'), 0,
  'update: with no window open even consumed_at changes NOTHING (0 rows: the policy hides the row)');
SELECT set_config('app.signin.proof_id', '5a5a1900-0000-0000-0000-0000000000a2', true);
SELECT is(pg_temp.consume('5a5a1900-0000-0000-0000-0000000000a1'), 0,
  'update: ... and a window opened for ANOTHER proof does not reach this one');
SELECT is(pg_temp.consume('5a5a1900-0000-0000-0000-0000000000a2'), 1,
  'update: ... but its own window does (the redemption)');
-- DELETE: only the account-deletion window and stale rows; never a live proof by its id alone
SELECT is(pg_temp.del_by_id('5a5a1900-0000-0000-0000-0000000000a2'), 0,
  'delete: the proof-id window cannot DELETE a live proof (only an account deletion or the purge can)');
SELECT set_config('app.signin.proof_id', '', true);
SELECT is(pg_temp.del_all(), NULL::text[],
  'delete (0041, N2): with no window open a DELETE reaches NOTHING (it used to reach every stale row)');
SELECT set_config('app.signin.proof_purge', 'on', true);
SELECT is(pg_temp.del_all(), ARRAY['5a5a1900-0000-0000-0000-0000000000a3'],
  'delete (0041, N2): ... inside the purge window it reaches the stale rows only');
SELECT set_config('app.signin.proof_purge', '', true);
SELECT set_config('app.delete_my_data.target_user_id', '5a5a1900-0000-0000-0000-00000000000c', true);
SELECT is(pg_temp.del_all(), ARRAY['5a5a1900-0000-0000-0000-0000000000a2', '5a5a1900-0000-0000-0000-0000000000a4'],
  'delete: the account-deletion window for C reaches the proofs C is a party to and NOT A -> B');
SELECT set_config('app.delete_my_data.target_user_id', '', true);
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 3. The purge and account deletion (as service_role, the lane that calls them)
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES
  ('5a5a1900-0000-0000-0000-00000000000a', 'p19-a@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000b', 'p19-b@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000c', 'p19-c@signin.test'),
  ('5a5a1900-0000-0000-0000-00000000000d', 'p19-d@signin.test');
INSERT INTO app.profile (user_id, handle) VALUES ('5a5a1900-0000-0000-0000-00000000000a', 'p19_a'), ('5a5a1900-0000-0000-0000-00000000000b', 'p19_b');
RESET ROLE;
SET LOCAL ROLE private_definer;
CREATE FUNCTION pg_temp.put(p_id uuid, p_caller uuid, p_target uuid, p_created interval, p_ttl interval, p_consumed boolean DEFAULT false) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM set_config('app.signin.proof_id', p_id::text, true);
  INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, created_at, expires_at, consumed_at)
  VALUES (p_id, p_caller, p_target, repeat('a', 64), 'apple', repeat('b', 64), now() + p_created, now() + p_created + p_ttl, CASE WHEN p_consumed THEN now() + p_created ELSE NULL END);
END
$f$;
-- S1 stale and unconsumed, S2 stale and consumed, F1 live, F2 live and consumed (all D -> C or similar, so deleting A or B leaves them)
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000b1', '5a5a1900-0000-0000-0000-00000000000d', '5a5a1900-0000-0000-0000-00000000000c', interval '-125 minutes', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000b2', '5a5a1900-0000-0000-0000-00000000000d', '5a5a1900-0000-0000-0000-00000000000c', interval '-125 minutes', interval '5 minutes', true);
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000b3', '5a5a1900-0000-0000-0000-00000000000d', '5a5a1900-0000-0000-0000-00000000000c', interval '-30 minutes', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000b4', '5a5a1900-0000-0000-0000-00000000000d', '5a5a1900-0000-0000-0000-00000000000c', interval '0', interval '5 minutes', true);
-- A is the caller of one, B the target of one, A -> B one, and one belongs to neither
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000c1', '5a5a1900-0000-0000-0000-00000000000a', '5a5a1900-0000-0000-0000-00000000000c', interval '0', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000c2', '5a5a1900-0000-0000-0000-00000000000d', '5a5a1900-0000-0000-0000-00000000000a', interval '0', interval '5 minutes');
SELECT pg_temp.put('5a5a1900-0000-0000-0000-0000000000c3', '5a5a1900-0000-0000-0000-00000000000d', '5a5a1900-0000-0000-0000-00000000000c', interval '0', interval '5 minutes');
SELECT set_config('app.signin.proof_id', '', true);
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

SELECT is(private.purge_signin_email_proofs(), 2, 'purge: removes exactly the two rows an hour past their expiry (consumed or not)');
SELECT is(private.purge_signin_email_proofs(), 0, 'purge: ... and is idempotent');
SELECT throws_ok($$SELECT count(*) FROM private.signin_email_proof$$, '42501', NULL, 'purge: (control) service_role itself can not read the table, only the definers can');
SELECT lives_ok($$SELECT private.delete_my_data('5a5a1900-0000-0000-0000-00000000000a')$$, 'delete: private.delete_my_data (0039 redefinition) deletes account A');
RESET ROLE;
SET LOCAL ROLE private_definer;
CREATE FUNCTION pg_temp.visible(p_id uuid) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE n int;
BEGIN
  PERFORM set_config('app.signin.proof_id', p_id::text, true);
  SELECT count(*)::int INTO n FROM private.signin_email_proof WHERE id = p_id;
  PERFORM set_config('app.signin.proof_id', '', true);
  RETURN n;
END
$f$;
SELECT is(pg_temp.visible('5a5a1900-0000-0000-0000-0000000000c1') + pg_temp.visible('5a5a1900-0000-0000-0000-0000000000c2'), 0,
  'delete: the proofs A was the CALLER of and the TARGET of are gone');
SELECT is(pg_temp.visible('5a5a1900-0000-0000-0000-0000000000c3') + pg_temp.visible('5a5a1900-0000-0000-0000-0000000000b3') + pg_temp.visible('5a5a1900-0000-0000-0000-0000000000b4'), 3,
  'delete: ... and nobody else''s proof was touched');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok($$SELECT private.delete_my_data('5a5a1900-0000-0000-0000-00000000000b')$$, 'delete: an account that is a party to no proof deletes cleanly (the proof statement is a no-op there)');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.visible('5a5a1900-0000-0000-0000-0000000000c3'), 1, 'delete: ... and still touches nobody else''s proof');
RESET ROLE;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
SELECT lives_ok($$SELECT private.delete_my_data('5a5a1900-0000-0000-0000-00000000000c')$$, 'delete: account C (the TARGET of the rest) deletes');
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT is(pg_temp.visible('5a5a1900-0000-0000-0000-0000000000c3') + pg_temp.visible('5a5a1900-0000-0000-0000-0000000000b3') + pg_temp.visible('5a5a1900-0000-0000-0000-0000000000b4'), 0,
  'delete: ... and every proof naming C as the target is gone');
RESET ROLE;
ROLLBACK;

-- ----------------------------------------------------------------------------
-- 4. Session reuse: a window GUC set in a COMMITTED transaction reads empty in the next one on the same connection, and nothing raises
-- ----------------------------------------------------------------------------
BEGIN;
SELECT tests.authenticate_as('service_role', '{}'::jsonb);
INSERT INTO auth.users (id, email) VALUES ('5a5a1900-0000-0000-0000-0000000000d1', 'p19-d1@signin.test'), ('5a5a1900-0000-0000-0000-0000000000d2', 'p19-d2@signin.test') ON CONFLICT (id) DO NOTHING;
RESET ROLE;
SET LOCAL ROLE private_definer;
SELECT set_config('app.signin.proof_id', '5a5a1900-0000-0000-0000-0000000000d9', true);
INSERT INTO private.signin_email_proof (id, caller_user_id, target_user_id, email_hash, provider, sub_hash, expires_at)
VALUES ('5a5a1900-0000-0000-0000-0000000000d9', '5a5a1900-0000-0000-0000-0000000000d1', '5a5a1900-0000-0000-0000-0000000000d2', repeat('a', 64), 'apple', repeat('b', 64), now() + interval '5 minutes');
COMMIT;
BEGIN;
SET LOCAL ROLE private_definer;
SELECT is(nullif(current_setting('app.signin.proof_id', true), ''), NULL, 'reuse: after the COMMIT the proof-id window reads empty (never NULL-then-raise)');
SELECT lives_ok($$SELECT count(*) FROM private.signin_email_proof$$, 'reuse: ... and a read on the reused connection raises nothing (the policies compare text)');
SELECT is((SELECT count(*)::int FROM private.signin_email_proof WHERE id = '5a5a1900-0000-0000-0000-0000000000d9'), 0, 'reuse: ... and the committed live proof is invisible without its window');
ROLLBACK;
-- clean up what was committed
BEGIN;
SET LOCAL ROLE private_definer;
SELECT set_config('app.delete_my_data.target_user_id', '5a5a1900-0000-0000-0000-0000000000d1', true);
DELETE FROM private.signin_email_proof WHERE id = '5a5a1900-0000-0000-0000-0000000000d9';
COMMIT;

-- No finish(): see 16_edge_role.sql.

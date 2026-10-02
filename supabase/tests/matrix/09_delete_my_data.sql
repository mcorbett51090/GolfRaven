-- 09_delete_my_data.sql
-- build plan §10 P3 AT(6) (docs/golf-trails/02-build-plan.md:2759).
-- ⛔ REWRITE (B3, gate round 2): this file used to assert "zero personal
-- rows" against a hand-enumerated UNION of table names. It now derives
-- the same assertion from `private.pii_retention_policy` (0014_hardening)
-- — the SAME table `private.delete_my_data` itself is driven by — via
-- `plpgsql` + `dblink`-free dynamic SQL run through a helper function, so
-- a table added later is caught automatically as long as its FK is
-- classified (and if it ISN'T classified, `delete_my_data` itself raises,
-- which 10_function... no — which this file's own "unclassified FK"
-- test below catches directly).

BEGIN;
SELECT plan(33);

-- S1 restricted-mode fix: private.delete_my_data is granted to
-- service_role only (0015) -- its real production caller (the me-delete
-- Edge Function). Under the default harness this "worked" only because
-- the connecting bootstrap role is a superuser and bypasses the EXECUTE
-- grant, private.pii_retention_policy's SELECT grant (0014), and every
-- RLS policy outright -- the exact false-pass S1 warns about.
-- authenticate_as('service_role', ...) here is the accurate caller
-- identity, and (service_role also has BYPASSRLS, 0009/shim) it is also
-- what lets the rest of this file's row-count assertions see the TRUE
-- post-deletion state rather than an RLS-narrowed view of it.
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

-- Every FK-to-auth.users column in `app` must be classified — this is the
-- same check `delete_my_data` itself makes at call time, asserted here
-- independently so a missing classification fails CI even before anyone
-- calls the function with real data.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
    LEFT JOIN private.pii_retention_policy pol
      ON pol.schema_name = 'app' AND pol.table_name = cl.relname AND pol.column_name = a.attname
    WHERE con.contype = 'f' AND n.nspname = 'app' AND con.confrelid = 'auth.users'::regclass
      AND pol.action IS NULL
  ),
  0,
  'every FK-to-auth.users column in app is classified in private.pii_retention_policy'
);

-- H1 (post-P3a gate) catalog test: every FK that references a
-- "delete_row table" (a table whose OWN rows get DELETEd by
-- delete_my_data's generic pass, per private.pii_retention_policy) must
-- carry ON DELETE CASCADE/SET NULL, OR have a REAL, present explicit
-- detach trigger registered in private.fk_explicit_detach_allowlist — a
-- plain NO ACTION FK to such a table fails at whatever point in the
-- generic loop's (arbitrary) iteration order the referenced table
-- happens to be deleted, exactly H1's reproduction (offer_code.play_id/
-- entitlement.play_id, added by 0017, were NO ACTION + non-deferrable
-- until this same round fixed them). Independent of any specific data
-- test below, so a FUTURE FK added to a delete_row table without the
-- right shape fails here even before anyone seeds data that would
-- trigger it.
--
-- ⛔ FIX (should-fix, post-P3a re-gate): "require CASCADE or SET NULL —
-- deferrable NO ACTION alone is not enough unless an explicit null-out is
-- registered." The PRIOR version of this test accepted bare
-- `con.condeferrable` as sufficient on its own (`NOT (condeferrable OR
-- confdeltype IN ('c','n'))`) — a merely-deferred NO ACTION FK with NO
-- detach logic at all would have passed this test even though it offers
-- no actual protection (deferred just means the SAME hard failure
-- happens at COMMIT instead of at the statement). Deferrable is no longer
-- checked at all: the FK must be CASCADE/SET NULL outright, OR its
-- constraint name must appear in private.fk_explicit_detach_allowlist
-- WITH a real, live, non-internal trigger of the registered name actually
-- present on the referenced (parent) table — a stale allowlist row whose
-- trigger was later dropped does NOT satisfy this (EXISTS requires
-- pg_trigger to have a live match), so removing the trigger without also
-- removing the allowlist row still fails here.
SELECT is(
  (
    SELECT count(*)::int
    FROM pg_constraint con
    JOIN pg_class cl ON cl.oid = con.conrelid
    JOIN pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_class target ON target.oid = con.confrelid
    JOIN pg_namespace tn ON tn.oid = target.relnamespace
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confdeltype NOT IN ('c', 'n')
      AND EXISTS (
        SELECT 1 FROM private.pii_retention_policy pol
        WHERE pol.schema_name = tn.nspname AND pol.table_name = target.relname AND pol.action = 'delete_row'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM private.fk_explicit_detach_allowlist al
        JOIN pg_trigger trg
          ON trg.tgrelid = target.oid
         AND trg.tgname = al.detach_trigger_name
         AND NOT trg.tgisinternal
        WHERE al.schema_name = n.nspname
          AND al.table_name = cl.relname
          AND al.constraint_name = con.conname
      )
  ),
  0,
  'every FK referencing a delete_row table is ON DELETE CASCADE/SET NULL, or has a REAL registered+present explicit-detach trigger (H1, tightened post-P3a re-gate)'
);

-- No row is left with an open TODO (gate round 2, item 2: "The 09 test
-- must fail on any TODO or unclassified entry"). Every classification
-- must be a real, implemented redaction path.
SELECT is(
  (SELECT count(*)::int FROM private.pii_retention_policy WHERE reason ILIKE '%TODO%'),
  0,
  'no private.pii_retention_policy row has a TODO in its reason'
);

-- Precondition: player A's seeded rows exist (activated + redeemed
-- entitlements, a redeemed offer_code, a partner_member row, both
-- directions of partner_invite, an audit_log row, a storage.objects
-- receipt) — see supabase/tests/helpers.sql.
SELECT is((SELECT count(*)::int FROM app.entitlement WHERE user_id = '00000000-0000-0000-0000-00000000000a'), 2, 'precondition: 2 entitlements seeded (one redeemable/activated, one redeemed)');
SELECT is((SELECT state::text FROM app.entitlement WHERE id = '50000000-0000-0000-0000-000000000002'), 'redeemed', 'precondition: the second entitlement is REDEEMED (terminal)');

-- P3d gate round 2, should-fix 3: seed two private.rate_limit_bucket rows
-- for player A -- an ordinary bucket (must be purged by delete_my_data)
-- and the in-flight `me-delete:user` bucket itself (must survive, per
-- this round's own documented choice -- see 0022_delete_my_data_post_
-- condition.sql's own comment on the exact same block -- so a RETRY of
-- the deletion call stays rate-limited). service_role already holds
-- SELECT/INSERT/UPDATE/DELETE on this table directly (0009), no RLS
-- policy needed for this seed insert.
INSERT INTO private.rate_limit_bucket (bucket_key, window_start, count) VALUES
  ('00000000-0000-0000-0000-00000000000a:evidence:device_x', now(), 3),
  ('00000000-0000-0000-0000-00000000000a:me-delete:user', now(), 1);

SELECT private.delete_my_data('00000000-0000-0000-0000-00000000000a'::uuid);

SELECT is(
  (
    SELECT count(*)::int FROM private.rate_limit_bucket
    WHERE bucket_key LIKE '00000000-0000-0000-0000-00000000000a:%'
      AND bucket_key <> '00000000-0000-0000-0000-00000000000a:me-delete:user'
  ),
  0,
  'P3d should-fix 3: every OTHER private.rate_limit_bucket key prefixed with the deleted user''s uid is purged by delete_my_data'
);
SELECT is(
  (SELECT count(*)::int FROM private.rate_limit_bucket WHERE bucket_key = '00000000-0000-0000-0000-00000000000a:me-delete:user'),
  1,
  'P3d should-fix 3: the in-flight me-delete:user bucket itself survives deletion, deliberately, so a retry of THIS SAME call stays rate-limited'
);

-- Generic, catalog-driven pass: every `delete_row` / `set_null` policy row
-- leaves ZERO rows matching the deleted user, over the WHOLE `app` schema
-- — this is the "asserted by a query over all personal tables" the gate
-- asked for, and it automatically covers a table added later as long as
-- its FK is classified.
DO $$
DECLARE
  v_pol record;
  v_count int;
BEGIN
  FOR v_pol IN
    SELECT table_name, column_name, action
    FROM private.pii_retention_policy
    WHERE schema_name = 'app' AND action IN ('delete_row', 'set_null')
  LOOP
    EXECUTE format(
      'SELECT count(*) FROM app.%I WHERE %I = $1', v_pol.table_name, v_pol.column_name
    ) INTO v_count USING '00000000-0000-0000-0000-00000000000a'::uuid;
    IF v_count <> 0 THEN
      RAISE EXCEPTION 'delete_my_data left % row(s) in app.%.% (policy: %)', v_count, v_pol.table_name, v_pol.column_name, v_pol.action;
    END IF;
  END LOOP;
END
$$;
SELECT pass('every delete_row/set_null-policed column has zero rows referencing the deleted user (catalog-driven)');

-- "special" cases, asserted individually (each has bespoke behaviour, so a
-- generic "zero rows" assertion is the wrong shape for them):
SELECT is(
  (SELECT state::text FROM app.entitlement WHERE id = '50000000-0000-0000-0000-000000000001'),
  'void', 'the unredeemed (redeemable/activated) entitlement is voided'
);
SELECT is(
  (SELECT state::text FROM app.entitlement WHERE id = '50000000-0000-0000-0000-000000000002'),
  'redeemed', 'the REDEEMED entitlement stays redeemed (terminal, never voided)'
);
SELECT is(
  (SELECT count(*)::int FROM app.entitlement WHERE user_id = '00000000-0000-0000-0000-00000000000a' AND activated_device_id IS NOT NULL),
  0, 'every entitlement (voided or redeemed) has its activated_device_id detached, so app.device could be deleted'
);
SELECT is(
  (SELECT count(*)::int FROM app.receipt_fingerprint WHERE id = '80000000-0000-0000-0000-000000000001' AND user_id IS NULL),
  1, 'the receipt_fingerprint row survives with user_id nulled (24-month fraud retention)'
);
SELECT is(
  (SELECT count(*)::int FROM storage.objects WHERE bucket_id = 'receipts' AND name LIKE 'receipts/00000000-0000-0000-0000-00000000000a/%'),
  0, 'the player''s receipt objects in storage.objects are removed'
);

-- ---------------------------------------------------------------------------
-- attestation.staff_user_id (gate round 2, item 2): deleting the STAFF
-- member's own data must redact their identity too — closes the gap the
-- first gate-round-2 pass left as a TODO. Same transaction, same
-- attestation row ('a0000000-...-001') — its staff_user_id currently
-- points at staff@X.
-- ---------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM app.attestation WHERE id = 'a0000000-0000-0000-0000-000000000001' AND staff_user_id = '00000000-0000-0000-0000-1000000000a1'),
  1, 'precondition: the attestation row''s staff_user_id still points at staff@X before their own deletion'
);

SELECT private.delete_my_data('00000000-0000-0000-0000-1000000000a1'::uuid);

SELECT is(
  (SELECT count(*)::int FROM app.attestation WHERE id = 'a0000000-0000-0000-0000-000000000001' AND staff_user_id IS NULL),
  1, 'deleting the staff member redacts attestation.staff_user_id to NULL (the row survives)'
);
SELECT is(
  (SELECT staff_pseudonym IS NOT NULL AND kind = 'presence' AND cosignal_ok = true FROM app.attestation WHERE id = 'a0000000-0000-0000-0000-000000000001'),
  true,
  'the attestation stays verifiable as "staff-attested" after redaction: staff_pseudonym, kind and cosignal_ok all survive'
);

-- ---------------------------------------------------------------------------
-- M5 (post-P3a gate): "Restore the dropped delete_my_data post-condition
-- tests" — attestation.player_user_id, the shift-log "deleted player"
-- entry, public_profile_projection removed, no address column; plus the
-- same discipline for partner_invite, audit_log and fraud_signal. All
-- asserted against player A's deletion above (both delete_my_data calls
-- already happened by this point in the file).
-- ---------------------------------------------------------------------------
SELECT is(
  (SELECT count(*)::int FROM app.attestation WHERE id = 'a0000000-0000-0000-0000-000000000001' AND player_user_id IS NULL),
  1, 'attestation.player_user_id is nulled for the deleted player (line 841)'
);
SELECT is(
  (SELECT player_handle_snapshot FROM app.attestation_shift_log WHERE facility_id = 'fac_x' AND kind = 'presence' AND player_pseudonym = encode(public.hmac('00000000-0000-0000-0000-00000000000a', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex')),
  'deleted player',
  'attestation_shift_log.player_handle_snapshot is rewritten to ''deleted player'', matched by the durable pseudonym'
);
SELECT is(
  (SELECT count(*)::int FROM app.public_profile_projection WHERE handle = 'player_a'),
  0, 'the player''s public_profile_projection row is removed'
);
SELECT is(
  (
    SELECT count(*)::int FROM information_schema.columns
    WHERE table_schema = 'app' AND table_name IN ('entitlement', 'offer_code')
      AND (column_name ILIKE '%address%' OR column_name ILIKE '%shipping%')
  ),
  0,
  'no address/shipping column exists on entitlement or offer_code (O9/O10, line 2759: "no address exists to retain")'
);
SELECT is(
  (SELECT count(*)::int FROM app.partner_invite WHERE id IN ('11100000-0000-0000-0000-000000000001', '11100000-0000-0000-0000-000000000002')),
  0, 'both partner_invite rows (sent by A, and received at A''s verified email) are deleted'
);
SELECT is(
  (SELECT count(*)::int FROM app.audit_log WHERE subject_id = '30000000-0000-0000-0000-000000000001' AND actor_user_id IS NULL),
  1, 'audit_log.actor_user_id is redacted for the deleted player''s own historical row'
);
SELECT is(
  (SELECT count(*)::int FROM app.fraud_signal WHERE kind = 'manual_review_seed' AND user_id IS NULL),
  1, 'fraud_signal.user_id is nulled, the row survives (admin fraud record kept)'
);

-- ---------------------------------------------------------------------------
-- M2 (post-P3a re-gate): "no jsonb detail or evidence column anywhere
-- contains the deleted user's uuid." Repro was app.review_item.detail/
-- app.fraud_signal.detail embedding 'user_id'/'matched_user_id' from
-- app.dedupe_receipt_fingerprint's cross-user branch (0017) — fixed there
-- by dropping those keys entirely (the row's own user_id column, plus
-- matched_receipt_fingerprint_id, are enough to look a match up without
-- ever putting a raw user uuid in a jsonb payload). This test is the
-- CATALOG-DRIVEN safety net that generalizes past that one call site: it
-- scans EVERY jsonb/text/uuid column in schema app (derived from
-- information_schema.columns, not a hand-maintained list — the same
-- "derived, not maintained" discipline as private.pii_retention_policy's
-- own generic pass above) for the literal deleted-user uuid appearing
-- ANYWHERE in its text form, so a FUTURE column that starts embedding a
-- raw user id fails here immediately, before anyone notices by hand.
--
-- ⛔ FIX (should-fix 5, post-P3a re-gate): "extend it from jsonb columns
-- to text and uuid columns in app, beyond FK'd columns, with documented
-- exemptions." Widened from `data_type = 'jsonb'` alone to `data_type IN
-- ('jsonb', 'text', 'uuid')` — a column that ISN'T a declared FK to
-- auth.users can still end up holding a raw user uuid as plain data (a
-- polymorphic subject_id, a hand-built text field, …), and the ORIGINAL
-- scan only ever looked at jsonb. A column that IS a declared FK to
-- auth.users is excluded here (`NOT EXISTS` against pg_constraint) — it
-- is already asserted zero-rows by the generic, catalog-driven
-- delete_row/set_null pass earlier in this file, so re-scanning it here
-- would be redundant, not a wider net ("beyond FK'd columns" is this
-- scan's whole point).
--
-- Exception (documented, narrow — should-fix 1, post-P3a re-gate):
-- app.audit_log's OWN completion record of the delete_my_data call itself
-- legitimately names the deleted user, in BOTH its jsonb `detail`
-- (`user_id`) and its text `subject_id` — the audit trail's whole
-- purpose ("user X was deleted"), unlike the dedupe_receipt_fingerprint
-- leak this test exists to catch, which put ANOTHER user's id into a
-- record that outlives and is unrelated to their own deletion.
-- ⛔ FIX (should-fix 1, post-P3a re-gate): "restrict it to rows with
-- subject_id = the deleted uuid and detail keys exactly {user_id,
-- deleted_at}." The PRIOR version exempted EVERY row with
-- action = 'delete_my_data', full stop — a hypothetical future row that
-- reuses that same action name but smuggles some OTHER user's id
-- alongside (in an extra detail key, or as a DIFFERENT subject_id) would
-- have sailed through unexamined. Narrowed to EXACTLY the one legitimate
-- shape: this row's own subject_id must equal the deleted user, AND
-- detail's key set must be EXACTLY {deleted_at, user_id} — nothing more,
-- nothing less. See docs/security/p3-money-path-requirements.md's own
-- note on this retention exception.
DO $$
DECLARE
  v_col record;
  v_count int;
  v_uuid text := '00000000-0000-0000-0000-00000000000a';
  v_exclude_sql text;
BEGIN
  FOR v_col IN
    SELECT c.table_name, c.column_name
    FROM information_schema.columns c
    WHERE c.table_schema = 'app' AND c.data_type IN ('jsonb', 'text', 'uuid')
      AND NOT EXISTS (
        SELECT 1 FROM pg_constraint con
        JOIN pg_class cl ON cl.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = cl.relnamespace
        JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
        WHERE con.contype = 'f' AND con.confrelid = 'auth.users'::regclass
          AND n.nspname = 'app' AND cl.relname = c.table_name AND a.attname = c.column_name
      )
  LOOP
    IF v_col.table_name = 'audit_log' AND v_col.column_name IN ('detail', 'subject_id') THEN
      v_exclude_sql := format(
        ' AND NOT (action = ''delete_my_data'' AND subject_id = %L AND (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(detail) k) = ARRAY[''deleted_at'',''user_id''])',
        v_uuid
      );
    ELSE
      v_exclude_sql := '';
    END IF;
    EXECUTE format(
      'SELECT count(*) FROM app.%I WHERE %I::text ILIKE $1%s', v_col.table_name, v_col.column_name, v_exclude_sql
    ) INTO v_count USING '%' || v_uuid || '%';
    IF v_count <> 0 THEN
      RAISE EXCEPTION 'the deleted user''s uuid (%) still appears in app.%.% (%) after delete_my_data — % row(s)', v_uuid, v_col.table_name, v_col.column_name, v_col.data_type, v_count;
    END IF;
  END LOOP;
END
$$;
SELECT pass('no jsonb/text/uuid column anywhere in schema app (excluding declared FKs-to-auth.users, already covered above) contains the deleted user''s uuid, as text, after delete_my_data (catalog-driven over information_schema.columns; should-fix 5, post-P3a re-gate)');

-- ---------------------------------------------------------------------------
-- M1 BLOCKING (post-P3a re-gate): "delete_my_data silently leaves PII
-- behind when a shift-log row has a pseudonym but a NULL key id." Two
-- write-time rejections (0018): the NULL-key-id shape itself (the pairing
-- CHECK), and an hmac id that never resolves in Vault at all (the
-- write-time validation trigger). Both proven directly against
-- app.attestation_shift_log (this repro's own table); the same CHECK/
-- trigger pair also applies to app.attestation (player + staff), not
-- separately re-proven here since the mechanism is identical.
-- ---------------------------------------------------------------------------
SELECT throws_ok(
  $$INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
    VALUES ('fac_x', 'presence', 'player_m1',
            encode(hmac('m1-null-key-id-repro', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex'),
            NULL, 'staff_x_handle')$$,
  '23514',
  NULL,
  'M1: a shift-log row with player_pseudonym SET but player_pseudonym_hmac_id NULL is rejected at WRITE time (pairing CHECK) -- the exact shape the repro constructed by UPDATE is now unwritable in the first place'
);
SELECT throws_ok(
  $$INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
    VALUES ('fac_x', 'presence', 'player_m1b', NULL,
            'a0000000-1111-0000-0000-000000000001', 'staff_x_handle')$$,
  '23514',
  NULL,
  'M1: the MIRROR shape (hmac_id SET, player_pseudonym NULL) is also rejected at write time by the same pairing CHECK'
);
SELECT throws_ok(
  $$UPDATE app.attestation_shift_log SET player_pseudonym_hmac_id = NULL
    WHERE player_pseudonym = encode(public.hmac('00000000-0000-0000-0000-00000000000a', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex')$$,
  '23514',
  NULL,
  'M1: the ORIGINAL repro itself -- UPDATE ... SET player_pseudonym_hmac_id = NULL on player A''s (v1-written) shift-log row, matched by its durable pseudonym (attestation_shift_log rows get no fixed fixture id) -- now fails at write time instead of silently succeeding and leaving the row unredactable'
);
SELECT throws_ok(
  $$INSERT INTO app.attestation_shift_log (facility_id, kind, player_handle_snapshot, player_pseudonym, player_pseudonym_hmac_id, staff_handle)
    VALUES ('fac_x', 'presence', 'player_m1c',
            encode(hmac('m1-unresolvable-key-repro', 'shim-test-only-pseudonym-hmac-one-32bytes-minimum-xxxxxxxxxxxxxxxxxxxx', 'sha256'), 'hex'),
            'ffffffff-ffff-ffff-ffff-ffffffffffff', 'staff_x_handle')$$,
  '23514',
  NULL,
  'M1: an hmac_id that does not resolve to any real vault.decrypted_secrets row is rejected at write time (the write-time validation trigger, 0018) -- a bad/unknown key id can never be written in the first place'
);

-- ---------------------------------------------------------------------------
-- M1 BLOCKING (post-P3a re-gate correction): "service_role can edit the
-- key registry, so deletion silently leaves PII behind." Repro this round:
-- with service_role holding SELECT/INSERT/DELETE, `DELETE FROM private.
-- pseudonym_key_registry WHERE key_id = <key 1's id>` then
-- `delete_my_data(A)` returned true while player_a's data SURVIVED
-- (discovery simply stopped trying that key); inserting a bogus key_id
-- made EVERY user's deletion raise. Two independent layers now close
-- this: service_role holds NO grant on the table at all (0018), and even
-- a role that bypasses RLS entirely (the table owner) cannot delete a
-- REFERENCED key_id -- the FK itself blocks it, not a policy or a grant.
-- ---------------------------------------------------------------------------
SELECT throws_ok(
  $$DELETE FROM private.pseudonym_key_registry WHERE key_id = 'a0000000-1111-0000-0000-000000000001'$$,
  '42501',
  NULL,
  'M1: service_role cannot DELETE from private.pseudonym_key_registry at all (no grant, post-P3a re-gate correction) -- the exact repro (delete key 1, then delete_my_data(A) "succeeds" while player_a survives) is closed at the privilege layer'
);
SELECT throws_ok(
  $$INSERT INTO private.pseudonym_key_registry (key_id) VALUES ('99999999-9999-9999-9999-999999999999')$$,
  '42501',
  NULL,
  'M1: service_role cannot INSERT into private.pseudonym_key_registry at all (no grant) -- the mirror repro (a bogus key_id making every deletion raise) is closed the same way'
);
-- "even as the definer or owner, because of the FK": private_definer
-- itself is ALSO blocked before ever reaching the FK -- should-fix 1's
-- split policies grant it SELECT/INSERT only, no DELETE policy exists at
-- all, so a DELETE as private_definer fails on RLS default-deny (FORCE
-- RLS, no matching policy), same class of failure as service_role's
-- missing grant, just enforced at a different layer. The role that
-- actually BYPASSES RLS and holds full privileges on this table by
-- construction is its OWNER (the connecting role itself, tests.
-- clear_actor() below reverts to it -- migration_owner under
-- HARNESS_MODE=restricted, postgres under HARNESS_MODE=superuser) -- this
-- is the one path that genuinely reaches the FK check, and it is what
-- this next assertion proves fails on: the FK itself, independent of any
-- policy or grant.
SELECT tests.clear_actor();
-- private.pseudonym_key_registry has FORCE ROW LEVEL SECURITY (0018) --
-- which means even the TABLE OWNER is subject to its RLS policies (that
-- is precisely what FORCE means), so the owner has NO visibility into
-- this table at all right now (only private_definer's own SELECT/INSERT
-- policies exist, and this connecting role is not private_definer). A
-- bare DELETE as the owner would therefore match ZERO rows and succeed
-- silently -- proving nothing about the FK at all, only that RLS hid the
-- row first. A temporary, test-only, self-granted policy (the owner CAN
-- create one -- CREATE POLICY is gated by ownership, not by RLS itself)
-- makes the row genuinely VISIBLE to this role, so the DELETE attempt
-- actually reaches the FK check -- proving the FK itself blocks it,
-- independent of any policy or grant, not merely that RLS never let the
-- attempt get that far.
SELECT lives_ok(
  $$CREATE POLICY current_user_registry_delete_m1_test ON private.pseudonym_key_registry FOR ALL TO CURRENT_USER USING (true)$$,
  'setup (M1 test): a temporary, test-only policy so the connecting role (table owner) can see the row it is about to try deleting'
);
SELECT throws_ok(
  $$DELETE FROM private.pseudonym_key_registry WHERE key_id = 'a0000000-1111-0000-0000-000000000001'$$,
  '23503',
  NULL,
  'M1: even AS THE TABLE OWNER, WITH explicit visibility into the row (the temporary policy above), deleting a key_id still REFERENCED by a live attestation_shift_log row fails on the FK itself'
);
SELECT lives_ok(
  $$DROP POLICY current_user_registry_delete_m1_test ON private.pseudonym_key_registry$$,
  'cleanup (M1 test): drop the temporary test-only policy'
);
SELECT tests.authenticate_as('service_role', '{}'::jsonb);

SELECT * FROM finish();
ROLLBACK;

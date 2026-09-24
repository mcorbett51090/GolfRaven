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
SELECT plan(21);

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
-- be deferrable OR carry ON DELETE CASCADE/SET NULL — a plain NO ACTION,
-- non-deferrable FK to such a table fails at whatever point in the
-- generic loop's (arbitrary) iteration order the referenced table
-- happens to be deleted, exactly H1's reproduction (offer_code.play_id/
-- entitlement.play_id, added by 0017, were NO ACTION + non-deferrable
-- until this same round fixed them). Independent of any specific data
-- test below, so a FUTURE FK added to a delete_row table without the
-- right shape fails here even before anyone seeds data that would
-- trigger it.
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
      AND NOT (con.condeferrable OR con.confdeltype IN ('c', 'n'))
      AND EXISTS (
        SELECT 1 FROM private.pii_retention_policy pol
        WHERE pol.schema_name = tn.nspname AND pol.table_name = target.relname AND pol.action = 'delete_row'
      )
  ),
  0,
  'every FK referencing a delete_row table is deferrable or ON DELETE CASCADE/SET NULL (H1)'
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

SELECT private.delete_my_data('00000000-0000-0000-0000-00000000000a'::uuid);

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
  (SELECT player_handle_snapshot FROM app.attestation_shift_log WHERE facility_id = 'fac_x' AND kind = 'presence' AND player_pseudonym = encode(public.digest('00000000-0000-0000-0000-00000000000a', 'sha256'), 'hex')),
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

SELECT * FROM finish();
ROLLBACK;

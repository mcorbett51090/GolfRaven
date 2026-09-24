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
SELECT plan(9);

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

SELECT * FROM finish();
ROLLBACK;

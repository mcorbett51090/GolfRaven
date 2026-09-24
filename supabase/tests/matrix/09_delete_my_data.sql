-- 09_delete_my_data.sql
-- build plan §10 P3 AT(6) (docs/golf-trails/02-build-plan.md:2759):
-- "DELETE /v1/me removes all personal rows (asserted by query), revokes
-- connectors and deletes push tokens; an unredeemed special-marker
-- entitlement or stock voucher is voided at once, and no address exists to
-- retain (O9/O10)."

BEGIN;
SELECT plan(12);

-- Precondition: player A has exactly the seeded rows before deletion.
SELECT is((SELECT count(*)::int FROM app.profile WHERE user_id = '00000000-0000-0000-0000-00000000000a'), 1, 'precondition: profile exists');
SELECT is((SELECT count(*)::int FROM app.entitlement WHERE user_id = '00000000-0000-0000-0000-00000000000a'), 1, 'precondition: entitlement exists (state earned)');

SELECT private.delete_my_data('00000000-0000-0000-0000-00000000000a'::uuid);

-- "removes all personal rows" — every DELETE-target table is empty for A.
SELECT is(
  (
    SELECT count(*)::int FROM (
      SELECT 1 FROM app.profile WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.device WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.push_token WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.evidence WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.purchase_evidence WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.play WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.play_evidence pe JOIN app.play p ON p.id = pe.play_id WHERE p.user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.user_achievement WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.device_reward_ledger WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.checkin_challenge WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.marker_credit WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.offer_code WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.connector_account WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.signin_provider_token WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.booking WHERE user_id = '00000000-0000-0000-0000-00000000000a'
      UNION ALL SELECT 1 FROM app.public_profile_projection WHERE handle = 'player_a'
    ) t
  ),
  0,
  'every personal table has zero rows for the deleted user (AT(6))'
);

-- "deletes push tokens" (line 832, 2759) — explicit, named check.
SELECT is((SELECT count(*)::int FROM app.push_token WHERE user_id = '00000000-0000-0000-0000-00000000000a'), 0, 'push tokens deleted');

-- "revokes connectors" (DB half: connector_account + signin_provider_token rows removed).
SELECT is((SELECT count(*)::int FROM app.connector_account WHERE user_id = '00000000-0000-0000-0000-00000000000a'), 0, 'connector_account rows removed');
SELECT is((SELECT count(*)::int FROM app.signin_provider_token WHERE user_id = '00000000-0000-0000-0000-00000000000a'), 0, 'signin_provider_token rows removed');

-- "an unredeemed special-marker entitlement ... is voided at once" — VOID,
-- not deleted (the row + its stock-movement audit trail survive).
SELECT is(
  (SELECT state::text FROM app.entitlement WHERE user_id = '00000000-0000-0000-0000-00000000000a'),
  'void',
  'the unredeemed special-marker entitlement is voided, not deleted'
);
SELECT is(
  (SELECT count(*)::int FROM app.entitlement WHERE user_id = '00000000-0000-0000-0000-00000000000a'),
  1,
  'the entitlement row itself still exists (voided in place, so the stock audit trail is not broken)'
);

-- attestation: nulled, not deleted (line 841, kept for staff-side audit
-- via player_pseudonym).
SELECT is(
  (SELECT count(*)::int FROM app.attestation WHERE id = 'a0000000-0000-0000-0000-000000000001' AND player_user_id IS NULL),
  1,
  'the attestation row survives with player_user_id nulled'
);

-- attestation_shift_log: snapshot replaced with "deleted player" (line 842).
SELECT is(
  (SELECT player_handle_snapshot FROM app.attestation_shift_log WHERE facility_id = 'fac_x' LIMIT 1),
  'deleted player',
  'the shift-log handle snapshot is rewritten to "deleted player"'
);

-- receipt_fingerprint: user_id nulled, row (and its 24-month fraud value)
-- kept (line 835's retention).
SELECT is(
  (SELECT count(*)::int FROM app.receipt_fingerprint WHERE id = '80000000-0000-0000-0000-000000000001' AND user_id IS NULL),
  1,
  'the receipt_fingerprint row survives with user_id nulled (24-month fraud retention preserved)'
);

-- "no address exists to retain" (O9/O10) — structural: no address/shipping
-- column exists on entitlement or anywhere in the schema (there never was
-- one to begin with; this asserts that stays true).
SELECT is(
  (SELECT count(*)::int FROM information_schema.columns
   WHERE table_schema = 'app' AND (column_name ILIKE '%address%' OR column_name ILIKE '%shipping%')),
  0,
  'no table carries an address/shipping column anywhere in the schema (O9/O10: nothing is shipped)'
);

SELECT * FROM finish();
ROLLBACK;

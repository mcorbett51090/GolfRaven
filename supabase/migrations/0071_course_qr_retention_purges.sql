-- 0071_course_qr_retention_purges.sql
--
-- P5 §57: retention for course-QR tables left open by S2a departure 6 /
-- partner-auth-design §56.3 — expired course_qr_token rows, aged
-- course_pin_alarm rows, and abandoned pending purchase_evidence rows
-- whose cosignal.awaiting.until has passed (they can no longer be
-- completed). Three bounded edge_system purges on the existing
-- retention-purge schedule (0040 / 0054 shape).
--
-- WHAT THIS ADDS
--   1. private.purge_course_qr_tokens()
--      expires_at < now() - 7 days; LIMIT 5000; used and unused alike.
--   2. private.purge_course_pin_alarms()
--      raised_at < now() - 90 days; LIMIT 5000.
--   3. private.purge_abandoned_pending_purchases()
--      status = 'pending' AND cosignal ? 'awaiting' AND until < now();
--      deletes linked pending marker_credit rows first, then the
--      purchase rows; LIMIT 5000 purchases per call. Method-agnostic
--      (course_qr / staff_scan / receipt all use the same awaiting seam).
--
-- POLICIES: each floor is repeated in a private_definer DELETE + SELECT
-- companion so private_definer can neither read nor delete a younger row
-- even if the body were wrong. Closed under a partner binding (same
-- InitPlan form as 0054 / 0050).
--
-- GRANTS: DELETE on course_pin_alarm (0016 already granted DELETE+SELECT
-- on course_qr_token / purchase_evidence / marker_credit). EXECUTE for
-- edge_system only on the three new definers.
--
-- DELIBERATELY NOT HERE: course_pin_epoch_log purge, PIN alarm UI,
-- pepper-rotation tooling, OCR / aHash / UI flag flips.
-- Nothing from 0001–0070 is edited.

-- ============================================================================
-- 1. Grants and policies (private_definer)
-- ============================================================================
GRANT DELETE ON app.course_pin_alarm TO private_definer;

-- Token: 7 days past expires_at (the operational TTL is 120 s; 7 days
-- matches consumed_nonce hygiene).
CREATE POLICY pd_purge_course_qr_token ON app.course_qr_token FOR DELETE TO private_definer
  USING (expires_at < now() - interval '7 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_course_qr_token_r ON app.course_qr_token FOR SELECT TO private_definer
  USING (expires_at < now() - interval '7 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- Alarm: 90 days past raised_at (operator-facing; no user id).
CREATE POLICY pd_purge_course_pin_alarm ON app.course_pin_alarm FOR DELETE TO private_definer
  USING (raised_at < now() - interval '90 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_course_pin_alarm_r ON app.course_pin_alarm FOR SELECT TO private_definer
  USING (raised_at < now() - interval '90 days'
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- Abandoned pending purchase: awaiting.until has passed.
CREATE POLICY pd_purge_abandoned_pending_purchase ON app.purchase_evidence FOR DELETE TO private_definer
  USING (status = 'pending'
         AND cosignal ? 'awaiting'
         AND (cosignal -> 'awaiting' ->> 'until')::timestamptz < now()
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_abandoned_pending_purchase_r ON app.purchase_evidence FOR SELECT TO private_definer
  USING (status = 'pending'
         AND cosignal ? 'awaiting'
         AND (cosignal -> 'awaiting' ->> 'until')::timestamptz < now()
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- Pending credits of those purchases (FK is ON DELETE SET NULL; delete
-- them explicitly so no orphan pending credit remains).
CREATE POLICY pd_purge_abandoned_pending_credit ON app.marker_credit FOR DELETE TO private_definer
  USING (status = 'pending'
         AND purchase_evidence_id IS NOT NULL
         AND EXISTS (
           SELECT 1 FROM app.purchase_evidence p
           WHERE p.id = marker_credit.purchase_evidence_id
             AND p.status = 'pending'
             AND p.cosignal ? 'awaiting'
             AND (p.cosignal -> 'awaiting' ->> 'until')::timestamptz < now()
         )
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');
CREATE POLICY pd_purge_abandoned_pending_credit_r ON app.marker_credit FOR SELECT TO private_definer
  USING (status = 'pending'
         AND purchase_evidence_id IS NOT NULL
         AND EXISTS (
           SELECT 1 FROM app.purchase_evidence p
           WHERE p.id = marker_credit.purchase_evidence_id
             AND p.status = 'pending'
             AND p.cosignal ? 'awaiting'
             AND (p.cosignal -> 'awaiting' ->> 'until')::timestamptz < now()
         )
         AND (SELECT private.partner_binding_kind()) IS DISTINCT FROM 'partner');

-- ============================================================================
-- 2. Definers (as private_definer)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE FUNCTION private.purge_course_qr_tokens()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.course_qr_token t
  WHERE t.nonce_hash = ANY (ARRAY(
    SELECT s.nonce_hash FROM app.course_qr_token s
    WHERE s.expires_at < pg_catalog.now() - interval '7 days'
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_course_pin_alarms()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  DELETE FROM app.course_pin_alarm a
  WHERE a.id = ANY (ARRAY(
    SELECT s.id FROM app.course_pin_alarm s
    WHERE s.raised_at < pg_catalog.now() - interval '90 days'
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

CREATE FUNCTION private.purge_abandoned_pending_purchases()
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_limit constant int := 5000;
  v_n integer;
BEGIN
  -- Drop pending credits of the same abandoned purchases first (FK is ON DELETE SET NULL;
  -- deleting them avoids orphan pending credits). Same InitPlan batch as the purchase DELETE.
  DELETE FROM app.marker_credit c
  WHERE c.status = 'pending'
    AND c.purchase_evidence_id = ANY (ARRAY(
      SELECT s.id FROM app.purchase_evidence s
      WHERE s.status = 'pending'
        AND s.cosignal ? 'awaiting'
        AND (s.cosignal -> 'awaiting' ->> 'until')::timestamptz < pg_catalog.now()
      LIMIT v_limit
    ));
  DELETE FROM app.purchase_evidence p
  WHERE p.id = ANY (ARRAY(
    SELECT s.id FROM app.purchase_evidence s
    WHERE s.status = 'pending'
      AND s.cosignal ? 'awaiting'
      AND (s.cosignal -> 'awaiting' ->> 'until')::timestamptz < pg_catalog.now()
    LIMIT v_limit
  ));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

REVOKE EXECUTE ON FUNCTION
  private.purge_course_qr_tokens(),
  private.purge_course_pin_alarms(),
  private.purge_abandoned_pending_purchases()
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_course_qr_tokens() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_course_pin_alarms() TO edge_system;
GRANT EXECUTE ON FUNCTION private.purge_abandoned_pending_purchases() TO edge_system;

COMMENT ON FUNCTION private.purge_course_qr_tokens() IS
  '0071 (§57). edge_system. Deletes course_qr_token rows whose expires_at is more than 7 days past, at most 5000 per call; returns the count. Floor repeated in pd_purge_course_qr_token[_r].';
COMMENT ON FUNCTION private.purge_course_pin_alarms() IS
  '0071 (§57). edge_system. Deletes course_pin_alarm rows whose raised_at is more than 90 days past, at most 5000 per call; returns the count. Floor repeated in pd_purge_course_pin_alarm[_r].';
COMMENT ON FUNCTION private.purge_abandoned_pending_purchases() IS
  '0071 (§57). edge_system. Deletes pending purchase_evidence rows whose cosignal.awaiting.until has passed (and their pending marker_credit rows), at most 5000 purchases per call; returns the purchase count. Method-agnostic. Floor repeated in pd_purge_abandoned_pending_purchase[_r] / pd_purge_abandoned_pending_credit[_r].';
COMMENT ON TABLE app.course_pin_alarm IS
  '0046/0071. One row each time the facility-wide wrong-PIN alarm (30 failures at one facility on one facility-local date, plan §9.2) rotated that facility''s PIN (pin_epoch + 1). Operator-facing: the portal (S2b / P5.1b) reads it. Holds no user id and no PIN, so it is not a personal table. Written only by private.course_pin_attempt_for_actor. Retention: private.purge_course_pin_alarms (raised_at older than 90 days).';

-- ============================================================================
-- 3. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'purge_abandoned_pending_purchases', '', false, false, false, false, true, false, false, '0071 (§57): edge_system; pending purchases past awaiting.until (+ their pending credits), 5000 per call'),
  ('private', 'purge_course_pin_alarms', '', false, false, false, false, true, false, false, '0071 (§57): edge_system; course_pin_alarm rows older than 90 days, 5000 per call'),
  ('private', 'purge_course_qr_tokens', '', false, false, false, false, true, false, false, '0071 (§57): edge_system; course_qr_token rows 7 days past expires_at, 5000 per call');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0071 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'course_pin_alarm', 'pd_purge_course_pin_alarm', 'DELETE', true, '0071 purge: alarms raised more than 90 days ago; closed under a partner binding', 'private_definer'),
  ('app', 'course_pin_alarm', 'pd_purge_course_pin_alarm_r', 'SELECT', true, 'row-visibility companion to pd_purge_course_pin_alarm', 'private_definer'),
  ('app', 'course_qr_token', 'pd_purge_course_qr_token', 'DELETE', true, '0071 purge: tokens 7 days past expires_at; closed under a partner binding', 'private_definer'),
  ('app', 'course_qr_token', 'pd_purge_course_qr_token_r', 'SELECT', true, 'row-visibility companion to pd_purge_course_qr_token', 'private_definer'),
  ('app', 'marker_credit', 'pd_purge_abandoned_pending_credit', 'DELETE', true, '0071 purge: pending credits of abandoned pending purchases; closed under a partner binding', 'private_definer'),
  ('app', 'marker_credit', 'pd_purge_abandoned_pending_credit_r', 'SELECT', true, 'row-visibility companion to pd_purge_abandoned_pending_credit', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_purge_abandoned_pending_purchase', 'DELETE', true, '0071 purge: pending purchases past awaiting.until; closed under a partner binding', 'private_definer'),
  ('app', 'purchase_evidence', 'pd_purge_abandoned_pending_purchase_r', 'SELECT', true, 'row-visibility companion to pd_purge_abandoned_pending_purchase', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class c ON c.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE al.schema_name = n.nspname AND al.table_name = c.relname AND al.policy_name = pol.polname
  AND pol.polname IN (
    'pd_purge_course_pin_alarm', 'pd_purge_course_pin_alarm_r',
    'pd_purge_course_qr_token', 'pd_purge_course_qr_token_r',
    'pd_purge_abandoned_pending_credit', 'pd_purge_abandoned_pending_credit_r',
    'pd_purge_abandoned_pending_purchase', 'pd_purge_abandoned_pending_purchase_r'
  );
DO $$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist
      WHERE policy_name IN (
        'pd_purge_course_pin_alarm', 'pd_purge_course_pin_alarm_r',
        'pd_purge_course_qr_token', 'pd_purge_course_qr_token_r',
        'pd_purge_abandoned_pending_credit', 'pd_purge_abandoned_pending_credit_r',
        'pd_purge_abandoned_pending_purchase', 'pd_purge_abandoned_pending_purchase_r'
      )) <> 8 THEN
    RAISE EXCEPTION '0071: expected 8 definer_policy_allowlist rows for the new purge policies';
  END IF;
END
$$;
DROP POLICY current_user_seed_definer_policy_allowlist_0071 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- Grant assertions: edge_system only; nobody else.
DO $$
BEGIN
  IF NOT (has_function_privilege('edge_system', 'private.purge_course_qr_tokens()', 'EXECUTE')
      AND has_function_privilege('edge_system', 'private.purge_course_pin_alarms()', 'EXECUTE')
      AND has_function_privilege('edge_system', 'private.purge_abandoned_pending_purchases()', 'EXECUTE')) THEN
    RAISE EXCEPTION '0071: edge_system must EXECUTE the three new purges';
  END IF;
  IF has_function_privilege('edge_actor', 'private.purge_course_qr_tokens()', 'EXECUTE')
     OR has_function_privilege('edge_partner', 'private.purge_course_qr_tokens()', 'EXECUTE')
     OR has_function_privilege('anon', 'private.purge_course_qr_tokens()', 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.purge_course_qr_tokens()', 'EXECUTE')
     OR has_function_privilege('service_role', 'private.purge_course_qr_tokens()', 'EXECUTE') THEN
    RAISE EXCEPTION '0071: purge_course_qr_tokens must not be EXECUTEable by client / partner / service_role';
  END IF;
END
$$;

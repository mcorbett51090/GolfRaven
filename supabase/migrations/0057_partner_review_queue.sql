-- 0057_partner_review_queue.sql
--
-- P5.1a, slice S4 (database half): RECEIPTS AND REVIEW. docs/security/partner-auth-design.md section 12 (S4), 12.1 (AT(11), AT(18), AT(7) handle escaping in exports; resolve_held_* reachable only through an A3
-- definer), 6.3 (A3 for held-review resolve), E20 (the held-review resolvers of 0027 are service_role-only today and say "the caller must authenticate the admin"), and the money doc's F7 ("the held-review queue has
-- no Edge Function yet") are the specification; its "As built: S4" section (design 27) is the reading guide for this file. Migrations 0001-0056 are untouched (0055 belongs to the parallel S2b slice and is not
-- created here).
--
-- WHAT THIS ADDS (all of it partner-bound: every `_for_partner` definer begins with private.partner_authorize)
--   1. private.partner_resolve_held_offer_code_for_partner(code_id, approve) and private.partner_resolve_held_entitlement_for_partner(entitlement_id, approve): class A3, ADMIN only. Wrap app.resolve_held_* (0027,
--      E20) so the Edge never reaches those functions: edge_partner still has no EXECUTE on them. The bound admin is p_resolved_by. Outcomes are STATUS rows (ok | not_found | not_held | budget_short), so an expected
--      refusal commits; only a missing authority (42501) or a malformed argument (22023) raises. The apply helpers (EXECUTE for nobody but their owner) translate the SQLSTATEs of resolve_held_* so the `_for_partner`
--      bodies stay free of EXCEPTION blocks (check 14).
--   2. private.partner_held_queue_for_partner(): class A0, ADMIN only. The open held_review offer_codes and entitlements plus open review_item rows the reviewer needs, with an SLA-breach flag (held longer than 48
--      hours; `[inference]`: the plan's §9.2 SLA number is not in the repository). No plaintext code, no DeviceCheck hash, no ledger row.
--   3. private.partner_review_sla_for_partner(): class A0, ADMIN only. Counts of open held rewards and open review_items, and of those past the SLA (the portal / ops alert surface).
--   4. BINDING-KEYED POLICIES: private.partner_bound_admin() and the private_definer policies that open held offer_code / entitlement / offer / device_reward_ledger / review_item / profile rows under a partner
--      binding of an admin, never under a GUC (the HARD RULE). Each is registered in definer_policy_allowlist and its checked-in fixture.
--   5. GRANT EXECUTE on app.resolve_held_* TO private_definer (the apply helpers call them); edge_partner, edge_actor and every other edge role still cannot. function_inventory notes for the two resolvers are updated.
--
-- DELIBERATELY NOT HERE (see design 27 "Not built, honestly"): the player-lane POST /v1/receipts upload (EXIF strip, size and type gates, phash); resolving a held PLAY (resolve_held_* moves the reward row, not the
-- play); clearing a fraud_signal; the contract-reviewer staffing trigger of roles-table.md.
--
-- CHECK 14: every `_for_partner` body begins with private.partner_authorize (a string-literal class), holds no dollar sign, double quote, backslash or E-string, and no EXCEPTION block.
-- OWNERSHIP BRACKET as 0054 / 0056: GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; CREATE FUNCTION ...; RESET ROLE; REVOKE CREATE.

-- ============================================================================
-- 1. Binding-keyed predicate (EXECUTE for nobody: policies and sibling definers owned by private_definer evaluate it)
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- true iff THIS transaction carries a partner binding whose member is an admin. Keyed on the binding, not a GUC.
CREATE FUNCTION private.partner_bound_admin()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM private.actor_binding b
    WHERE b.backend_pid = pg_catalog.pg_backend_pid()
      AND b.xact = pg_catalog.pg_current_xact_id_if_assigned()
      AND b.kind = 'partner'
      AND private.is_admin(b.actor_uid)
  );
$$;

REVOKE EXECUTE ON FUNCTION private.partner_bound_admin() FROM PUBLIC;
COMMENT ON FUNCTION private.partner_bound_admin() IS
  '0057. Policy predicate: a partner binding is bound in THIS transaction and its member is an admin. Keyed on the binding, not a GUC. No role holds EXECUTE but the owner.';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 2. Grants and policies (private_definer). Every policy is keyed on partner_bound_admin().
-- ============================================================================
-- 2a. held offer_codes the admin resolves (SELECT + UPDATE of the state machine columns resolve_held_offer_code writes).
CREATE POLICY pd_partner_review_offer_code_select ON app.offer_code FOR SELECT TO private_definer
  USING (private.partner_bound_admin());
CREATE POLICY pd_partner_review_offer_code_update ON app.offer_code FOR UPDATE TO private_definer
  USING (private.partner_bound_admin())
  WITH CHECK (private.partner_bound_admin());

-- 2b. held entitlements
CREATE POLICY pd_partner_review_entitlement_select ON app.entitlement FOR SELECT TO private_definer
  USING (private.partner_bound_admin());
CREATE POLICY pd_partner_review_entitlement_update ON app.entitlement FOR UPDATE TO private_definer
  USING (private.partner_bound_admin())
  WITH CHECK (private.partner_bound_admin());

-- 2c. offer budget the reservation path touches on approve of an unreserved hold
CREATE POLICY pd_partner_review_offer_select ON app.offer FOR SELECT TO private_definer
  USING (private.partner_bound_admin());
CREATE POLICY pd_partner_review_offer_update ON app.offer FOR UPDATE TO private_definer
  USING (private.partner_bound_admin())
  WITH CHECK (private.partner_bound_admin());

-- 2d. device_reward_ledger INSERT on approve-to-issued / approve-to-redeemable (the player's user_id, not the admin's)
CREATE POLICY pd_partner_review_ledger_insert ON app.device_reward_ledger FOR INSERT TO private_definer
  WITH CHECK (private.partner_bound_admin());
CREATE POLICY pd_partner_review_ledger_select ON app.device_reward_ledger FOR SELECT TO private_definer
  USING (private.partner_bound_admin());

-- 2e. review_item: the queue read (every open item); the budget-unreserved INSERT reserve_offer_for_code may write on approve
CREATE POLICY pd_partner_review_item_select ON app.review_item FOR SELECT TO private_definer
  USING (private.partner_bound_admin());
CREATE POLICY pd_partner_review_item_insert ON app.review_item FOR INSERT TO private_definer
  WITH CHECK (private.partner_bound_admin()
              AND subject_table = 'offer_code'
              AND kind IN ('held_offer_budget_unreserved', 'issued_offer_budget_unreserved'));

-- 2f. profile handle for the queue listing (admin only; the list filters by id)
CREATE POLICY pd_partner_review_profile_select ON app.profile FOR SELECT TO private_definer
  USING (private.partner_bound_admin());

-- ============================================================================
-- 3. The apply helpers (not _for_partner: they may hold an EXCEPTION block) and the four partner definers
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 3a. Translate app.resolve_held_offer_code SQLSTATEs into statuses. EXECUTE for nobody but the owner.
CREATE FUNCTION private.partner_resolve_held_offer_code_apply(p_code_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_state app.offer_code_state;
BEGIN
  BEGIN
    v_state := app.resolve_held_offer_code(p_code_id, p_approve, p_resolved_by);
    RETURN QUERY SELECT 'ok'::text, v_state::text;
  EXCEPTION
    WHEN SQLSTATE 'P0002' THEN RETURN QUERY SELECT 'not_found'::text, NULL::text;
    WHEN SQLSTATE '55000' THEN RETURN QUERY SELECT 'not_held'::text, NULL::text;
    WHEN check_violation THEN RETURN QUERY SELECT 'budget_short'::text, NULL::text;
  END;
END
$$;

-- 3b. Translate app.resolve_held_entitlement SQLSTATEs into statuses.
CREATE FUNCTION private.partner_resolve_held_entitlement_apply(p_entitlement_id uuid, p_approve boolean, p_resolved_by uuid)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_state app.entitlement_state;
BEGIN
  BEGIN
    v_state := app.resolve_held_entitlement(p_entitlement_id, p_approve, p_resolved_by);
    RETURN QUERY SELECT 'ok'::text, v_state::text;
  EXCEPTION
    WHEN SQLSTATE 'P0002' THEN RETURN QUERY SELECT 'not_found'::text, NULL::text;
    WHEN SQLSTATE '55000' THEN RETURN QUERY SELECT 'not_held'::text, NULL::text;
  END;
END
$$;

-- 3c. POST resolve/offer-code (class A3): an admin decides a held offer code. The bound uid is p_resolved_by.
CREATE FUNCTION private.partner_resolve_held_offer_code_for_partner(p_code_id uuid, p_approve boolean)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_resolve_held_offer_code_for_partner: only an admin may resolve a held reward' USING ERRCODE = '42501';
  END IF;
  IF p_code_id IS NULL OR p_approve IS NULL THEN
    RAISE EXCEPTION 'partner_resolve_held_offer_code_for_partner: a code id and an approve flag are required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY SELECT a.o_status, a.o_state FROM private.partner_resolve_held_offer_code_apply(p_code_id, p_approve, v_uid) a;
END
$$;

-- 3d. POST resolve/entitlement (class A3): an admin decides a held entitlement.
CREATE FUNCTION private.partner_resolve_held_entitlement_for_partner(p_entitlement_id uuid, p_approve boolean)
RETURNS TABLE (o_status text, o_state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A3');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_resolve_held_entitlement_for_partner: only an admin may resolve a held reward' USING ERRCODE = '42501';
  END IF;
  IF p_entitlement_id IS NULL OR p_approve IS NULL THEN
    RAISE EXCEPTION 'partner_resolve_held_entitlement_for_partner: an entitlement id and an approve flag are required' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY SELECT a.o_status, a.o_state FROM private.partner_resolve_held_entitlement_apply(p_entitlement_id, p_approve, v_uid) a;
END
$$;

-- 3e. GET queue (class A0, admin): held offer_codes, held entitlements and open review_items, newest holds first, capped.
-- SLA breach: held / open longer than 48 hours ([inference]).
CREATE FUNCTION private.partner_held_queue_for_partner()
RETURNS TABLE (
  o_kind text,
  o_id uuid,
  o_subject_table text,
  o_subject_id uuid,
  o_user_id uuid,
  o_handle text,
  o_facility_id text,
  o_trail_id text,
  o_hold_detail jsonb,
  o_reserved_amount numeric,
  o_held_at timestamptz,
  o_sla_breached boolean,
  o_review_kind text
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sla interval := interval '48 hours';
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_held_queue_for_partner: only an admin may read the held-review queue' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT q.o_kind, q.o_id, q.o_subject_table, q.o_subject_id, q.o_user_id, q.o_handle, q.o_facility_id, q.o_trail_id,
         q.o_hold_detail, q.o_reserved_amount, q.o_held_at, q.o_sla_breached, q.o_review_kind
  FROM (
    SELECT 'offer_code'::text AS o_kind, c.id AS o_id, 'offer_code'::text AS o_subject_table, c.id AS o_subject_id,
           c.user_id AS o_user_id, p.handle AS o_handle, c.facility_id AS o_facility_id, NULL::text AS o_trail_id,
           c.hold_detail AS o_hold_detail, c.reserved_amount AS o_reserved_amount, c.earned_at AS o_held_at,
           (c.earned_at < pg_catalog.now() - v_sla) AS o_sla_breached, NULL::text AS o_review_kind
    FROM app.offer_code c
    LEFT JOIN app.profile p ON p.user_id = c.user_id
    WHERE c.state = 'held_review'
    UNION ALL
    SELECT 'entitlement'::text, e.id, 'entitlement'::text, e.id, e.user_id, p.handle, NULL::text, e.trail_id,
           e.hold_detail, NULL::numeric, e.activated_at,
           (e.activated_at IS NOT NULL AND e.activated_at < pg_catalog.now() - v_sla), NULL::text
    FROM app.entitlement e
    LEFT JOIN app.profile p ON p.user_id = e.user_id
    WHERE e.state = 'held_review'
    UNION ALL
    SELECT 'review_item'::text, r.id, r.subject_table, r.subject_id, NULL::uuid, NULL::text, NULL::text, NULL::text,
           r.detail, NULL::numeric, r.created_at, (r.created_at < pg_catalog.now() - v_sla), r.kind
    FROM app.review_item r
    WHERE r.resolved_at IS NULL AND r.status = 'open'
  ) q
  ORDER BY q.o_sla_breached DESC, q.o_held_at ASC NULLS LAST, q.o_id
  LIMIT 500;
END
$$;

-- 3f. GET sla (class A0, admin): counts for the ops alert surface.
CREATE FUNCTION private.partner_review_sla_for_partner()
RETURNS TABLE (
  o_held_offer_codes bigint,
  o_held_entitlements bigint,
  o_open_review_items bigint,
  o_sla_breached_rewards bigint,
  o_sla_breached_review_items bigint,
  o_sla_hours integer
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_sla interval := interval '48 hours';
BEGIN
  v_uid := private.partner_authorize(NULL, NULL, ARRAY['operator']::app.partner_role[], 'A0');
  IF NOT private.is_admin(v_uid) THEN
    RAISE EXCEPTION 'partner_review_sla_for_partner: only an admin may read the review SLA summary' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT
    (SELECT pg_catalog.count(*) FROM app.offer_code c WHERE c.state = 'held_review'),
    (SELECT pg_catalog.count(*) FROM app.entitlement e WHERE e.state = 'held_review'),
    (SELECT pg_catalog.count(*) FROM app.review_item r WHERE r.resolved_at IS NULL AND r.status = 'open'),
    (SELECT pg_catalog.count(*) FROM app.offer_code c WHERE c.state = 'held_review' AND c.earned_at < pg_catalog.now() - v_sla)
      + (SELECT pg_catalog.count(*) FROM app.entitlement e WHERE e.state = 'held_review' AND e.activated_at IS NOT NULL AND e.activated_at < pg_catalog.now() - v_sla),
    (SELECT pg_catalog.count(*) FROM app.review_item r WHERE r.resolved_at IS NULL AND r.status = 'open' AND r.created_at < pg_catalog.now() - v_sla),
    48;
END
$$;

REVOKE EXECUTE ON FUNCTION private.partner_resolve_held_offer_code_apply(uuid, boolean, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_resolve_held_entitlement_apply(uuid, boolean, uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_resolve_held_offer_code_for_partner(uuid, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_resolve_held_entitlement_for_partner(uuid, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_held_queue_for_partner() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.partner_review_sla_for_partner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.partner_resolve_held_offer_code_for_partner(uuid, boolean) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_resolve_held_entitlement_for_partner(uuid, boolean) TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_held_queue_for_partner() TO edge_partner;
GRANT EXECUTE ON FUNCTION private.partner_review_sla_for_partner() TO edge_partner;
COMMENT ON FUNCTION private.partner_resolve_held_offer_code_apply(uuid, boolean, uuid) IS
  '0057. Translates app.resolve_held_offer_code SQLSTATEs into statuses. Reads no binding; EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_resolve_held_entitlement_apply(uuid, boolean, uuid) IS
  '0057. Translates app.resolve_held_entitlement SQLSTATEs into statuses. Reads no binding; EXECUTE for nobody but the owner.';
COMMENT ON FUNCTION private.partner_resolve_held_offer_code_for_partner(uuid, boolean) IS
  '0057 (S4, E20). edge_partner only; class A3; ADMIN only. Wraps app.resolve_held_offer_code so the Edge never reaches it. Statuses: ok | not_found | not_held | budget_short.';
COMMENT ON FUNCTION private.partner_resolve_held_entitlement_for_partner(uuid, boolean) IS
  '0057 (S4, E20). edge_partner only; class A3; ADMIN only. Wraps app.resolve_held_entitlement. Statuses: ok | not_found | not_held.';
COMMENT ON FUNCTION private.partner_held_queue_for_partner() IS
  '0057 (S4). edge_partner only; class A0; ADMIN only. The open held_review rewards and open review_items, with an SLA-breach flag (48 h, [inference]).';
COMMENT ON FUNCTION private.partner_review_sla_for_partner() IS
  '0057 (S4). edge_partner only; class A0; ADMIN only. Counts of open held rewards and review_items, and of those past the 48 h SLA ([inference]).';
RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. resolve_held_* reachable by private_definer (the apply helpers); still NOT by any edge role. Inventory notes updated.
-- ============================================================================
GRANT EXECUTE ON FUNCTION app.resolve_held_offer_code(uuid, boolean, uuid) TO private_definer;
GRANT EXECUTE ON FUNCTION app.resolve_held_entitlement(uuid, boolean, uuid) TO private_definer;

DO $assert_0057_resolve$
BEGIN
  IF has_function_privilege('edge_partner', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_partner', 'app.resolve_held_entitlement(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_actor', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_actor', 'app.resolve_held_entitlement(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_system', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_system', 'app.resolve_held_entitlement(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('edge_partner_minter', 'app.resolve_held_entitlement(uuid, boolean, uuid)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0057: an edge role can EXECUTE app.resolve_held_* (S4: reachable only through the A3 partner wrappers)';
  END IF;
  IF NOT has_function_privilege('private_definer', 'app.resolve_held_offer_code(uuid, boolean, uuid)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('private_definer', 'app.resolve_held_entitlement(uuid, boolean, uuid)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0057: private_definer cannot EXECUTE app.resolve_held_* (the apply helpers need it)';
  END IF;
END
$assert_0057_resolve$;

UPDATE private.function_inventory
SET note = 'P3f / 0057 (S4): the §9.2 review decision on a held offer code; p_resolved_by must be an admin. service_role and private_definer (the A3 partner wrapper calls it); no edge role'
WHERE schema_name = 'app' AND function_name = 'resolve_held_offer_code';
UPDATE private.function_inventory
SET note = 'P3f / 0057 (S4): the §9.2 review decision on a held entitlement; p_resolved_by must be an admin. service_role and private_definer (the A3 partner wrapper calls it); no edge role'
WHERE schema_name = 'app' AND function_name = 'resolve_held_entitlement';

-- ============================================================================
-- 5. Registries
-- ============================================================================
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, expected_edge_partner, expected_edge_partner_minter, note)
VALUES
  ('private', 'partner_bound_admin', '', false, false, false, false, false, false, false, '0057 (S4): policy predicate, a partner binding of an admin; EXECUTE for nobody but the owner'),
  ('private', 'partner_held_queue_for_partner', '', false, false, false, false, false, true, false, '0057 (S4): edge_partner only; class A0; ADMIN only; the held-review queue read'),
  ('private', 'partner_resolve_held_entitlement_apply', 'p_entitlement_id uuid, p_approve boolean, p_resolved_by uuid', false, false, false, false, false, false, false, '0057 (S4): status translation of app.resolve_held_entitlement; EXECUTE for nobody but the owner'),
  ('private', 'partner_resolve_held_entitlement_for_partner', 'p_entitlement_id uuid, p_approve boolean', false, false, false, false, false, true, false, '0057 (S4, E20): edge_partner only; class A3; ADMIN only; wraps resolve_held_entitlement'),
  ('private', 'partner_resolve_held_offer_code_apply', 'p_code_id uuid, p_approve boolean, p_resolved_by uuid', false, false, false, false, false, false, false, '0057 (S4): status translation of app.resolve_held_offer_code; EXECUTE for nobody but the owner'),
  ('private', 'partner_resolve_held_offer_code_for_partner', 'p_code_id uuid, p_approve boolean', false, false, false, false, false, true, false, '0057 (S4, E20): edge_partner only; class A3; ADMIN only; wraps resolve_held_offer_code'),
  ('private', 'partner_review_sla_for_partner', '', false, false, false, false, false, true, false, '0057 (S4): edge_partner only; class A0; ADMIN only; SLA counts for the ops alert surface');

GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0057 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note, role_name) VALUES
  ('app', 'offer_code', 'pd_partner_review_offer_code_select', 'SELECT', true, 'S4: an admin partner binding reads every offer_code (the held-review queue and resolve)', 'private_definer'),
  ('app', 'offer_code', 'pd_partner_review_offer_code_update', 'UPDATE', true, 'S4: an admin partner binding updates a held offer_code through resolve_held_offer_code', 'private_definer'),
  ('app', 'entitlement', 'pd_partner_review_entitlement_select', 'SELECT', true, 'S4: an admin partner binding reads every entitlement (the held-review queue and resolve)', 'private_definer'),
  ('app', 'entitlement', 'pd_partner_review_entitlement_update', 'UPDATE', true, 'S4: an admin partner binding updates a held entitlement through resolve_held_entitlement', 'private_definer'),
  ('app', 'offer', 'pd_partner_review_offer_select', 'SELECT', true, 'S4: an admin partner binding reads offer rows the reservation path needs on approve', 'private_definer'),
  ('app', 'offer', 'pd_partner_review_offer_update', 'UPDATE', true, 'S4: an admin partner binding updates offer.budget_reserved on approve of an unreserved hold', 'private_definer'),
  ('app', 'device_reward_ledger', 'pd_partner_review_ledger_insert', 'INSERT', true, 'S4: an admin partner binding inserts the ledger row of an approve-to-issued / approve-to-redeemable', 'private_definer'),
  ('app', 'device_reward_ledger', 'pd_partner_review_ledger_select', 'SELECT', true, 'S4: INSERT ... ON CONFLICT needs the ledger row visible under an admin partner binding', 'private_definer'),
  ('app', 'review_item', 'pd_partner_review_item_select', 'SELECT', true, 'S4: an admin partner binding reads every review_item (the queue)', 'private_definer'),
  ('app', 'review_item', 'pd_partner_review_item_insert', 'INSERT', true, 'S4: reserve_offer_for_code may write a budget-unreserved item under an admin partner binding on approve', 'private_definer'),
  ('app', 'profile', 'pd_partner_review_profile_select', 'SELECT', true, 'S4: an admin partner binding reads handles for the held-review queue listing', 'private_definer');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_partner_review_offer_code_select', 'pd_partner_review_offer_code_update', 'pd_partner_review_entitlement_select', 'pd_partner_review_entitlement_update',
    'pd_partner_review_offer_select', 'pd_partner_review_offer_update', 'pd_partner_review_ledger_insert', 'pd_partner_review_ledger_select',
    'pd_partner_review_item_select', 'pd_partner_review_item_insert', 'pd_partner_review_profile_select');
DO $assert_0057_allowlist$
BEGIN
  IF (SELECT count(*) FROM private.definer_policy_allowlist WHERE policy_name IN (
    'pd_partner_review_offer_code_select', 'pd_partner_review_offer_code_update', 'pd_partner_review_entitlement_select', 'pd_partner_review_entitlement_update',
    'pd_partner_review_offer_select', 'pd_partner_review_offer_update', 'pd_partner_review_ledger_insert', 'pd_partner_review_ledger_select',
    'pd_partner_review_item_select', 'pd_partner_review_item_insert', 'pd_partner_review_profile_select')
        AND (using_expr IS NOT NULL OR with_check_expr IS NOT NULL)) <> 11 THEN
    RAISE EXCEPTION '0057: an allowlist row names no live policy (its expressions were not derived)';
  END IF;
END
$assert_0057_allowlist$;
DROP POLICY current_user_seed_definer_policy_allowlist_0057 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

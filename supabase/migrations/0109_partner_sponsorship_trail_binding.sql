-- 0109_partner_sponsorship_trail_binding.sql
--
-- P5 §137: the sponsorship an offer, or a trail's special marker, is funded by must be a sponsorship OF THAT TRAIL.
--
-- WHAT WAS WRONG (observed on the real database, 2026-10-12, an operator of trl_t bound to a real session; the probe is in design section 137.2).
-- private.partner_offer_upsert_for_partner (0059) checked that a sponsor offer names a sponsorship and that any other offer does not, and nothing else: the only
-- thing between a sponsorship id and the offer row was the foreign key. So an operator of one trail could write an offer on THEIR trail funded by a sponsorship of
-- ANOTHER trail (the id is a random uuid, but it is shown to that trail's operators and admins), and the settlement export (0060/0062: "one row per facility, funder
-- and sponsorship") then attributes the redemptions to the other trail's sponsor. private.partner_trail_programme_upsert_for_partner (0059) had the same hole for
-- special_marker_sponsorship_id. An id that names NO sponsorship was a raw foreign-key violation (23503) that the Edge does not translate.
--
-- WHAT THIS CHANGES (two functions, CREATE OR REPLACE; owner, ACL, search_path, volatility untouched; no other function, table, policy or grant)
--   1. partner_offer_upsert_for_partner: a non-null p_sponsorship_id that is not a sponsorship of p_trail_id is the existing status bad_funder (422 on the Edge,
--      already mapped and already translated by the portal). One answer for "another trail's" and "no such id", so the refusal says nothing about anyone else's ids.
--   2. partner_trail_programme_upsert_for_partner: a non-null p_special_marker_sponsorship_id that is not a sponsorship of p_trail_id is 22023 (the Edge maps it to
--      422 invalid_request, as for every other malformed argument). The statuses of both functions are unchanged; the Edge needs no change.
--
-- DELIBERATELY NOT HERE (product calls, listed in design section 137.3): that a sponsorship be live (not draft or ended) or have a scope that includes offers; that
-- special_marker_funded_by = 'sponsor' go with a sponsorship id and 'trail' without one. Nothing from 0001-0107 is edited. Migration 0108 is left to the open
-- draft that claims it (PR #162); nothing here depends on it and it depends on nothing here.

GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.partner_trail_programme_upsert_for_partner(
  p_trail_id text,
  p_status text,
  p_marker_source text,
  p_marker_requires_completion boolean,
  p_special_marker_funded_by text,
  p_special_marker_low_threshold integer,
  p_web_player_flow boolean,
  p_special_marker_sku text,
  p_special_marker_sponsorship_id uuid,
  p_fee_model text,
  p_fee_amount numeric,
  p_starts_on date,
  p_ends_on date
)
RETURNS TABLE (o_status text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  n integer;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = ''
     OR p_status IS NULL OR p_status NOT IN ('off', 'pilot', 'live')
     OR p_marker_source IS NULL OR p_marker_source NOT IN ('any_purchase', 'programme_marker')
     OR p_marker_requires_completion IS NULL
     OR (p_special_marker_funded_by IS NOT NULL AND p_special_marker_funded_by NOT IN ('trail', 'sponsor'))
     OR p_special_marker_low_threshold IS NULL OR p_special_marker_low_threshold < 0 OR p_special_marker_low_threshold > 100000
     OR (p_fee_model IS NOT NULL AND p_fee_model NOT IN ('flat', 'per_redemption', 'none'))
     OR (p_special_marker_sku IS NOT NULL AND pg_catalog.char_length(p_special_marker_sku) > 120) THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: a trail, status, marker_source, marker_requires_completion and a non-negative low_threshold are required' USING ERRCODE = '22023';
  END IF;
  IF p_web_player_flow IS TRUE THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: web_player_flow must stay false' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.catalog_id_ledger l WHERE l.id = p_trail_id AND l.kind = 'trail') THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  -- 0109: the sponsorship named for the special marker is one of THIS trail (a foreign trail's sponsorship, or an id that names none, is 22023 like the other bad arguments;
  -- before 0109 the first was accepted and the second was a raw foreign-key error).
  IF p_special_marker_sponsorship_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM app.sponsorship s WHERE s.id = p_special_marker_sponsorship_id AND s.trail_id = p_trail_id
  ) THEN
    RAISE EXCEPTION 'partner_trail_programme_upsert_for_partner: the sponsorship must be one of this trail' USING ERRCODE = '22023';
  END IF;
  INSERT INTO app.trail_programme (
    trail_id, status, marker_source, marker_requires_completion, special_marker_funded_by,
    special_marker_low_threshold, web_player_flow, special_marker_sku, special_marker_sponsorship_id,
    fee_model, fee_amount, starts_on, ends_on
  ) VALUES (
    p_trail_id, p_status::app.programme_status, p_marker_source::app.marker_source, p_marker_requires_completion,
    p_special_marker_funded_by::app.special_marker_funded_by, p_special_marker_low_threshold, false,
    p_special_marker_sku, p_special_marker_sponsorship_id, p_fee_model::app.fee_model, p_fee_amount, p_starts_on, p_ends_on
  )
  ON CONFLICT (trail_id) DO UPDATE SET
    status = EXCLUDED.status,
    marker_source = EXCLUDED.marker_source,
    marker_requires_completion = EXCLUDED.marker_requires_completion,
    special_marker_funded_by = EXCLUDED.special_marker_funded_by,
    special_marker_low_threshold = EXCLUDED.special_marker_low_threshold,
    web_player_flow = false,
    special_marker_sku = EXCLUDED.special_marker_sku,
    special_marker_sponsorship_id = EXCLUDED.special_marker_sponsorship_id,
    fee_model = EXCLUDED.fee_model,
    fee_amount = EXCLUDED.fee_amount,
    starts_on = EXCLUDED.starts_on,
    ends_on = EXCLUDED.ends_on;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> 1 THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  END IF;
  PERFORM private.partner_audit_write('partner.trail_programme_upsert', 'app.trail_programme', p_trail_id,
    pg_catalog.jsonb_build_object('status', p_status, 'marker_source', p_marker_source));
  RETURN QUERY SELECT 'ok'::text;
END
$$;

CREATE OR REPLACE FUNCTION private.partner_offer_upsert_for_partner(
  p_id uuid,
  p_trail_id text,
  p_facility_id text,
  p_eligibility jsonb,
  p_funder text,
  p_sponsorship_id uuid,
  p_budget_cap numeric,
  p_max_redemptions integer,
  p_face_value numeric,
  p_valid_from date,
  p_valid_to date
)
RETURNS TABLE (o_status text, o_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_row record;
  v_id uuid;
BEGIN
  v_uid := private.partner_authorize(NULL, p_trail_id, ARRAY['operator']::app.partner_role[], 'A3');
  IF p_trail_id IS NULL OR pg_catalog.btrim(p_trail_id) = '' OR p_facility_id IS NULL OR pg_catalog.btrim(p_facility_id) = ''
     OR p_eligibility IS NULL OR p_funder IS NULL OR p_budget_cap IS NULL OR p_budget_cap < 0
     OR p_face_value IS NULL OR p_face_value < 0 OR p_valid_from IS NULL OR p_valid_to IS NULL
     OR p_valid_to < p_valid_from
     OR (p_max_redemptions IS NOT NULL AND p_max_redemptions < 0) THEN
    RAISE EXCEPTION 'partner_offer_upsert_for_partner: a trail, facility, eligibility, funder, budget_cap, face_value and a valid date range are required' USING ERRCODE = '22023';
  END IF;
  IF p_funder NOT IN ('course', 'operator', 'sponsor') THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_funder = 'sponsor' AND p_sponsorship_id IS NULL THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_funder <> 'sponsor' AND p_sponsorship_id IS NOT NULL THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  -- 0109: the sponsorship that funds an offer is one of THIS trail. Another trail's sponsorship, and an id that names no sponsorship at all, are the same refusal
  -- (so the answer is not a way to ask whether an id belongs to somebody else); before 0109 the first was accepted and the second was a raw foreign-key error.
  IF p_sponsorship_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM app.sponsorship s WHERE s.id = p_sponsorship_id AND s.trail_id = p_trail_id
  ) THEN
    RETURN QUERY SELECT 'bad_funder'::text, NULL::uuid;
    RETURN;
  END IF;
  IF p_id IS NULL THEN
    v_id := pg_catalog.gen_random_uuid();
    INSERT INTO app.offer (
      id, trail_id, facility_id, eligibility, funder, sponsorship_id, budget_cap,
      max_redemptions, face_value, valid_from, valid_to, status
    ) VALUES (
      v_id, p_trail_id, p_facility_id, p_eligibility, p_funder::app.offer_funder, p_sponsorship_id, p_budget_cap,
      p_max_redemptions, p_face_value, p_valid_from, p_valid_to, 'draft'
    );
    PERFORM private.partner_audit_write('partner.offer_upsert', 'app.offer', v_id::text,
      pg_catalog.jsonb_build_object('trail', p_trail_id, 'status', 'draft'));
    RETURN QUERY SELECT 'ok'::text, v_id;
    RETURN;
  END IF;
  SELECT o.status INTO v_row FROM app.offer o WHERE o.id = p_id AND o.trail_id = p_trail_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'not_found'::text, NULL::uuid;
    RETURN;
  END IF;
  IF v_row.status <> 'draft' THEN
    RETURN QUERY SELECT 'not_draft'::text, p_id;
    RETURN;
  END IF;
  UPDATE app.offer SET
    facility_id = p_facility_id,
    eligibility = p_eligibility,
    funder = p_funder::app.offer_funder,
    sponsorship_id = p_sponsorship_id,
    budget_cap = p_budget_cap,
    max_redemptions = p_max_redemptions,
    face_value = p_face_value,
    valid_from = p_valid_from,
    valid_to = p_valid_to
  WHERE id = p_id AND status = 'draft';
  PERFORM private.partner_audit_write('partner.offer_upsert', 'app.offer', p_id::text,
    pg_catalog.jsonb_build_object('trail', p_trail_id, 'status', 'draft'));
  RETURN QUERY SELECT 'ok'::text, p_id;
END
$$;

COMMENT ON FUNCTION private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date) IS
  '0059/0109 (S6, section 137). edge_partner only; class A3 (operator of the trail). INSERT or UPDATE trail_programme. web_player_flow true is 22023; a special_marker_sponsorship_id that is not a sponsorship of this trail is 22023. Statuses: ok | not_found.';
COMMENT ON FUNCTION private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date) IS
  '0059/0109 (S6, section 137). edge_partner only; class A3. Create or edit a draft offer; a sponsorship that is not one of this trail is bad_funder. Statuses: ok | not_found | not_draft | bad_funder.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

GRANT INSERT, UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0109 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);

UPDATE private.function_inventory
SET note = '0059/0109 (S6, section 137): edge_partner only; class A3; trail_programme upsert; the special-marker sponsorship must be of this trail (22023)'
WHERE schema_name = 'private'
  AND function_name = 'partner_trail_programme_upsert_for_partner';

UPDATE private.function_inventory
SET note = '0059/0109 (S6, section 137): edge_partner only; class A3; draft offer upsert; the sponsorship must be of this trail (bad_funder)'
WHERE schema_name = 'private'
  AND function_name = 'partner_offer_upsert_for_partner';

DROP POLICY current_user_edit_function_inventory_0109 ON private.function_inventory;
REVOKE INSERT, UPDATE ON private.function_inventory FROM CURRENT_USER;

DO $assert_0109$
DECLARE
  v_def text;
  v_acl text;
BEGIN
  SELECT pg_get_functiondef('private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT LIKE '%s.trail_id = p_trail_id%' THEN
    RAISE EXCEPTION '0109: partner_offer_upsert_for_partner must check the sponsorship against the trail';
  END IF;
  SELECT pg_get_functiondef('private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure) INTO v_def;
  IF v_def IS NULL OR v_def NOT LIKE '%s.trail_id = p_trail_id%' THEN
    RAISE EXCEPTION '0109: partner_trail_programme_upsert_for_partner must check the sponsorship against the trail';
  END IF;
  -- CREATE OR REPLACE keeps the ACL; assert that it did (edge_partner may execute, nobody else but the owner)
  IF NOT has_function_privilege('edge_partner', 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure, 'EXECUTE')
     OR NOT has_function_privilege('edge_partner', 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('authenticated', 'private.partner_offer_upsert_for_partner(uuid, text, text, jsonb, text, uuid, numeric, integer, numeric, date, date)'::regprocedure, 'EXECUTE')
     OR has_function_privilege('anon', 'private.partner_trail_programme_upsert_for_partner(text, text, text, boolean, text, integer, boolean, text, uuid, text, numeric, date, date)'::regprocedure, 'EXECUTE') THEN
    RAISE EXCEPTION '0109: the EXECUTE set of the two upsert definers changed';
  END IF;
END
$assert_0109$;

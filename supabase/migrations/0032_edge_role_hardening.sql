-- 0032_edge_role_hardening.sql
-- PR1b of the NOBYPASSRLS edge-role work (follow-up 6): closes the findings of the PR1 security gate
-- (docs/security/p3-money-path-requirements.md, "Edge role PR1 gate PASS ... findings to close before PR2").
-- 0030 and 0031 are merged and immutable; everything below is NEW. Nothing here touches anon,
-- authenticated or service_role, and every table keeps ENABLE + FORCE ROW LEVEL SECURITY.
--
-- WHAT THIS CLOSES
--   L3  an asserting DO block: if a pre-existing edge_* role is misconfigured (SUPERUSER / BYPASSRLS /
--       REPLICATION / CREATEROLE / CREATEDB / INHERIT, a login on the two NOLOGIN roles, a membership outside
--       the intended set) this migration refuses to run, instead of trusting the CREATE ROLE IF NOT EXISTS
--       guard in 0030 (which skips a role that already exists, however it is configured).
--   M2  two one-way columns were reversible under edge_actor: app.checkin_token.consumed_at (a consumed
--       presence token could be reset to NULL and replayed) and app.device.attest_counter (an App Attest
--       counter could be rolled back, defeating the anti-replay). BEFORE UPDATE triggers make them set-once /
--       monotonic for EVERY role, exactly like 0017's checkin_challenge_used_at_once.
--   M3  the own-row INSERT policies checked only user_id: an actor could write a row that REFERENCES another
--       user's device or challenge, and the FK check doubled as an existence oracle. The INSERT policies of
--       checkin_challenge, checkin_token, evidence and push_token now also require the referenced device (and
--       challenge) to be the actor's own. The oracle is closed, not just documented: RLS WITH CHECK is evaluated
--       BEFORE the foreign-key trigger, so a foreign id and a nonexistent id both fail the same WITH CHECK with
--       the same 42501 and the FK is never reached (proved in 16_edge_role.sql).
--   M4  (R1 and R2 of 0031, now closed -- the PR4 precondition). edge_actor no longer has ANY write on the shared
--       offer budget or on a reward's state:
--         * UPDATE on app.offer, app.offer_code and app.entitlement, INSERT on app.device_reward_ledger and every
--           privilege on app.review_item are revoked, with their policies;
--         * EXECUTE on app.activate_offer_code / activate_entitlement / reserve_offer_for_code /
--           release_offer_budget / release_account_reservations is revoked;
--         * activation, the play-hold cascade and account deletion reach those writes only through three
--           SECURITY DEFINER functions owned by private_definer that take NO caller-chosen user or amount:
--           private.activate_offer_code_for_actor / activate_entitlement_for_actor (they call the unchanged P3f
--           app.activate_* with the BOUND actor's uid) and private.hold_play_rewards_for_actor (the held-review
--           cascade's body, extracted unchanged into app.hold_play_rewards), plus delete_my_data_for_actor,
--           which now releases the account's reservations itself;
--         * private_definer gets ACTOR-KEYED policies (user_id = private.actor_uid(), and for the offer row "an offer
--           the actor holds a code on") and a column-limited UPDATE (budget_reserved) on app.offer. The amount
--           reserved or released is always the code's own reserved_amount or the offer's face_value, read in the
--           database, never an argument. P3f's functions are NOT edited: they simply run as private_definer.
--   L1  private.delete_my_data read pg_constraint / pg_class / pg_namespace / pg_attribute unqualified; edge_actor
--       holds TEMP, and pg_temp is searched BEFORE pg_catalog for relations even with search_path = '', so a temp
--       table of that name shadowed the catalog (it failed closed through the post-condition, but it should not
--       be shadowable at all). Redefined from its current body (0022) with pg_catalog. qualified, nothing else changed.
--   L5  audit_log INSERT now ties subject_id to the actor's own play; install_link_account INSERT ties the row to
--       the actor's own device's link hash and to the key that produced the pseudonym; review_item is no longer
--       readable or writable by edge_actor at all (M4).
--   NIT pd_device_link_read compares the device GUC as text (a non-uuid session value can no longer raise 22P02
--       on reads); purge_fix_coords refuses a retention shorter than 7 days (the importer uses 30).
--
-- Not changed here (L2/L6, verification only): checks 9 and 12 of tools/db/verify-function-inventory.mjs (and the
-- twins in supabase/tests/matrix/10_function_inventory.sql) are extended, and 16_edge_role.sql gained the
-- session-reuse cells for the three GUC windows. Registries: private.edge_policy_allowlist,
-- private.definer_policy_allowlist and private.function_inventory are updated below, and both fixtures
-- (supabase/tests/fixtures/edge_policy_exprs.txt, definer_policy_exprs.txt) are regenerated.
--
-- Same bracket as 0030: functions owned by private_definer are created INSIDE
-- GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; ... RESET ROLE; REVOKE CREATE.
-- `migration_owner` is never named.

-- ============================================================================
-- 0. L3: refuse to run against a misconfigured edge role
-- ============================================================================
DO $$
DECLARE
  v_bad text;
BEGIN
  IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('edge_gateway', 'edge_actor', 'edge_system')) <> 3 THEN
    RAISE EXCEPTION '0032: edge_gateway / edge_actor / edge_system must all exist (0030 creates them)';
  END IF;

  SELECT string_agg(r.rolname || ' has ' || a.attr, '; ') INTO v_bad
  FROM pg_roles r
  CROSS JOIN LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('BYPASSRLS', r.rolbypassrls), ('REPLICATION', r.rolreplication),
                             ('CREATEROLE', r.rolcreaterole), ('CREATEDB', r.rolcreatedb), ('INHERIT', r.rolinherit)) AS a(attr, is_on)
  WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system') AND a.is_on;
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0032: an edge role holds an attribute it must not (SUPERUSER, BYPASSRLS, REPLICATION, CREATEROLE, CREATEDB, INHERIT): %', v_bad;
  END IF;

  SELECT string_agg(rolname, ', ') INTO v_bad FROM pg_roles WHERE rolname IN ('edge_actor', 'edge_system') AND rolcanlogin;
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0032: edge_actor / edge_system must be NOLOGIN (only edge_gateway logs in): %', v_bad;
  END IF;

  -- An edge role must be a member of nothing but (edge_gateway -> edge_actor, edge_system).
  SELECT string_agg(m.rolname || ' is a member of ' || r.rolname, '; ') INTO v_bad
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
  WHERE m.rolname IN ('edge_gateway', 'edge_actor', 'edge_system')
    AND NOT (m.rolname = 'edge_gateway' AND r.rolname IN ('edge_actor', 'edge_system'));
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0032: an edge role is a member of a role outside the intended set: %', v_bad;
  END IF;

  -- edge_gateway's membership of the other two is SET TRUE, INHERIT FALSE, and without ADMIN OPTION.
  SELECT string_agg('edge_gateway -> ' || r.rolname, '; ') INTO v_bad
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
  WHERE m.rolname = 'edge_gateway' AND r.rolname IN ('edge_actor', 'edge_system')
    AND (NOT am.set_option OR am.inherit_option OR am.admin_option);
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0032: edge_gateway must be a SET TRUE, INHERIT FALSE, non-admin member of edge_actor and edge_system: %', v_bad;
  END IF;

  -- Nobody outside the three may be a member of an edge role, except a SUPERUSER / CREATEROLE role holding it
  -- WITHOUT set and inherit (the migrating role's ADMIN OPTION from CREATE ROLE).
  SELECT string_agg(m.rolname || ' -> ' || r.rolname, '; ') INTO v_bad
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member JOIN pg_roles r ON r.oid = am.roleid
  WHERE r.rolname IN ('edge_gateway', 'edge_actor', 'edge_system') AND m.rolname NOT IN ('edge_gateway', 'edge_actor', 'edge_system')
    AND (am.set_option OR am.inherit_option OR NOT (m.rolsuper OR m.rolcreaterole));
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION '0032: a role outside the edge set is a member of an edge role: %', v_bad;
  END IF;
END
$$;

-- ============================================================================
-- 1. M2: one-way columns (set-once / monotonic), for EVERY role
-- ============================================================================
CREATE FUNCTION app.checkin_token_consumed_at_once() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- Same contract as app.checkin_challenge_used_at_once (0017): once consumed_at is set, any UPDATE that touches
  -- the column is refused -- it cannot be cleared (replay of a presence token) or moved, and re-writing the
  -- identical value is refused too (now() is transaction-stable, so "set it again" would otherwise look like a no-op).
  IF OLD.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'checkin_token: consumed_at is already set (%) and cannot be changed or cleared (id=%)', OLD.consumed_at, OLD.jti
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER checkin_token_consumed_at_once_trg
BEFORE UPDATE OF consumed_at ON app.checkin_token
FOR EACH ROW EXECUTE FUNCTION app.checkin_token_consumed_at_once();

CREATE FUNCTION app.device_attest_counter_monotonic() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- The App Attest assertion counter only ever moves forward (the verifier's own statement is
  -- `UPDATE ... WHERE attest_counter < $new`); a lower value is a replay window being re-opened.
  IF NEW.attest_counter < OLD.attest_counter THEN
    RAISE EXCEPTION 'device: attest_counter is monotonic (% -> % refused, id=%)', OLD.attest_counter, NEW.attest_counter, OLD.id
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER device_attest_counter_monotonic_trg
BEFORE UPDATE OF attest_counter ON app.device
FOR EACH ROW EXECUTE FUNCTION app.device_attest_counter_monotonic();

-- ============================================================================
-- 2. M4 (part 1): take the write paths away from edge_actor
-- ============================================================================
-- A table-level REVOKE also revokes the column-level grants of the same privilege (0031 granted column lists).
REVOKE UPDATE ON app.offer, app.offer_code, app.entitlement FROM edge_actor;
REVOKE INSERT ON app.device_reward_ledger FROM edge_actor;
REVOKE ALL ON app.review_item FROM edge_actor;
REVOKE EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text, jsonb) FROM edge_actor;
REVOKE EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text, jsonb) FROM edge_actor;
REVOKE EXECUTE ON FUNCTION app.reserve_offer_for_code(uuid, uuid, text) FROM edge_actor;
REVOKE EXECUTE ON FUNCTION app.release_offer_budget(uuid, numeric) FROM edge_actor;
REVOKE EXECUTE ON FUNCTION app.release_account_reservations(uuid) FROM edge_actor;

DROP POLICY edge_actor_offer_update ON app.offer;
DROP POLICY edge_actor_offer_code_update ON app.offer_code;
DROP POLICY edge_actor_entitlement_update ON app.entitlement;
DROP POLICY edge_actor_device_reward_ledger_insert ON app.device_reward_ledger;
DROP POLICY edge_actor_review_item_insert ON app.review_item;
DROP POLICY edge_actor_review_item_select ON app.review_item;

-- ============================================================================
-- 3. M3 + L5: own-row INSERT policies that also tie the REFERENCED rows to the actor
-- ============================================================================
-- (Modelled on edge_actor_device_reward_ledger_insert / edge_actor_play_evidence_insert in 0031.) Each is dropped and
-- recreated: a policy's WITH CHECK cannot be altered in place under the name the allowlist already carries.
DROP POLICY edge_actor_checkin_challenge_insert ON app.checkin_challenge;
CREATE POLICY edge_actor_checkin_challenge_insert ON app.checkin_challenge
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid()) AND staff_user_id IS NULL
              AND EXISTS (SELECT 1 FROM app.device d WHERE d.id = device_id AND d.user_id = (SELECT private.actor_uid())));

DROP POLICY edge_actor_checkin_token_insert ON app.checkin_token;
CREATE POLICY edge_actor_checkin_token_insert ON app.checkin_token
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid())
              AND EXISTS (SELECT 1 FROM app.device d WHERE d.id = device_id AND d.user_id = (SELECT private.actor_uid()))
              AND EXISTS (SELECT 1 FROM app.checkin_challenge c WHERE c.id = challenge_id AND c.user_id = (SELECT private.actor_uid())));

DROP POLICY edge_actor_evidence_insert ON app.evidence;
CREATE POLICY edge_actor_evidence_insert ON app.evidence
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid())
              AND (device_id IS NULL OR EXISTS (SELECT 1 FROM app.device d WHERE d.id = device_id AND d.user_id = (SELECT private.actor_uid()))));

DROP POLICY edge_actor_push_token_insert ON app.push_token;
CREATE POLICY edge_actor_push_token_insert ON app.push_token
  FOR INSERT TO edge_actor
  WITH CHECK (user_id = (SELECT private.actor_uid())
              AND EXISTS (SELECT 1 FROM app.device d WHERE d.id = device_id AND d.user_id = (SELECT private.actor_uid())));

DROP POLICY edge_actor_audit_log_insert ON app.audit_log;
CREATE POLICY edge_actor_audit_log_insert ON app.audit_log
  FOR INSERT TO edge_actor
  WITH CHECK (actor_user_id = (SELECT private.actor_uid()) AND action = 'play.repick' AND subject_table = 'play'
              AND EXISTS (SELECT 1 FROM app.play p WHERE p.id::text = subject_id AND p.user_id = (SELECT private.actor_uid())));

-- The tombstone row must be the actor's pseudonym (as before), under the key that PRODUCED it, on an install the
-- actor's own device is actually linked to (app.record_install_link sets the device's hash first, then inserts).
DROP POLICY edge_actor_install_link_account_insert ON app.install_link_account;
CREATE POLICY edge_actor_install_link_account_insert ON app.install_link_account
  FOR INSERT TO edge_actor
  WITH CHECK (CASE WHEN (SELECT private.actor_uid()) IS NULL THEN false ELSE
      EXISTS (SELECT 1 FROM app.device d WHERE d.user_id = (SELECT private.actor_uid()) AND d.install_link_hash = install_link_account.install_link_hash)
      AND EXISTS (SELECT 1 FROM private.account_pseudonyms((SELECT private.actor_uid())) a
                  WHERE a.pseudonym = install_link_account.account_pseudonym AND a.key_id = install_link_account.account_pseudonym_hmac_id)
    END);

-- ============================================================================
-- 4. M4 (part 2): what private_definer needs to run the P3f functions for ONE bound actor
-- ============================================================================
-- Every policy below applies to private_definer and is registered in private.definer_policy_allowlist (section 8)
-- and in supabase/tests/fixtures/definer_policy_exprs.txt. All are ACTOR-KEYED: a function running as private_definer
-- sees and writes only the rows of the actor bound in the CURRENT transaction (private.actor_uid()), so even a bug in
-- a definer cannot reach another account's reward, device or play. Two deliberate limits:
--   * app.offer: SELECT, and UPDATE of budget_reserved ONLY (column grant), on an offer the actor holds a code on.
--     0027's note "private_definer must not be given a grant on app.offer" was about the DELETE branch of
--     app.offer_code_reservation_sync, which asks has_table_privilege('app.offer', 'UPDATE'): that is a TABLE-level
--     question and stays false for a column grant, so account deletion still releases through
--     app.release_account_reservations (now called by private.delete_my_data_for_actor before the delete).
--   * review_item: INSERT of the four columns app.reserve_offer_for_code writes, only for the two budget kinds on
--     one of the actor's own codes; SELECT only the same rows (the once-per-code dedupe read).
GRANT SELECT ON app.offer TO private_definer;
GRANT UPDATE (budget_reserved) ON app.offer TO private_definer;
GRANT INSERT (kind, subject_table, subject_id, detail) ON app.review_item TO private_definer;
GRANT INSERT (device_id, devicecheck_token_hash, user_id, reward_kind, reward_id) ON app.device_reward_ledger TO private_definer;

CREATE POLICY pd_edge_act_offer_code_select ON app.offer_code
  FOR SELECT TO private_definer USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_offer_code_update ON app.offer_code
  FOR UPDATE TO private_definer USING (user_id = (SELECT private.actor_uid())) WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_entitlement_select ON app.entitlement
  FOR SELECT TO private_definer USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_entitlement_update ON app.entitlement
  FOR UPDATE TO private_definer USING (user_id = (SELECT private.actor_uid())) WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_device_select ON app.device
  FOR SELECT TO private_definer USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_play_select ON app.play
  FOR SELECT TO private_definer USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_fraud_signal_select ON app.fraud_signal
  FOR SELECT TO private_definer USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_ledger_select ON app.device_reward_ledger
  FOR SELECT TO private_definer USING (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_ledger_insert ON app.device_reward_ledger
  FOR INSERT TO private_definer WITH CHECK (user_id = (SELECT private.actor_uid()));
CREATE POLICY pd_edge_act_offer_select ON app.offer
  FOR SELECT TO private_definer
  USING (EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.offer_id = offer.id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY pd_edge_act_offer_update ON app.offer
  FOR UPDATE TO private_definer
  USING (EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.offer_id = offer.id AND oc.user_id = (SELECT private.actor_uid())))
  WITH CHECK (EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.offer_id = offer.id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY pd_edge_act_review_item_select ON app.review_item
  FOR SELECT TO private_definer
  USING (subject_table = 'offer_code' AND kind IN ('held_offer_budget_unreserved', 'issued_offer_budget_unreserved')
         AND EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.id = review_item.subject_id AND oc.user_id = (SELECT private.actor_uid())));
CREATE POLICY pd_edge_act_review_item_insert ON app.review_item
  FOR INSERT TO private_definer
  WITH CHECK (subject_table = 'offer_code' AND kind IN ('held_offer_budget_unreserved', 'issued_offer_budget_unreserved')
              AND EXISTS (SELECT 1 FROM app.offer_code oc WHERE oc.id = review_item.subject_id AND oc.user_id = (SELECT private.actor_uid())));

-- NIT: compare the device GUC as TEXT. `id = nullif(current_setting(..), '')::uuid` raised 22P02 for a non-uuid session
-- value on every read of app.device while the policy was evaluated; text-vs-text cannot. Same window, same form.
DROP POLICY pd_device_link_read ON app.device;
CREATE POLICY pd_device_link_read ON app.device
  FOR SELECT TO private_definer USING (
    id::text = nullif(current_setting('app.edge.link_device_id', true), '')
    OR install_link_hash = nullif(current_setting('app.edge.link_hash', true), '')
    OR attest_key_id = nullif(current_setting('app.edge.link_attest_key', true), '')
  );

-- ============================================================================
-- 5. M4 (part 3): the P3f functions run as private_definer; the cascade body moves, unchanged, into one function
-- ============================================================================
-- private_definer runs these invoker-rights functions on the bound actor's behalf, so it needs EXECUTE on them.
-- (service_role keeps its own grants.)
GRANT EXECUTE ON FUNCTION app.activate_offer_code(uuid, uuid, uuid, text, text, jsonb) TO private_definer;
GRANT EXECUTE ON FUNCTION app.activate_entitlement(uuid, uuid, uuid, text, text, jsonb) TO private_definer;
GRANT EXECUTE ON FUNCTION app.reserve_offer_for_code(uuid, uuid, text) TO private_definer;
GRANT EXECUTE ON FUNCTION app.release_offer_budget(uuid, numeric) TO private_definer;
GRANT EXECUTE ON FUNCTION app.release_account_reservations(uuid) TO private_definer;

-- app.hold_play_rewards: the BODY of app.play_held_review_cascade (0017, locks reordered by 0027 N5), unchanged,
-- taking the play id instead of NEW.id. Lock order is the same global one: the play's codes (id order), their offers
-- (id order), the play's entitlements (id order). Plain invoker-rights.
CREATE FUNCTION app.hold_play_rewards(p_play_id uuid) RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  PERFORM 1 FROM app.offer_code
    WHERE play_id = p_play_id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired')
    ORDER BY id FOR UPDATE;
  PERFORM 1 FROM app.offer
    WHERE id IN (
      SELECT offer_id FROM app.offer_code
      WHERE play_id = p_play_id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired')
    )
    ORDER BY id FOR UPDATE;
  PERFORM 1 FROM app.entitlement
    WHERE play_id = p_play_id AND state NOT IN ('held_review', 'redeemed', 'void')
    ORDER BY id FOR UPDATE;
  UPDATE app.offer_code SET state = 'held_review'
    WHERE play_id = p_play_id AND state NOT IN ('held_review', 'redeemed', 'void', 'expired');
  UPDATE app.entitlement SET state = 'held_review'
    WHERE play_id = p_play_id AND state NOT IN ('held_review', 'redeemed', 'void');
END;
$$;
REVOKE EXECUTE ON FUNCTION app.hold_play_rewards(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.hold_play_rewards(uuid) TO service_role, private_definer;

-- The trigger function: same trigger (play_held_review_cascade_trg, AFTER UPDATE OF held_review), same contract. A role
-- that can write the reward rows itself (service_role, the table owner) runs the body directly, exactly as before; a role
-- that cannot (edge_actor, which no longer holds UPDATE on offer_code) hands the play to the definer, which checks that
-- the play is the BOUND actor's and held, then runs the same body as private_definer. has_table_privilege is a TABLE-level
-- question about the invoking role, the idiom 0027's reservation trigger already uses.
CREATE OR REPLACE FUNCTION app.play_held_review_cascade() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.held_review AND NOT OLD.held_review THEN
    IF has_table_privilege('app.offer_code', 'UPDATE') THEN
      PERFORM app.hold_play_rewards(NEW.id);
    ELSE
      PERFORM private.hold_play_rewards_for_actor(NEW.id);
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- ============================================================================
-- 6. The definer functions
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

-- 6a. Activation for the BOUND user actor. No user argument: the uid is the binding's. A system delegate (a catalog-drain
-- binding) never activates rewards. Errors are the P3f ones (P0002 not yours / 42501 device not yours / 55000 state / 23514
-- backstop), raised by app.activate_* itself.
CREATE FUNCTION private.activate_offer_code_for_actor(
  p_code_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb DEFAULT NULL
) RETURNS app.offer_code_state
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'activate_offer_code_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'activate_offer_code_for_actor: a system delegate may not activate a reward' USING ERRCODE = '42501';
  END IF;
  RETURN app.activate_offer_code(p_code_id, v_uid, p_device_id, p_token_hash, p_decision, p_hold_detail);
END;
$$;

CREATE FUNCTION private.activate_entitlement_for_actor(
  p_entitlement_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb DEFAULT NULL
) RETURNS app.entitlement_state
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'activate_entitlement_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'activate_entitlement_for_actor: a system delegate may not activate a reward' USING ERRCODE = '42501';
  END IF;
  RETURN app.activate_entitlement(p_entitlement_id, v_uid, p_device_id, p_token_hash, p_decision, p_hold_detail);
END;
$$;

-- 6b. The held-review cascade for the bound actor's own held play (called by app.play_held_review_cascade, so also by the
-- rescore delegate, whose binding is kind = system_delegate: any binding kind may hold the bound owner's play rewards).
CREATE FUNCTION private.hold_play_rewards_for_actor(p_play_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.actor_uid();
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'hold_play_rewards_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM app.play p WHERE p.id = p_play_id AND p.user_id = v_uid AND p.held_review) THEN
    RAISE EXCEPTION 'hold_play_rewards_for_actor: that play is not a held play of the bound actor' USING ERRCODE = '42501';
  END IF;
  PERFORM app.hold_play_rewards(p_play_id);
END;
$$;

-- 6c. Account deletion for the bound user actor: hand back what the account's codes reserve FIRST (a bare DELETE of an
-- offer_code row only releases when its role holds table-level UPDATE on app.offer, which private_definer never does),
-- then the existing delete. Replaces 0030's version, which left the release to a separate edge_actor call.
CREATE OR REPLACE FUNCTION private.delete_my_data_for_actor()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_kind text;
BEGIN
  SELECT b.actor_uid, b.kind INTO v_uid, v_kind
  FROM private.actor_binding b
  WHERE b.backend_pid = pg_backend_pid() AND b.xact = pg_current_xact_id_if_assigned();
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'delete_my_data_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  IF v_kind <> 'user' THEN
    RAISE EXCEPTION 'delete_my_data_for_actor: a system delegate may not delete an account' USING ERRCODE = '42501';
  END IF;
  PERFORM app.release_account_reservations(v_uid);
  RETURN private.delete_my_data(v_uid);
END;
$$;

-- 6d. purge_fix_coords with a sane lower bound on retention (the importer uses 30 days; 0030 accepted 1).
CREATE OR REPLACE FUNCTION private.purge_fix_coords(p_retention_days int, p_limit int)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n int;
BEGIN
  IF p_retention_days IS NULL OR p_retention_days < 7 OR p_retention_days > 30 THEN
    RAISE EXCEPTION 'purge_fix_coords: retention must be between 7 and 30 days' USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
    RAISE EXCEPTION 'purge_fix_coords: limit must be between 1 and 10000' USING ERRCODE = '22023';
  END IF;
  -- Open the read window (policy pd_fix_coords_read) for this transaction; closed again below.
  PERFORM set_config('app.edge.purge_fix_coords', 'on', true);
  UPDATE app.evidence e SET integrity = e.integrity - 'fixCoords'
  WHERE e.id IN (
    SELECT d.id FROM app.evidence d
    WHERE d.integrity ? 'fixCoords'
      AND (
        d.created_at < now() - make_interval(days => p_retention_days)
        OR d.course_id IS NULL
        OR NOT EXISTS (
          SELECT 1 FROM app.catalog_id_ledger l
          WHERE l.id = d.course_id
            AND (l.status = 'stub'
                 OR l.split_from IS NOT NULL
                 OR EXISTS (SELECT 1 FROM app.catalog_id_ledger s WHERE s.split_from = l.id)
                 OR EXISTS (SELECT 1 FROM app.catalog_rescore_backlog b WHERE b.course_id = l.id AND b.done_at IS NULL))
        )
      )
    ORDER BY d.created_at
    LIMIT p_limit
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  PERFORM set_config('app.edge.purge_fix_coords', '', true);
  RETURN v_n;
END;
$$;

-- 6e. L1: private.delete_my_data, redefined from its current body (0022) with ONLY the four pg_catalog relations
-- qualified (pg_constraint, pg_class, pg_namespace, pg_attribute). Same signature, owner, search_path, grants and comment.
CREATE OR REPLACE FUNCTION private.delete_my_data(p_user_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
DECLARE
  v_handle text;
  v_email text;
  v_result jsonb := '{}'::jsonb;
  v_pol record;
  v_row_count int;
  v_key_id uuid;
  v_key_secret text;
  v_pseudonym_candidate text;
  v_post_pol record;
  v_remaining int;
BEGIN
  IF p_user_id IS NULL THEN
    RAISE EXCEPTION 'delete_my_data: user_id is required';
  END IF;

  -- S1 close-out (gate round 3): this function is owned by `private_definer`
  -- (0016_private_definer.sql), a NOLOGIN NOSUPERUSER NOBYPASSRLS role that
  -- is NOT the table owner — every table below stays ENABLE + FORCE ROW
  -- LEVEL SECURITY, and private_definer reaches rows only through the
  -- explicit, narrow policies 0016 defines, each scoped to this session-
  -- local GUC. Set it FIRST, before the very first table read below, since
  -- even `app.profile`'s own SELECT now goes through a policy keyed on it.
  PERFORM set_config('app.delete_my_data.target_user_id', p_user_id::text, true);

  SELECT handle INTO v_handle FROM app.profile WHERE user_id = p_user_id;
  SELECT email INTO v_email FROM auth.users WHERE id = p_user_id;
  -- Fully qualified: this function runs with search_path = '' (below),
  -- and pgcrypto is installed into `public` (confirmed this session via
  -- `pg_extension.extnamespace`), so an unqualified hmac()/digest() would
  -- 42883 ("function ... does not exist") here even though the extension
  -- is present.
  --
  -- ⛔ FIX (M1, post-P3a re-gate): the pseudonym key is NEVER read from a
  -- GUC any more (0015/0016's prior `current_setting('app.pseudonym_hmac')`
  -- design had four confirmed problems: readable by anon/authenticated,
  -- overridable by any caller's own `SET LOCAL`, silently accepted an
  -- empty value with no error, and production never sets an `app.*` GUC
  -- at all — see supabase/tests/shim.sql's own note on this, where the
  -- fix is explained in full). The key now comes from Supabase Vault
  -- (`vault.decrypted_secrets`, real in production, shimmed locally) —
  -- read INSIDE this SECURITY DEFINER function body, which no other role
  -- can do (private_definer's own narrow, column-level grant on that
  -- view, 0018_pseudonym_vault.sql — anon/authenticated get none).
  --
  -- Rotation: EVERY row named `pseudonym_hmac%` in the vault is an
  -- "active" key (0018's own deploy-check note explains the naming
  -- convention). A pseudonym was computed, at WRITE time, with WHATEVER
  -- key was active then — so finding it again means trying every
  -- currently-active key, not just the newest one, or a row written
  -- under an older key becomes permanently unfindable the moment a new
  -- key is added. The loop below (right before the one place this
  -- function actually MATCHES rows by pseudonym, attestation_shift_log)
  -- does exactly that: for each active key, validate it, compute this
  -- user's pseudonym under it, and run the shift-log UPDATE once per
  -- key — safe to repeat (idempotent: a row already updated on an
  -- earlier key's pass no longer matches ANY later key's WHERE clause,
  -- since its own player_pseudonym column never changes).
  -- The two derived GUCs the "special" policies (partner_invite,
  -- public_profile_projection) match on — set once either value is
  -- known; empty string (not NULL) when there is nothing to match, so
  -- `current_setting(..., true)` never returns NULL into a `column =
  -- NULL` comparison (which would be neither true nor false and so
  -- would never permit a row — the intended, fail-closed behaviour when
  -- e.g. the account has no email on file). `target_pseudonym` is set
  -- per-key, in the loop right above the attestation_shift_log UPDATE
  -- below — see that block for why.
  PERFORM set_config('app.delete_my_data.target_email', COALESCE(v_email, ''), true);
  PERFORM set_config('app.delete_my_data.target_handle', COALESCE(v_handle, ''), true);

  -- ==========================================================================
  -- Generic pass: every FK-to-auth.users column in `app`, driven by
  -- private.pii_retention_policy. Fails closed on anything unclassified.
  -- ==========================================================================
  FOR v_pol IN
    SELECT
      cl.relname AS table_name,
      a.attname AS column_name,
      pol.action,
      pol.reason
    FROM pg_catalog.pg_constraint con
    JOIN pg_catalog.pg_class cl ON cl.oid = con.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = cl.relnamespace
    JOIN pg_catalog.pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
    LEFT JOIN private.pii_retention_policy pol
      ON pol.schema_name = 'app' AND pol.table_name = cl.relname AND pol.column_name = a.attname
    WHERE con.contype = 'f'
      AND n.nspname = 'app'
      AND con.confrelid = 'auth.users'::regclass
  LOOP
    IF v_pol.action IS NULL THEN
      RAISE EXCEPTION
        'delete_my_data: app.%.% references auth.users but has no private.pii_retention_policy row — classify it (delete_row / set_null / special) before this function can run',
        v_pol.table_name, v_pol.column_name;
    ELSIF v_pol.action = 'delete_row' THEN
      EXECUTE format('DELETE FROM app.%I WHERE %I = $1', v_pol.table_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'set_null' THEN
      EXECUTE format('UPDATE app.%I SET %I = NULL WHERE %I = $1', v_pol.table_name, v_pol.column_name, v_pol.column_name) USING p_user_id;
    ELSIF v_pol.action = 'special' THEN
      CONTINUE; -- handled below, by name, not generically
    END IF;
  END LOOP;

  -- ==========================================================================
  -- Special cases (each cross-referenced to its private.pii_retention_policy
  -- row and reason).
  -- ==========================================================================

  -- entitlement: detach activated_device_id UNCONDITIONALLY, for every
  -- state (including `redeemed`, which is terminal and never voided) — the
  -- device row is about to be deleted by the generic pass above (device.
  -- user_id is a delete_row policy) and RESTRICT (the default) on
  -- entitlement.activated_device_id would otherwise block that delete.
  -- This is not a pii_retention_policy row because activated_device_id
  -- does not reference auth.users — it references app.device — so it is
  -- outside the auth.users-driven loop above by construction; called out
  -- here because it was exactly B3's "handle the RESTRICT FK on
  -- activated_device_id" finding.
  UPDATE app.entitlement SET activated_device_id = NULL, devicecheck_token_hash = NULL
    WHERE user_id = p_user_id;
  -- entitlement.play_id / offer_code.play_id (H1, post-P3a gate): also
  -- references app.play, which the generic pass below deletes (play.user_id
  -- = delete_row) — the FK itself is now ON DELETE SET NULL DEFERRABLE
  -- INITIALLY DEFERRED (0017), so this is belt-and-suspenders, not load-
  -- bearing, but detaching explicitly here matches activated_device_id's
  -- own pattern immediately above and keeps the intent visible at the
  -- call site rather than only in the FK definition.
  UPDATE app.entitlement SET play_id = NULL WHERE user_id = p_user_id;
  UPDATE app.offer_code SET play_id = NULL WHERE user_id = p_user_id;
  -- Then, per line 2759 / O9-O10: void any UNREDEEMED entitlement or stock
  -- voucher (redeemed stays redeemed — terminal, kept for the stock ledger).
  UPDATE app.entitlement
  SET state = 'void'
  WHERE user_id = p_user_id
    AND kind = 'special_marker'
    AND state IN ('earned', 'held_review', 'redeemable', 'vouchered');
  -- offer_code.activated_device_id has the same RESTRICT shape; offer_code
  -- rows for this user are deleted by the generic pass (offer_code.user_id
  -- = delete_row), so no separate detach is needed there — but another
  -- user's already-activated offer_code could in principle point at a
  -- device this user owns only if devices were ever shared, which they are
  -- not (app.device.user_id is 1:1 with the owning account) — no action
  -- needed.

  -- attestation.player_user_id (special): nulled, not deleted (line 841).
  UPDATE app.attestation SET player_user_id = NULL WHERE player_user_id = p_user_id;
  -- attestation.staff_user_id is handled by the generic pass above (it is
  -- now a plain `set_null` policy row, gate round 2 fix) — no bespoke code
  -- needed here; staff_pseudonym (populated at attest time, out of this
  -- stage's scope) survives so the row stays verifiable as "staff-attested".

  -- audit_log.actor_user_id (special): redacted via the trigger's one
  -- narrow exception (0006) — covers every historical row matching, "older
  -- audit_log rows" included, since the WHERE has no date bound.
  UPDATE app.audit_log SET actor_user_id = NULL WHERE actor_user_id = p_user_id;

  -- receipt_fingerprint.user_id (special): nulled, row kept (24-month
  -- fraud retention, line 835).
  UPDATE app.receipt_fingerprint SET user_id = NULL WHERE user_id = p_user_id;

  -- fraud_signal.user_id (special): nulled, row kept — an admin fraud
  -- record survives its subject's account deletion.
  UPDATE app.fraud_signal SET user_id = NULL WHERE user_id = p_user_id;

  -- partner_invite (special): deleted on EITHER match — the inviter
  -- deleting their account (invited_by), or the invite naming the deleted
  -- user's own verified email (invitee_email) — task instruction: "Cover
  -- ... partner_invite.invitee_email".
  DELETE FROM app.partner_invite
  WHERE invited_by = p_user_id
     OR (v_email IS NOT NULL AND invitee_email = v_email);

  -- attestation_shift_log: match by the durable player_pseudonym (HMAC of
  -- user_id), NOT by the current handle (B3 fix — a handle can change or
  -- be reused after being freed; the projection never stores a user id at
  -- all, line 842). A row logged before this stage's pseudonym column
  -- existed falls back to matching the pre-deletion handle.
  --
  -- ⛔ FIX (should-fix, post-P3a re-gate: "key rotation ... match on each
  -- row's recorded hmac id and raise if that key is missing"): the PRIOR
  -- version tried every vault row whose NAME matched 'pseudonym_hmac%' —
  -- renaming a retired key out of that naming convention (e.g.
  -- 'pseudonym_hmac_v1' -> 'retired_v1') silently dropped it from this
  -- loop even though rows still carry its id in their OWN
  -- player_pseudonym_hmac_id column, "succeeding" while leaving that
  -- key's rows unredacted. This version drives the loop from the DATA
  -- instead of the vault's naming convention: every id ever recorded
  -- against a player_pseudonym/staff_pseudonym pair is resolved BY ID
  -- (name-independent, so a rename never matters), and a recorded id that
  -- no longer resolves in vault.decrypted_secrets at all (deleted, not
  -- merely renamed — should-fix "FK into vault.secrets", 0018, dropped
  -- the FK specifically so this can be validated here instead of relying
  -- on referential integrity to prevent it) RAISES rather than silently
  -- skipping that key's rows.
  --
  -- ⛔ FIX (should-fix 2, post-P3a re-gate): "replace the broad
  -- pd_shift_log_discover_hmac_id policy (USING(true)) with a small
  -- registry of key ids ever used ... deletion iterates the registry."
  -- The SOURCE of this loop's key ids is now private.
  -- pseudonym_key_registry (0018), populated at WRITE time by the
  -- app.attestation/app.attestation_shift_log validation triggers (also
  -- 0018) — NOT a live, row-unscoped SELECT over the wide
  -- attestation_shift_log table any more, which is what let the broad
  -- discovery policy this replaces be narrowed away entirely.
  FOR v_key_id IN
    SELECT key_id FROM private.pseudonym_key_registry
  LOOP
    SELECT decrypted_secret INTO v_key_secret FROM vault.decrypted_secrets WHERE id = v_key_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'delete_my_data: attestation_shift_log references pseudonym key id % that no longer resolves in vault.decrypted_secrets (deleted or otherwise gone) — cannot safely determine whether it matches this user', v_key_id;
    END IF;
    IF v_key_secret IS NULL OR length(v_key_secret) < 32 THEN
      RAISE EXCEPTION 'delete_my_data: pseudonym key % in vault.decrypted_secrets is NULL or shorter than 32 bytes', v_key_id;
    END IF;
    v_pseudonym_candidate := encode(public.hmac(p_user_id::text, v_key_secret, 'sha256'), 'hex');
    -- `app.delete_my_data.target_pseudonym` is re-set per key so
    -- 0016_private_definer.sql's RLS policy (which independently checks
    -- the same GUC, since private_definer reaches this table only
    -- through that policy) agrees with this statement's own WHERE clause
    -- on each pass.
    PERFORM set_config('app.delete_my_data.target_pseudonym', v_pseudonym_candidate, true);
    UPDATE app.attestation_shift_log
    SET player_handle_snapshot = 'deleted player'
    WHERE player_pseudonym_hmac_id = v_key_id AND player_pseudonym = v_pseudonym_candidate;
  END LOOP;
  -- Legacy fallback: a row logged before player_pseudonym/
  -- player_pseudonym_hmac_id existed at all has neither set — matched by
  -- the pre-deletion handle instead, same as always (0016's own RLS
  -- policy already has a SEPARATE branch for exactly this shape, keyed
  -- on target_handle, not target_pseudonym).
  UPDATE app.attestation_shift_log
  SET player_handle_snapshot = 'deleted player'
  WHERE player_pseudonym IS NULL AND player_pseudonym_hmac_id IS NULL
    AND v_handle IS NOT NULL AND player_handle_snapshot = v_handle;

  -- receipt objects in storage.objects (task instruction: "receipt objects
  -- in storage.objects"). Matched by `owner` (set at upload time by the
  -- out-of-scope receipts Edge Function) and, defensively, by the
  -- `receipts/<user_id>/...` path convention (line 868) in case `owner`
  -- was never populated for an older object.
  DELETE FROM storage.objects
  WHERE bucket_id = 'receipts'
    AND (owner = p_user_id OR name LIKE 'receipts/' || p_user_id::text || '/%');

  -- public_profile_projection + profile: profile is deleted by the
  -- generic pass (delete_row); its projection has no FK (holds no user
  -- id, line 825) so it is removed here by the handle captured above,
  -- before profile's row (and therefore v_handle's source) is gone.
  IF v_handle IS NOT NULL THEN
    DELETE FROM app.public_profile_projection WHERE handle = v_handle;
  END IF;

  -- ==========================================================================
  -- P3d gate round 2, should-fix 3: "Rate-limit keys. During deletion,
  -- remove the user's own rate_limit_bucket keys, i.e. those prefixed with
  -- their uid, inside delete_my_data or me-delete. It's fine to keep the
  -- in-flight me-delete bucket so retries stay limited, if you document
  -- it. Or wire the purge. Say which you chose."
  --
  -- CHOSEN: inside delete_my_data (here), not me-delete's own handler —
  -- this is the same transaction as the deletion itself, so it is
  -- automatically atomic with (and rolls back together with) everything
  -- else in this function, and it fires for EVERY caller of this
  -- function, not only the me-delete Edge Function specifically.
  --
  -- Scope: every bucket_key `hitRateLimitForActor` (privileged.ts) ever
  -- writes for THIS user is prefixed `<uid>:...` (that function's own
  -- `scopedBucketKey = \`${actor.uid}:${bucketKey}\``) — so a LIKE-prefix
  -- match on `p_user_id::text || ':%'` covers every bucket this user has
  -- ever hit, across every endpoint, with no separate registry needed.
  --
  -- EXCLUDED, deliberately: the in-flight `me-delete:user` bucket itself
  -- (me-delete/index.ts's own `hitRateLimitForActor(actor, "me-delete:
  -- user", ...)`, scoped key `<uid>:me-delete:user`) — kept so a RETRY of
  -- THIS SAME deletion call (delete-handler.ts's own doc: the one
  -- legitimate reason to call this endpoint again in a short window,
  -- e.g. after a partial failure) stays rate-limited exactly the way a
  -- first attempt already is, rather than becoming unbounded the moment
  -- one successful run has purged its own counter. Every OTHER bucket —
  -- evidence submission, redemption, check-in, etc. — is purged: those
  -- limits exist to bound abuse by a live account, and this account no
  -- longer has personal data to abuse anything with.
  --
  -- No new RLS policy needed: private_definer already holds an unscoped
  -- DELETE policy on this table (`pd_rate_limit_purge`, 0016), the SAME
  -- one `private.purge_rate_limit_buckets`'s own nightly sweep already
  -- uses — its own `_r` companion (`pd_rate_limit_purge_r`) already
  -- exists too.
  DELETE FROM private.rate_limit_bucket
  WHERE bucket_key LIKE p_user_id::text || ':%'
    AND bucket_key <> p_user_id::text || ':me-delete:user';

  -- ==========================================================================
  -- P3d should-fix 2: fail-closed POST-CONDITION. Re-reads every table this
  -- function's own registry (private.pii_retention_policy) names, through
  -- private_definer's own SELECT visibility, and RAISES if ANY subject row
  -- still remains. See this file's own header for why `entitlement.user_id`
  -- is the one deliberate exclusion (redeemed/terminal rows are
  -- intentionally retained, O9/O10).
  --
  -- ⛔ CORRECTED COMMENT (P3d gate round 3, S4 — the PRIOR wording here
  -- overclaimed what this post-condition is trustworthy against). The
  -- prior comment said the "_r companion" check (tools/db/verify-
  -- function-inventory.mjs check 8 / 10_function_inventory.sql check 11)
  -- guarantees this post-condition can see every row it re-counts. That
  -- was TRUE only up to the granularity that check actually verified,
  -- which round 2's version did NOT match: it was TABLE-level ("does
  -- SOME SELECT policy exist for private_definer on this table at all"),
  -- while this post-condition re-counts PER COLUMN, under RLS, using the
  -- SAME session GUC every DELETE/UPDATE policy is scoped to. A table
  -- with TWO classified columns — one with a real, correctly-scoped
  -- SELECT companion, one with none — passed the OLD table-level check
  -- (the table has *a* SELECT policy), while this post-condition's
  -- re-count for the SECOND column would ALSO see zero rows for the
  -- SAME reason RLS hid the evidence from the ORIGINAL delete/update —
  -- reporting success while a row for that column genuinely survives,
  -- table-level check notwithstanding. The check below THIS comment was
  -- fixed for this round: check 8/11/12 are now COLUMN-level (every
  -- `pii_retention_policy` (table, column) pair requires its OWN SELECT
  -- policy whose USING clause matches the exact `nullif(current_setting
  -- (...))` form on THAT column, not merely "some policy on this
  -- table") — proven against a planted must-fail fixture
  -- (`app.zz_two`, two columns, a SELECT companion on only one) this
  -- round. THAT is what makes the post-condition below trustworthy now.
  -- ==========================================================================
  FOR v_post_pol IN
    SELECT table_name, column_name
    FROM private.pii_retention_policy
    WHERE schema_name = 'app'
      AND NOT (table_name = 'entitlement' AND column_name = 'user_id')
  LOOP
    EXECUTE format('SELECT count(*) FROM app.%I WHERE %I = $1', v_post_pol.table_name, v_post_pol.column_name)
      INTO v_remaining USING p_user_id;
    IF v_remaining > 0 THEN
      RAISE EXCEPTION
        'delete_my_data: post-condition failed — % row(s) still remain in app.%.% for user % after deletion (fail-closed; a missing/misscoped RLS policy can let a DELETE/UPDATE silently affect 0 rows while reporting success — see private.pii_retention_policy and the column-level "_r companion" check in tools/db/verify-function-inventory.mjs)',
        v_remaining, v_post_pol.table_name, v_post_pol.column_name, p_user_id;
    END IF;
  END LOOP;

  v_result := jsonb_build_object('user_id', p_user_id, 'deleted_at', now());
  -- Logged via a plain INSERT — this is a NEW audit row about the
  -- deletion event itself, not a mutation of an old one, so the
  -- insert-only trigger does not apply to it.
  INSERT INTO app.audit_log (actor_user_id, action, subject_table, subject_id, detail)
  VALUES (NULL, 'delete_my_data', 'app.profile', p_user_id::text, v_result);

  RETURN v_result;
END;
$function$;

REVOKE EXECUTE ON FUNCTION private.activate_offer_code_for_actor(uuid, uuid, text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.activate_entitlement_for_actor(uuid, uuid, text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION private.hold_play_rewards_for_actor(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.activate_offer_code_for_actor(uuid, uuid, text, text, jsonb) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.activate_entitlement_for_actor(uuid, uuid, text, text, jsonb) TO edge_actor;
GRANT EXECUTE ON FUNCTION private.hold_play_rewards_for_actor(uuid) TO edge_actor;

COMMENT ON FUNCTION private.activate_offer_code_for_actor(uuid, uuid, text, text, jsonb) IS
  'edge_actor only (0032). app.activate_offer_code for the BOUND user actor: the uid is the binding''s, never an argument, so an actor can only activate its own code. The P3f function runs as private_definer under actor-keyed policies; edge_actor itself has no write on offer_code / offer / device_reward_ledger / review_item.';
COMMENT ON FUNCTION private.activate_entitlement_for_actor(uuid, uuid, text, text, jsonb) IS
  'edge_actor only (0032). app.activate_entitlement for the BOUND user actor (see activate_offer_code_for_actor).';
COMMENT ON FUNCTION private.hold_play_rewards_for_actor(uuid) IS
  'edge_actor only (0032), called by the app.play_held_review_cascade trigger function when the invoking role cannot write the reward rows itself. Holds the rewards of one HELD play of the bound actor (any binding kind).';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 7. Registry: private.edge_policy_allowlist (edge_actor / edge_system policies)
-- ============================================================================
-- FORCE RLS with no policy for the migrating role (the owner keeps its table privileges): the temporary, self-dropped
-- CURRENT_USER policy 0030/0031 use.
CREATE POLICY current_user_edit_edge_policy_allowlist_0032 ON private.edge_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
DELETE FROM private.edge_policy_allowlist
WHERE (schema_name, table_name, policy_name) IN (
  ('app', 'offer', 'edge_actor_offer_update'),
  ('app', 'offer_code', 'edge_actor_offer_code_update'),
  ('app', 'entitlement', 'edge_actor_entitlement_update'),
  ('app', 'device_reward_ledger', 'edge_actor_device_reward_ledger_insert'),
  ('app', 'review_item', 'edge_actor_review_item_insert'),
  ('app', 'review_item', 'edge_actor_review_item_select'));
UPDATE private.edge_policy_allowlist SET note = v.note
FROM (VALUES
  ('checkin_challenge', 'edge_actor_checkin_challenge_insert', 'a player-issued challenge for the actor, on the actor''s own device; a staff-issued one is not an edge_actor path (0032 M3)'),
  ('checkin_token', 'edge_actor_checkin_token_insert', 'token issuance for the actor, on the actor''s own device and the actor''s own challenge (0032 M3); the consumed_at_once trigger keeps consumption one-way (0032 M2)'),
  ('evidence', 'edge_actor_evidence_insert', 'intake inserts the actor''s own evidence; a device id, when given, must be the actor''s own (0032 M3)'),
  ('push_token', 'edge_actor_push_token_insert', 'registration on the actor''s own device (0032 M3)'),
  ('audit_log', 'edge_actor_audit_log_insert', 'the re-pick audit row, for one of the actor''s own plays (0032 L5)'),
  ('install_link_account', 'edge_actor_install_link_account_insert', 'app.record_install_link writes the tombstone row for the actor''s own pseudonym, under the key that produced it, on an install the actor''s own device is linked to (0032 L5)')
) AS v(table_name, policy_name, note)
WHERE edge_policy_allowlist.schema_name = 'app' AND edge_policy_allowlist.table_name = v.table_name AND edge_policy_allowlist.policy_name = v.policy_name;
UPDATE private.edge_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN ('edge_actor_checkin_challenge_insert', 'edge_actor_checkin_token_insert', 'edge_actor_evidence_insert',
                         'edge_actor_push_token_insert', 'edge_actor_audit_log_insert', 'edge_actor_install_link_account_insert');
DROP POLICY current_user_edit_edge_policy_allowlist_0032 ON private.edge_policy_allowlist;

-- ============================================================================
-- 8. Registry: private.definer_policy_allowlist (policies that apply to private_definer)
-- ============================================================================
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0032 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'offer_code', 'pd_edge_act_offer_code_select', 'SELECT', true, 'activate_*_for_actor / hold_play_rewards_for_actor / delete_my_data_for_actor: the BOUND actor''s own codes only (private.actor_uid())'),
  ('app', 'offer_code', 'pd_edge_act_offer_code_update', 'UPDATE', true, 'the same functions write the bound actor''s own codes only (state, reserved_amount, activation columns); edge_actor itself holds no UPDATE'),
  ('app', 'entitlement', 'pd_edge_act_entitlement_select', 'SELECT', true, 'the bound actor''s own entitlements only (private.actor_uid())'),
  ('app', 'entitlement', 'pd_edge_act_entitlement_update', 'UPDATE', true, 'the bound actor''s own entitlements only; edge_actor itself holds no UPDATE'),
  ('app', 'device', 'pd_edge_act_device_select', 'SELECT', true, 'app.activate_*: "is this device the actor''s" -- the bound actor''s own devices only'),
  ('app', 'play', 'pd_edge_act_play_select', 'SELECT', true, 'app.activate_* / hold_play_rewards_for_actor: the bound actor''s own plays only'),
  ('app', 'fraud_signal', 'pd_edge_act_fraud_signal_select', 'SELECT', true, 'app.activate_*: the open attestation_failed check -- the bound actor''s own signals only'),
  ('app', 'device_reward_ledger', 'pd_edge_act_ledger_select', 'SELECT', true, 'app.activate_* ledger INSERT ... ON CONFLICT DO NOTHING: the bound actor''s own rows only'),
  ('app', 'device_reward_ledger', 'pd_edge_act_ledger_insert', 'INSERT', true, 'app.activate_*: the ledger row of the bound actor''s own reward only (INSERT column grant; edge_actor itself holds no INSERT)'),
  ('app', 'offer', 'pd_edge_act_offer_select', 'SELECT', true, 'reserve_offer_for_code / release_offer_budget / the cascade lock: an offer the bound actor holds a code on'),
  ('app', 'offer', 'pd_edge_act_offer_update', 'UPDATE', true, 'budget_reserved only (column grant), only on an offer the bound actor holds a code on, only from the P3f functions the definers call; edge_actor itself holds no UPDATE (closes R1)'),
  ('app', 'review_item', 'pd_edge_act_review_item_select', 'SELECT', true, 'reserve_offer_for_code''s once-per-code dedupe read: the two budget kinds, on one of the bound actor''s own codes'),
  ('app', 'review_item', 'pd_edge_act_review_item_insert', 'INSERT', true, 'reserve_offer_for_code: the ''budget could not be reserved'' item, the two budget kinds, for one of the bound actor''s own codes');
UPDATE private.definer_policy_allowlist SET
  note = 'device_link_signals_for_actor: GUC-scoped (app.edge.link_*) to exactly the device and its linked rows, cleared right after -- the 0017 guard-read pattern; the device GUC is compared as TEXT so a non-uuid session value cannot raise 22P02 (0032)'
WHERE schema_name = 'app' AND table_name = 'device' AND policy_name = 'pd_device_link_read';
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN (
    'pd_device_link_read',
    'pd_edge_act_offer_code_select', 'pd_edge_act_offer_code_update', 'pd_edge_act_entitlement_select', 'pd_edge_act_entitlement_update',
    'pd_edge_act_device_select', 'pd_edge_act_play_select', 'pd_edge_act_fraud_signal_select', 'pd_edge_act_ledger_select',
    'pd_edge_act_ledger_insert', 'pd_edge_act_offer_select', 'pd_edge_act_offer_update', 'pd_edge_act_review_item_select',
    'pd_edge_act_review_item_insert');
DROP POLICY current_user_seed_definer_policy_allowlist_0032 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- ============================================================================
-- 9. Registry: private.function_inventory
-- ============================================================================
GRANT UPDATE ON private.function_inventory TO CURRENT_USER;
CREATE POLICY current_user_edit_function_inventory_0032 ON private.function_inventory
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
-- The five app.* functions edge_actor can no longer call.
UPDATE private.function_inventory SET expected_edge_actor = false
WHERE (schema_name, function_name, identity_args) IN (
  ('app', 'activate_offer_code', 'p_code_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb'),
  ('app', 'activate_entitlement', 'p_entitlement_id uuid, p_user_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb'),
  ('app', 'reserve_offer_for_code', 'p_offer_id uuid, p_code_id uuid, p_review_kind text'),
  ('app', 'release_offer_budget', 'p_offer_id uuid, p_amount numeric'),
  ('app', 'release_account_reservations', 'p_user_id uuid'));
INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('app', 'checkin_token_consumed_at_once', '', false, false, false, false, false, '0032: trigger function (app.checkin_token_consumed_at_once_trg) -- consumed_at is set-once; never EXECUTEd directly by any role'),
  ('app', 'device_attest_counter_monotonic', '', false, false, false, false, false, '0032: trigger function (app.device_attest_counter_monotonic_trg) -- attest_counter never decreases; never EXECUTEd directly by any role'),
  ('app', 'hold_play_rewards', 'p_play_id uuid', false, false, true, false, false, '0032: the held-review cascade body (extracted unchanged from app.play_held_review_cascade); service_role and private_definer only, reached by edge_actor through private.hold_play_rewards_for_actor'),
  ('private', 'activate_offer_code_for_actor', 'p_code_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb', false, false, false, true, false, '0032: edge_actor only; app.activate_offer_code for the BOUND user actor (no user argument); closes R1/R2 for activation'),
  ('private', 'activate_entitlement_for_actor', 'p_entitlement_id uuid, p_device_id uuid, p_token_hash text, p_decision text, p_hold_detail jsonb', false, false, false, true, false, '0032: edge_actor only; app.activate_entitlement for the BOUND user actor (no user argument)'),
  ('private', 'hold_play_rewards_for_actor', 'p_play_id uuid', false, false, false, true, false, '0032: edge_actor only; the held-review cascade for a HELD play of the bound actor, called by the cascade trigger function');
DROP POLICY current_user_edit_function_inventory_0032 ON private.function_inventory;
REVOKE UPDATE ON private.function_inventory FROM CURRENT_USER;

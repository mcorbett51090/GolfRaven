-- 0033_edge_role_pr2.sql
-- PR2 of the NOBYPASSRLS edge-role work (follow-up 6): what routing the TypeScript through edge_actor
-- (`EDGE_DB_MODE=edge`, supabase/functions/_shared/privileged.ts) needed from the database, plus the PR1b
-- gate's LOW-1. 0030-0032 are merged and untouched; nothing here touches anon, authenticated or service_role,
-- and every table keeps ENABLE + FORCE ROW LEVEL SECURITY.
--
--   1. private.lock_own_reward_for_actor(reward_id). `Repo#rewards.lockOwnReward` used to `SELECT ... FOR UPDATE`
--      the bound user's offer_code / entitlement row so that two concurrent activations of one reward are
--      SERIALISED (the second one then reads the first one's committed state and answers idempotently). edge_actor
--      holds no UPDATE on those tables since 0032 (M4), and `FOR UPDATE` needs one. PR2's first attempt simply
--      dropped the lock on the argument that the activation definers lock the row themselves; the integration
--      suite refuted it: the handler DECIDES (held vs issue) from state it read BEFORE that lock, so under a race
--      the second request, which read `earned`, saw the first one's ledger row, decided "repeat user -> hold" and
--      turned an already ISSUED code into held_review (the suite's "two simultaneous activations ... issue it
--      once" test: ["issued", "held_review"]). A row lock taken by a definer is held until the TRANSACTION ends, so
--      a definer that does the same `FOR UPDATE` (as private_definer, under 0032's actor-keyed policies) gives the
--      Repo exactly the lock it had. It returns nothing, takes no id but the reward's, and only ever locks a row
--      of the BOUND actor (any binding kind: the lock reads nothing out). Lock order is unchanged (the code row is
--      locked first, as in app.activate_offer_code).
--
--   2. LOW-1 (PR1b gate): app.play_held_review_cascade picked its lane with
--      has_table_privilege('app.offer_code', 'UPDATE'), a TABLE-level question. A role that holds the table
--      privilege but is RLS-limited in what it can SEE (private_definer) would take the direct lane and hold 0 rows
--      silently. The dispatch is now explicit: the one role that must NOT write the reward rows itself, edge_actor,
--      takes the definer lane; every other role keeps the direct lane exactly as before. And the definer lane now has a
--      POST-CONDITION: after the hold, no code or entitlement of the play may still be in a non-held, non-terminal
--      state (it raises 55000 otherwise), so a hold that silently affected nothing can no longer pass.
--
--   3. Install-link tombstone retention (owner decision 2026-10-02, F19): app.install_link_account rows older than
--      24 MONTHS by first_seen_at are purged, mirroring app.receipt_fingerprint's 24-month fraud-tombstone retention.
--      private.purge_install_link_tombstones(max_rows): SECURITY DEFINER, owned by private_definer, set-based and bounded
--      per call, EXECUTE for service_role and edge_system only. The 24 months live in ONE place per object that needs
--      them (the function body constant `v_retention`, and the two private_definer policies that confine what the function
--      can even see or delete to rows past that cutoff); a test proves a 25-month-old row is purged and a 23-month-old one
--      kept. The import/drain pass calls it where it already calls the fix-coordinate purge. SCHEDULING the purges
--      independently of an import is a still-open, launch-blocking follow-up (see the money-path doc). Before launch the
--      tombstone still needs privacy-officer / PIA sign-off and a privacy-policy disclosure.
--
-- Same bracket as 0030/0032: functions owned by private_definer are created INSIDE
-- GRANT CREATE ON SCHEMA private TO private_definer; SET ROLE private_definer; ...; RESET ROLE; REVOKE CREATE.
-- `migration_owner` is never named.

-- ============================================================================
-- 1. LOW-1: explicit lane dispatch in the cascade trigger function
-- ============================================================================
CREATE OR REPLACE FUNCTION app.play_held_review_cascade() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.held_review AND NOT OLD.held_review THEN
    IF current_user = 'edge_actor' THEN
      -- edge_actor holds no write on the reward rows: the definer checks that the play is a HELD play of the bound
      -- actor, runs the same body as private_definer under the actor-keyed policies, and verifies the result.
      PERFORM private.hold_play_rewards_for_actor(NEW.id);
    ELSE
      PERFORM app.hold_play_rewards(NEW.id);
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

-- ============================================================================
-- 2. What private_definer needs for the tombstone purge (registered in section 4)
-- ============================================================================
-- DELETE on the tombstone, and SELECT of first_seen_at (the purge's own predicate; 0030 granted only the three columns the
-- device-link read needs). Both policies are ROW-NARROW: they admit only rows past the 24-month cutoff, so the purge can
-- neither read nor delete a live tombstone whatever its body says. (A DELETE with a WHERE clause also needs SELECT
-- visibility of the rows it examines, hence the pair.)
GRANT DELETE ON app.install_link_account TO private_definer;
GRANT SELECT (first_seen_at) ON app.install_link_account TO private_definer;
CREATE POLICY pd_purge_install_link_read ON app.install_link_account
  FOR SELECT TO private_definer USING (first_seen_at < now() - interval '24 months');
CREATE POLICY pd_purge_install_link_delete ON app.install_link_account
  FOR DELETE TO private_definer USING (first_seen_at < now() - interval '24 months');

-- ============================================================================
-- 3. The definers
-- ============================================================================
GRANT CREATE ON SCHEMA private TO private_definer;
SET ROLE private_definer;

CREATE OR REPLACE FUNCTION private.hold_play_rewards_for_actor(p_play_id uuid)
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
  -- The post-condition (0033, LOW-1): the same two states app.hold_play_rewards leaves alone are the only ones that may
  -- remain. (The rows are the bound actor's own: the composite FKs force play.user_id = code.user_id, and the
  -- actor-keyed policies show private_definer exactly those.)
  IF EXISTS (
       SELECT 1 FROM app.offer_code c
       WHERE c.play_id = p_play_id AND c.state NOT IN ('held_review', 'redeemed', 'void', 'expired')
     ) OR EXISTS (
       SELECT 1 FROM app.entitlement e
       WHERE e.play_id = p_play_id AND e.state NOT IN ('held_review', 'redeemed', 'void')
     ) THEN
    RAISE EXCEPTION 'hold_play_rewards_for_actor: a reward of the held play was not moved to held_review' USING ERRCODE = '55000';
  END IF;
END;
$$;

-- 3a. The retention purge. A pseudonymous tombstone (no user id) that deliberately survives account deletion is kept for
-- the fraud window it exists for and no longer: 24 months from first_seen_at.
CREATE FUNCTION private.purge_install_link_tombstones(p_max_rows integer)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  -- THE retention (owner decision 2026-10-02). The private_definer policies pd_purge_install_link_read / _delete (0033,
  -- section 4) repeat the same interval so that, even if this body were wrong, the function could not see or delete a
  -- younger row; matrix 16 proves both sides (25 months purged, 23 months kept).
  v_retention constant interval := interval '24 months';
  v_n integer;
BEGIN
  IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 100000 THEN
    RAISE EXCEPTION 'purge_install_link_tombstones: p_max_rows must be between 1 and 100000' USING ERRCODE = '22023';
  END IF;
  DELETE FROM app.install_link_account t
  WHERE (t.install_link_hash, t.account_pseudonym) IN (
    SELECT o.install_link_hash, o.account_pseudonym
    FROM app.install_link_account o
    WHERE o.first_seen_at < now() - v_retention
    ORDER BY o.first_seen_at, o.install_link_hash, o.account_pseudonym
    LIMIT p_max_rows
  );
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.purge_install_link_tombstones(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.purge_install_link_tombstones(integer) TO service_role, edge_system;

COMMENT ON FUNCTION private.purge_install_link_tombstones(integer) IS
  'service_role and edge_system only (0033). Deletes app.install_link_account rows whose first_seen_at is more than 24 months old (owner decision 2026-10-02, mirroring receipt_fingerprint), at most p_max_rows (1..100000) per call, oldest first; returns the count. Run by the import/drain pass next to the fix-coordinate purge.';

CREATE FUNCTION private.lock_own_reward_for_actor(p_reward_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := private.actor_uid();
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'lock_own_reward_for_actor: no actor is bound in this transaction' USING ERRCODE = '42501';
  END IF;
  -- Ownership is part of the predicate (and of the actor-keyed policies): another user's id and a nonexistent id
  -- lock nothing, identically. A reward id is a code id OR an entitlement id; each statement locks at most one row.
  PERFORM 1 FROM app.offer_code WHERE id = p_reward_id AND user_id = v_uid FOR UPDATE;
  PERFORM 1 FROM app.entitlement WHERE id = p_reward_id AND user_id = v_uid FOR UPDATE;
END;
$$;

REVOKE EXECUTE ON FUNCTION private.lock_own_reward_for_actor(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.lock_own_reward_for_actor(uuid) TO edge_actor;

COMMENT ON FUNCTION private.lock_own_reward_for_actor(uuid) IS
  'edge_actor only (0033). The row lock Repo#rewards.lockOwnReward used to take with SELECT ... FOR UPDATE, which edge_actor cannot (no UPDATE since 0032): locks the BOUND actor''s offer_code / entitlement row with that id until the transaction ends, so concurrent activations of one reward are serialised. Locks nothing for another user''s id.';

RESET ROLE;
REVOKE CREATE ON SCHEMA private FROM private_definer;

-- ============================================================================
-- 4. Registries
-- ============================================================================
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0033 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'install_link_account', 'pd_purge_install_link_read', 'SELECT', true, 'purge_install_link_tombstones: ROW-NARROW, only tombstones older than 24 months (first_seen_at); the DELETE re-checks visibility through it'),
  ('app', 'install_link_account', 'pd_purge_install_link_delete', 'DELETE', true, 'purge_install_link_tombstones: ROW-NARROW, only tombstones older than 24 months (first_seen_at; owner decision 2026-10-02, mirroring receipt_fingerprint)');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.policy_name IN ('pd_purge_install_link_read', 'pd_purge_install_link_delete');
DROP POLICY current_user_seed_definer_policy_allowlist_0033 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('private', 'purge_install_link_tombstones', 'p_max_rows integer', false, false, true, false, true, '0033: retention purge of app.install_link_account (first_seen_at older than 24 months; owner decision 2026-10-02); service_role and edge_system only, run by the import/drain pass next to purge_fix_coords'),
  ('private', 'lock_own_reward_for_actor', 'p_reward_id uuid', false, false, false, true, false, '0033: edge_actor only; the FOR UPDATE row lock of the bound actor''s own offer_code / entitlement row (edge_actor holds no UPDATE), serialising concurrent activations');

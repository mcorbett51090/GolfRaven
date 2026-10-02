-- 0036_attest_hardening.sql
--
-- App Attest follow-up hardening (security-gate NIT-2 on 0034). One function body is redefined; nothing else changes.
--
-- WHAT 0034 CLAIMED, AND WHAT IT DID NOT DO. 0034's header and docs/security/p3-money-path-requirements.md say the
-- counter trigger lets a counter fall only when the old key is on the NEW retired list, and describe the retired list
-- as FIFO ("forgetting a retired entry in the same statement" -> 23514). The trigger checked three things about the
-- lists -- the OLD key's hash is in NEW.attest_retired_key_hashes, the NEW key's hash is in neither the OLD nor the NEW
-- list -- and nothing else. So a writer could present a legitimate-looking replacement whose NEW list had silently
-- DROPPED some OTHER entry (e.g. `ARRAY[<old key hash>]` over a list that held three keys): the counter reset was
-- accepted and the forgotten key could then be registered again, re-opening a replay window for assertions that key
-- signed. app.register_attest_key never does this (it appends and trims), so the gap was reachable only by a hand-written
-- UPDATE, but "the database enforces it" was the claim, so the database should.
--
-- THE FIX. Inside the one legitimate-decrease branch, the NEW list must be EXACTLY what app.register_attest_key writes:
-- the OLD list with the replaced key's hash appended, trimmed to the newest 16 (FIFO). That is stronger than "OLD <@ NEW
-- (or cardinality 16)" and has no at-cap special case to get wrong: at 16 entries the oldest drops and the rest keep
-- their order, and nothing else is accepted. The three existing conditions stay (and are now implied by, but not
-- replaced by, the exact comparison).
--
-- WHAT THIS DOES NOT CLOSE (stated, not fixed here): the trigger is `BEFORE UPDATE OF attest_counter` (0032), so a
-- statement that does not assign attest_counter does not fire it, and a bare `UPDATE ... SET attest_retired_key_hashes`
-- is not covered by any trigger. Only service_role and private_definer hold UPDATE on that column (edge_actor,
-- authenticated and anon hold none), and the only code that writes it is app.register_attest_key. Closing it
-- would mean a second trigger on that column; it is recorded as a follow-up, not claimed.
--
-- Same function, same trigger, same signature, same (empty) search_path, same owner and ACL (CREATE OR REPLACE keeps
-- them; the function is trigger-only and EXECUTEd by no role), so private.function_inventory's existing
-- ('app', 'device_attest_counter_monotonic', '') row (0032) stays accurate and no registry row is added.
-- No table, grant, policy or RLS setting is touched; FORCE RLS is not involved.

CREATE OR REPLACE FUNCTION app.device_attest_counter_monotonic() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_old_hash text;
  v_new_hash text;
  v_expected text[];
BEGIN
  IF NEW.attest_counter >= OLD.attest_counter THEN
    RETURN NEW;
  END IF;
  -- The ONE legitimate decrease: a key replaced by a key this row has never used. Decided by CONTENT, not by role.
  IF NEW.attest_counter = 0
     AND OLD.attest_key_id IS NOT NULL AND NEW.attest_key_id IS NOT NULL
     AND NEW.attest_key_id IS DISTINCT FROM OLD.attest_key_id
     AND OLD.attest_public_key IS NOT NULL AND NEW.attest_public_key IS NOT NULL
     AND NEW.attest_public_key IS DISTINCT FROM OLD.attest_public_key
  THEN
    v_old_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(OLD.attest_key_id, 'UTF8')), 'hex');
    v_new_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(NEW.attest_key_id, 'UTF8')), 'hex');
    -- The list a replacement must leave behind: the OLD list, the replaced key appended, the newest 16 kept (array
    -- slices are 1-based and inclusive). The same arithmetic as app.register_attest_key.
    v_expected := OLD.attest_retired_key_hashes OPERATOR(pg_catalog.||) v_old_hash;
    IF pg_catalog.cardinality(v_expected) > 16 THEN
      v_expected := v_expected[pg_catalog.cardinality(v_expected) - 15 : pg_catalog.cardinality(v_expected)];
    END IF;
    IF v_old_hash = ANY (NEW.attest_retired_key_hashes)
       AND NOT (v_new_hash = ANY (OLD.attest_retired_key_hashes))
       AND NOT (v_new_hash = ANY (NEW.attest_retired_key_hashes))
       AND NEW.attest_retired_key_hashes IS NOT DISTINCT FROM v_expected
    THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'device: attest_counter is monotonic per key (% -> % refused, id=%); only a replacement by a never-before-used key, which appends the replaced key to the retired list (newest 16 kept) and drops nothing else, may start from 0', OLD.attest_counter, NEW.attest_counter, OLD.id
    USING ERRCODE = '23514';
END;
$$;

-- 0038_attest_trigger_key_change.sql
--
-- App Attest counter trigger: decide on "did the KEY change?", not on "did the counter go down?" (security-gate LOW-A on
-- 0036). One function body is redefined and one trigger is dropped and recreated with a wider column list; nothing else
-- changes.
--
-- WHAT 0032 / 0034 / 0036 DID NOT DO. app.device_attest_counter_monotonic() was `BEFORE UPDATE OF attest_counter`, and its
-- body returned at once when the counter did not fall (`NEW.attest_counter >= OLD.attest_counter`). So as service_role (or
-- private_definer; no other role holds UPDATE on the key columns) a hand-written statement was accepted in three shapes:
--   P15  SET attest_key_id = <a RETIRED key>, attest_public_key = <its public key>, attest_counter = <the OLD counter, unchanged>
--        -- the trigger fired but the counter had not fallen, so it returned: a retired key came back with its old counter window
--        reopened, and the retired list still named it;
--   P16  the same key swap without assigning attest_counter -- the trigger did not fire at all;
--   P17  `SET attest_retired_key_hashes = '{}'` (the list wiped, again no trigger), then a "legitimate-looking" replacement to the
--        key that had been retired.
-- Only service_role and private_definer can write those columns and the only code that does is app.register_attest_key (which
-- refuses a retired key), so this was defence in depth -- but docs/security/p3-money-path-requirements.md said "a retired key coming
-- back ... is 23514", and the trigger did not enforce that.
--
-- THE FIX.
--  1. The trigger fires on every column that defines "which key, with which history":
--       BEFORE UPDATE OF attest_counter, attest_key_id, attest_public_key, attest_retired_key_hashes
--     (same trigger name; DROP + CREATE is the only way to change an UPDATE OF column list).
--  2. The body decides on the KEY, by CONTENT, never by role:
--       key UNCHANGED (key id AND public key both IS NOT DISTINCT FROM OLD)
--           the counter must not decrease and the retired list must be exactly what it was;
--       FIRST registration (OLD has no key id and no public key)
--           the counter stays where it was (app.register_attest_key does not touch it: a keyless device's counter is 0 on every
--           reachable path, and the existing 17_ suite registers a keyless device that sits at 5 and expects 5), and the list
--           stays unchanged; this is also the only way a keyless row may gain a key, so a key can never be "cleared" and then
--           re-installed to restart the counter;
--       REPLACEMENT (OLD has both, NEW has both, both differ) -- exactly what app.register_attest_key writes:
--           counter = 0; the new key's hash is NOT in the OLD list, not in the NEW list, and is not the old key's own;
--           the NEW list = (OLD list || hash of the replaced key) trimmed to the newest 16 (FIFO); attest_registered_at is
--           set (the function writes now(); it is deliberately NOT compared with the old value, see below);
--       anything else is 23514. That includes CLEARING a key (NEW key NULL while OLD is not), a half-key, and a swap with
--       the counter, list or provenance left as they were.
--  3. Clearing a key: refused, because no legitimate path does it. A device is DELETED, never updated, when its account goes
--     (private.delete_my_data / the auth.users ON DELETE CASCADE; pd_delete_device_user_id is a DELETE policy), the key columns have
--     no writer but app.register_attest_key, and a cleared-then-reinstalled key is the very rollback this closes.
--
-- WHAT THIS DOES NOT CLOSE (stated, not fixed here):
--   - attest_registered_at is not in the trigger's column list and the trigger cannot tell a VERIFIED registration from an
--     unverified one (verification is Apple's chain, done in TypeScript). On a replacement it can only require the flag to be set
--     (register_attest_key always sets it); a writer who can write the key columns can still write a flag. That is the same trust
--     the whole service_role / private_definer lane has, and is unchanged. It is NOT required to move forward: it is now() of the
--     writing TRANSACTION, and two registrations racing for one device row lock in the opposite order to their start times, so a
--     legitimate replacement can carry an EARLIER timestamp than the one it replaces (a first draft of this trigger refused that, and
--     attest-key.deno.test.ts "two concurrent registrations of DIFFERENT keys" caught it).
--   - A statement that touches none of the four columns is of course not covered (it cannot change the key or the counter).
--   - TRUNCATE, ALTER TABLE ... DISABLE TRIGGER and a superuser are outside any row trigger (as for every trigger in this schema).
--
-- Same function, same trigger name, same signature, same (empty) search_path, same owner and ACL (CREATE OR REPLACE keeps them; the
-- function is trigger-only and EXECUTEd by no role), so private.function_inventory's existing
-- ('app', 'device_attest_counter_monotonic', '') row (0032) stays accurate and no registry row is added. No table, grant, policy or
-- RLS setting is touched; FORCE RLS is not involved. There is no schema change for the activation reason `key_replaced` (NIT-A):
-- fraud_signal.detail is free-form jsonb.

CREATE OR REPLACE FUNCTION app.device_attest_counter_monotonic() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_old_hash text;
  v_new_hash text;
  v_expected text[];
BEGIN
  -- 1. The key did not change: the counter only moves forward, and the retired list is not touched.
  IF NEW.attest_key_id IS NOT DISTINCT FROM OLD.attest_key_id
     AND NEW.attest_public_key IS NOT DISTINCT FROM OLD.attest_public_key
  THEN
    IF NEW.attest_counter < OLD.attest_counter THEN
      RAISE EXCEPTION 'device: attest_counter is monotonic per key (% -> % refused, id=%); only a replacement by a never-before-used key may start from 0', OLD.attest_counter, NEW.attest_counter, OLD.id
        USING ERRCODE = '23514';
    END IF;
    IF NEW.attest_retired_key_hashes IS DISTINCT FROM OLD.attest_retired_key_hashes THEN
      RAISE EXCEPTION 'device: the retired-key list changes only when the key is replaced (key unchanged, id=%)', OLD.id
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  -- 2. The key changed. First registration: a device with no key at all gains one; the counter and the list stay as they are.
  IF OLD.attest_key_id IS NULL AND OLD.attest_public_key IS NULL THEN
    IF NEW.attest_counter = OLD.attest_counter
       AND NEW.attest_retired_key_hashes IS NOT DISTINCT FROM OLD.attest_retired_key_hashes
    THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'device: a first key registration leaves the counter and the retired-key list as they are (id=%)', OLD.id
      USING ERRCODE = '23514';
  END IF;

  -- 3. The key changed and the device already had one: the ONE legitimate shape is a replacement by a key this row has never used,
  -- written exactly as app.register_attest_key writes it. A key is never cleared and never half-replaced.
  IF OLD.attest_key_id IS NOT NULL AND NEW.attest_key_id IS NOT NULL
     AND NEW.attest_key_id IS DISTINCT FROM OLD.attest_key_id
     AND OLD.attest_public_key IS NOT NULL AND NEW.attest_public_key IS NOT NULL
     AND NEW.attest_public_key IS DISTINCT FROM OLD.attest_public_key
     AND NEW.attest_counter = 0
     AND NEW.attest_registered_at IS NOT NULL
  THEN
    v_old_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(OLD.attest_key_id, 'UTF8')), 'hex');
    v_new_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(NEW.attest_key_id, 'UTF8')), 'hex');
    -- The list a replacement must leave behind: the OLD list, the replaced key appended, the newest 16 kept (array slices are
    -- 1-based and inclusive). The same arithmetic as app.register_attest_key.
    v_expected := OLD.attest_retired_key_hashes OPERATOR(pg_catalog.||) v_old_hash;
    IF pg_catalog.cardinality(v_expected) > 16 THEN
      v_expected := v_expected[pg_catalog.cardinality(v_expected) - 15 : pg_catalog.cardinality(v_expected)];
    END IF;
    IF v_new_hash <> v_old_hash
       AND v_old_hash = ANY (NEW.attest_retired_key_hashes)
       AND NOT (v_new_hash = ANY (OLD.attest_retired_key_hashes))
       AND NOT (v_new_hash = ANY (NEW.attest_retired_key_hashes))
       AND NEW.attest_retired_key_hashes IS NOT DISTINCT FROM v_expected
    THEN
      RETURN NEW;
    END IF;
  END IF;

  RAISE EXCEPTION 'device: the App Attest key may change only by a replacement with a never-before-used key, written as app.register_attest_key writes it (counter 0, the replaced key appended to the retired list with the newest 16 kept and nothing else dropped, registered_at set); a key is never cleared, a retired key never returns, and the retired list never changes with the key (% -> %, id=%)', OLD.attest_counter, NEW.attest_counter, OLD.id
    USING ERRCODE = '23514';
END;
$$;

DROP TRIGGER device_attest_counter_monotonic_trg ON app.device;
CREATE TRIGGER device_attest_counter_monotonic_trg
BEFORE UPDATE OF attest_counter, attest_key_id, attest_public_key, attest_retired_key_hashes ON app.device
FOR EACH ROW EXECUTE FUNCTION app.device_attest_counter_monotonic();

-- 0043_device_first_attested.sql
--
-- A sticky "this device has shown it can attest" mark, so the no-attestation rule can count a successful ACTIVATION as evidence of capability.
--
-- WHY. The no-attestation rule (checkin-token and rewards-activate, supabase/functions/_shared/rewards/attestation-evidence.ts) grades a request
-- that carries no attestation `failed` whatever it claims when the server has evidence the device CAN attest. For iOS the evidence is a registered
-- App Attest key (0034). For Android it was only "a check-in token previously issued on the device graded `attested`", so an Android device that had
-- attested only at ACTIVATION (never at check-in) could still claim "I cannot attest" and be believed. An activation records its verdict on the
-- device row as `app.device.integrity_last = {"grade": ..., "at": ...}` (privileged.ts#recordDeviceVerdict), but that column is "the LAST verdict":
-- the next activation overwrites it, so a later `failed` or `unattestable` verdict would erase the evidence the rule needs. The evidence must be sticky.
--
-- WHAT IS ADDED, and what is not:
--   1. app.device.first_attested_at timestamptz, NULL = no `attested` verdict has ever been recorded on this device.
--   2. A BEFORE UPDATE trigger (app.device_first_attested_stamp) that is the ONLY thing that ever writes it:
--        - the first time `integrity_last ->> 'grade'` is 'attested' the column is stamped with now();
--        - once set it is never cleared and never moved: whatever an UPDATE assigns to the column, the trigger puts the old value back.
--      Nothing but a verdict write can set it, by any role: edge_actor has NO UPDATE on this column (its UPDATE grant is unchanged: attest_counter,
--      devicecheck_token_hash, integrity_last, last_seen, install_link_hash), and a role that does have UPDATE (service_role) is normalised by the
--      trigger. The trigger is SECURITY INVOKER with an empty search_path and needs no privilege on the column, because Postgres checks column
--      privileges on the columns an UPDATE NAMES, not on columns a BEFORE trigger changes.
--   3. The registry row in private.function_inventory (the trigger function is EXECUTEd by no role, as for every trigger function in this schema).
--
-- NOT DONE, on purpose:
--   - No grant is added or widened, no policy is added or changed, FORCE ROW LEVEL SECURITY is untouched (asserted below). edge_actor reads the column
--     through its existing table-level SELECT on app.device and the row policy edge_actor_device_select (own devices only).
--   - No backfill. A row written before 0043 that holds an `attested` verdict has no stamp, and the Edge read treats `integrity_last` itself as evidence
--     too (privileged.ts#hasAttestedVerdictOnDevice), so such a row still counts until its next verdict. (An UPDATE inside a migration is filtered by
--     FORCE ROW LEVEL SECURITY for the table owner, so a backfill here would be unreliable; this repository's databases are pre-launch.)
--   - Not added to GET /v1/me/export (private.export_my_data lists device columns by name). `integrity_last` (grade + time of the last verdict) is
--     already exported; this column is a derived internal mark of the same fact. Recorded as a follow-up in the security doc.
--
-- Deploy order: apply this migration BEFORE the Edge code that reads `first_attested_at` (an older schema would fail the read with 42703).

ALTER TABLE app.device ADD COLUMN first_attested_at timestamptz;
COMMENT ON COLUMN app.device.first_attested_at IS
  'When an `attested` verdict was FIRST written to integrity_last for this device; NULL = never. Stamped once by app.device_first_attested_stamp and never cleared or moved, so a later failed/unattestable verdict (which overwrites integrity_last) does not erase the evidence that the device can attest. 0043.';

CREATE FUNCTION app.device_first_attested_stamp() RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- Sticky: an existing stamp is restored whatever the statement assigned (clearing, moving it later, moving it earlier). Otherwise it is stamped
  -- only by an `attested` verdict arriving in integrity_last; any other assignment to the column on a never-attested device is discarded.
  NEW.first_attested_at := COALESCE(
    OLD.first_attested_at,
    CASE WHEN NEW.integrity_last OPERATOR(pg_catalog.->>) 'grade' = 'attested' THEN pg_catalog.now() END
  );
  RETURN NEW;
END;
$$;
CREATE TRIGGER device_first_attested_stamp_trg
BEFORE UPDATE OF integrity_last, first_attested_at ON app.device
FOR EACH ROW EXECUTE FUNCTION app.device_first_attested_stamp();

INSERT INTO private.function_inventory
  (schema_name, function_name, identity_args, expected_anon, expected_authenticated, expected_service_role, expected_edge_actor, expected_edge_system, note)
VALUES
  ('app', 'device_first_attested_stamp', '', false, false, false, false, false,
   '0043: trigger function (app.device_first_attested_stamp_trg) -- stamps app.device.first_attested_at once, when an attested verdict is written to integrity_last, and never clears or moves it; never EXECUTEd directly by any role');

DO $assert_0043$
BEGIN
  IF has_column_privilege('edge_actor', 'app.device', 'first_attested_at', 'UPDATE') THEN
    RAISE EXCEPTION '0043: edge_actor must hold no UPDATE on app.device.first_attested_at (only the trigger writes it)';
  END IF;
  IF has_column_privilege('edge_actor', 'app.device', 'first_attested_at', 'INSERT') THEN
    RAISE EXCEPTION '0043: edge_actor must hold no INSERT on app.device.first_attested_at';
  END IF;
  IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = 'app.device'::regclass) THEN
    RAISE EXCEPTION '0043: app.device must keep FORCE ROW LEVEL SECURITY';
  END IF;
END
$assert_0043$;

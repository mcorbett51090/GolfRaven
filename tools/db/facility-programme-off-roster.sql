-- tools/db/facility-programme-off-roster.sql
--
-- READ-ONLY. Lists every app.facility_programme row whose facility is NOT on its trail's CURRENT roster: the rows migration 0110 (design section 141) would now refuse to create, or to leave accepted, and
-- the rows a bug or a hand edit made BEFORE it. Why you want this list: private.has_facility_scope (0007) lets an OPERATOR reach any facility for which a facility_programme row exists for a trail it
-- operates, so a row whose facility is not on the trail's roster is a standing grant of reach to a facility that has nothing to do with that trail (design section 138.1). 0110 fixes the WRITE only; a row
-- written earlier stays a grant until somebody removes it or the read is fixed (section 138.3, option B). Nothing is deployed as of section 141, so none are expected; run this ONCE at the first deploy,
-- after the catalogue has been imported and before the first operator signs in.
--
-- The roster test is the one the editor applies (0110): a member of the trail's LATEST roster version (the greatest catalog_roster_version.version) with removed_on IS NULL (any non-null date, past or
-- future, removes the member) that names the facility (facility_id), a course of it (course_id), a hole of it (hole_id) or a course of it inside any_of_course_ids. The matrix 88 cells run this exact text
-- against the definer, row by row.
--
-- HOW TO RUN. As a role that BYPASSES row level security: the Supabase service_role (SET ROLE service_role;) or the Postgres superuser. The roster tables are FORCE ROW LEVEL SECURITY, and a role that is
-- subject to it (the migration owner in a restricted setup, an application role) reads an EMPTY roster and so would list EVERY programme row, or print an empty list that looks like "all clean". The guard
-- below refuses to go on as such a role (it raises), so a wrong role can never produce an answer.
--
--   psql -v ON_ERROR_STOP=1 "$DATABASE_URL" -f tools/db/facility-programme-off-roster.sql
--
-- The file also switches ON_ERROR_STOP on itself (the first line below), so the guard stops the run even when the flag is forgotten: without it psql prints the guard's
-- error, carries on, prints "0|0" and an empty list and exits 0 (the Opus gate ran exactly that against the restricted migration owner).
--
-- WHAT TO DO WITH A ROW. Decide per row whether the facility belongs on the trail.
--   * If it does, put it on the roster (the importer's job: a new roster version) and the row is correct.
--   * If it does not, the row is a stray grant, and there are two different things to stop:
--       - the PLAYER LANE (check-ins, marker attests, receipts at that facility): they require participation = 'accepted'. The operator can switch them off through the editor even though the facility is off
--         the roster: demote the row to 'left' or 'declined' (0110 allows that on an existing row, and no other participation value; the same call may also change the row's other columns). That is the operator's off-switch for the player lane.
--       - the REACH: has_facility_scope reads the row and NOT its participation (there is no participation filter, G3, section 138.3, undecided), so a demoted row STILL gives the trail's operator
--         reach to that facility (invites, PIN resets, credential revocation, the printed QR). Only DELETING the row removes it (there is no route that deletes a programme row, by design):
--         DELETE FROM app.facility_programme WHERE trail_id = ... AND facility_id = ...; as the owner. Until the G3 filter (or option B) exists, `left` is not a full off-switch.
-- This script changes nothing.

\set ON_ERROR_STOP on

-- BEGIN rls guard
DO $guard$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolbypassrls)) THEN
    RAISE EXCEPTION 'facility-programme-off-roster: run this as a role that bypasses row level security (service_role, or the superuser); % is subject to it, reads an empty roster and would list every programme row', current_user USING ERRCODE = '42501';
  END IF;
END
$guard$
-- END rls guard
;

SELECT (SELECT count(*) FROM app.catalog_roster_member) AS roster_members_visible,
       (SELECT count(*) FROM app.facility_programme) AS facility_programme_rows;

-- BEGIN off-roster query
SELECT fp.trail_id, fp.facility_id, fp.participation::text AS participation
FROM app.facility_programme fp
WHERE NOT EXISTS (
  SELECT 1
  FROM app.catalog_roster_member rm
  WHERE rm.trail_id = fp.trail_id
    AND rm.removed_on IS NULL
    AND rm.roster_version = (SELECT max(v.version) FROM app.catalog_roster_version v WHERE v.trail_id = fp.trail_id)
    AND (
      rm.facility_id = fp.facility_id
      OR rm.course_id IN (SELECT c.id FROM app.catalog_course c WHERE c.facility_id = fp.facility_id)
      OR rm.hole_id IN (SELECT h.id FROM app.catalog_hole h JOIN app.catalog_course c ON c.id = h.course_id WHERE c.facility_id = fp.facility_id)
      OR rm.any_of_course_ids && ARRAY(SELECT c.id FROM app.catalog_course c WHERE c.facility_id = fp.facility_id)
    )
)
ORDER BY fp.trail_id, fp.facility_id
-- END off-roster query
;

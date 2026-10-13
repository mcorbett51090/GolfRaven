-- tools/db/facility-programme-off-roster.sql
--
-- READ-ONLY. Lists every app.facility_programme row whose facility is NOT on its trail's CURRENT roster: the rows migration 0110 (design section 140) would now refuse to write, and the rows a
-- bug or a hand edit made BEFORE it. Why you want this list: private.has_facility_scope (0007) lets an OPERATOR reach any facility for which a facility_programme row exists for a trail it
-- operates, so a row whose facility is not on the trail's roster is a standing grant of reach to a facility that has nothing to do with that trail (design section 138.1). 0110 fixes the WRITE only;
-- a row written earlier stays a grant until somebody removes it or the read is fixed (section 138.3, option B). Nothing is deployed as of section 140, so none are expected; run this ONCE at the
-- first deploy, after the catalogue has been imported and before the first operator signs in.
--
-- The roster test is the one the editor applies (0110): a member of the trail's LATEST roster version (the greatest catalog_roster_version.version) with removed_on IS NULL that names the facility
-- (facility_id), a course of it (course_id), a hole of it (hole_id) or a course of it inside any_of_course_ids. The matrix 88 cells run this exact text against the definer, row by row.
--
-- HOW TO RUN. As a role that BYPASSES row level security: the Supabase service_role (SET ROLE service_role;) or the Postgres superuser. The roster tables are FORCE ROW LEVEL SECURITY, and a role that
-- is subject to it (the migration owner in a restricted setup, an application role) reads an EMPTY roster and so would list EVERY programme row. The first statement below is the check on that:
-- if roster_members_visible is 0 while facility_programme_rows is not, you are not bypassing RLS; stop and switch role.
--
--   psql "$DATABASE_URL" -f tools/db/facility-programme-off-roster.sql
--
-- WHAT TO DO WITH A ROW. Decide per row whether the facility belongs on the trail. If it does, put it on the roster (the importer's job, a new roster version) and the row is correct. If it does not, the
-- row is a stray grant: remove it (DELETE FROM app.facility_programme WHERE trail_id = ... AND facility_id = ...; there is no route that deletes one, by design) or set participation to left
-- once the participation filter (section 138.3, G3) exists. This script changes nothing.

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

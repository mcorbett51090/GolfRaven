-- 25_partner_auth_spine_edgez_cleanup.sql
-- Deletes what 25_partner_auth_spine_edge.sql committed (two sessions' worth of fixtures: one credential, three sessions) and proves they are gone, so the file stays
-- re-runnable on one cluster and nothing leaks into a later file. Named `edgez_cleanup` so pg_prove's lexical order runs it AFTER `..._edge.sql` (a plain `_edge_cleanup`
-- sorts before `_edge` on some locales). Same shape as 23_offline_totp_seed_rows.sql: a temporary CURRENT_USER policy on each FORCE-RLS table.
\set QUIET 1
BEGIN;
SELECT plan(3);
GRANT SELECT, UPDATE, DELETE ON app.partner_credential, app.partner_session TO CURRENT_USER;
CREATE POLICY zz24e_cred ON app.partner_credential FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
CREATE POLICY zz24e_sess ON app.partner_session FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE id::text LIKE 'ee24e000-%'), 3, 'precondition: the edge file left its three sessions');
DELETE FROM app.partner_session WHERE id::text LIKE 'ee24e000-%';
DELETE FROM app.partner_credential WHERE id::text LIKE 'ee24e000-%';
SELECT is((SELECT count(*)::int FROM app.partner_session WHERE id::text LIKE 'ee24e000-%') + (SELECT count(*)::int FROM app.partner_credential WHERE id::text LIKE 'ee24e000-%'), 0, 'the edge file''s committed fixtures are deleted');
SELECT is((SELECT count(*)::int FROM pg_trigger WHERE tgrelid IN ('app.partner_session'::regclass, 'app.partner_credential'::regclass) AND tgname IN ('partner_session_insert_guard_trg', 'partner_credential_insert_guard_trg') AND tgenabled = 'O'), 2, 'the INSERT guards are enabled again after the edge file''s seeding');
DROP POLICY zz24e_cred ON app.partner_credential;
DROP POLICY zz24e_sess ON app.partner_session;
REVOKE SELECT, UPDATE, DELETE ON app.partner_credential, app.partner_session FROM CURRENT_USER;
SELECT * FROM finish();
COMMIT;

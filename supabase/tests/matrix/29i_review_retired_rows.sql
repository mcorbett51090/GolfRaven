-- 29i_review_retired_rows.sql
-- 0051 (gate review F1): what 29h left behind, then the cleanup of everything 29g seeded and the harness's own review account put back. Harness role -> service_role.

\set QUIET 1
SELECT plan(4);
SET ROLE service_role;
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29520000-0000-0000-0000-00000000000a' AND action = 'review_account.session_refused' AND subject_id = '29520000-0000-0000-0000-0000000005a1'), 1, 'the RETIRED account was refused (a window open) and audited once');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29520000-0000-0000-0000-00000000000a' AND action = 'review_account.session_allowed'), 0, 'and never once "allowed"');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29520000-0000-0000-0000-00000000000b' AND action = 'review_account.session_allowed' AND subject_id = '29520000-0000-0000-0000-0000000005a2'), 1, 'the new active account: one allowed row for its session');
SELECT is((SELECT count(*)::int FROM app.app_review_demo_account WHERE user_id = '29520000-0000-0000-0000-00000000000a' AND retired_at IS NOT NULL), 1, 'the retired row is still there');
RESET ROLE;
-- cleanup. The retired row can only be deleted once its Auth user is gone (the guard), and this harness cannot delete auth.users as service_role: the OWNER switches the guard off for this one statement.
SET ROLE service_role;
DELETE FROM app.app_review_window WHERE id = '29520000-0000-0000-0000-00000000f001';
DELETE FROM app.app_review_demo_account WHERE retired_at IS NULL;
RESET ROLE;
ALTER TABLE app.app_review_demo_account DISABLE TRIGGER review_account_retire_guard_trg;
SET ROLE service_role;
DELETE FROM app.app_review_demo_account WHERE retired_at IS NOT NULL;
RESET ROLE;
ALTER TABLE app.app_review_demo_account ENABLE TRIGGER review_account_retire_guard_trg;
SET ROLE service_role;
INSERT INTO app.app_review_demo_account (user_id) VALUES ('00000000-0000-0000-0000-5000000000e0') ON CONFLICT DO NOTHING; -- the harness's own review account (helpers.sql), put back
RESET ROLE;

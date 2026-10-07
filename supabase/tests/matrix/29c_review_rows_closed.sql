-- 29c_review_rows_closed.sql
-- 0051: what 29b's refusals left behind, read back after they COMMITTED (the 0020 lesson: a refusal that raised would have rolled these rows back). Then it opens a live window
-- for 29d. Harness role -> service_role.

\set QUIET 1
SELECT plan(11);
SET ROLE service_role;
CREATE FUNCTION pg_temp.n(p_where text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE v int;
BEGIN
  EXECUTE 'SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = ''29510000-0000-0000-0000-0000000000a0'' AND ' || p_where INTO v;
  RETURN v;
END
$f$;
SELECT is(pg_temp.n($$action = 'review_account.session_refused' AND subject_id = '29510000-0000-0000-0000-0000000005a1'$$), 1, 'session S1 was refused TWICE and audited ONCE (the refusal committed; dedupe per session)');
SELECT is(pg_temp.n($$action = 'review_account.session_refused' AND subject_id = '29510000-0000-0000-0000-0000000005a2'$$), 1, 'session S2 (upper-case in the call) is recorded in canonical lower case');
SELECT is(pg_temp.n($$action = 'review_account.session_refused' AND subject_id IS NULL$$), 3, 'an unreadable or missing session id is audited on EVERY call (three calls, three rows)');
SELECT is(pg_temp.n($$true$$), 5, 'R has exactly five audit rows (S1, S2, three unknown)');
SELECT is(pg_temp.n($$action = 'review_account.session_allowed'$$), 0, 'and none says allowed');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29510000-0000-0000-0000-0000000000b0'), 0, 'the ordinary account N has NO audit row (not_review writes nothing)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29510000-0000-0000-0000-0000000000a0' AND detail <> '{"outcome": "refused"}'::jsonb), 0, 'every row holds exactly {"outcome": "refused"} in detail: no email, no address, no token');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29510000-0000-0000-0000-0000000000a0' AND subject_table IS DISTINCT FROM 'auth_session'), 0, 'and the subject is the auth session, nothing else');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29510000-0000-0000-0000-0000000000a0' AND (to_jsonb(audit_log)::text ~* '@|bearer|eyJ')), 0, 'no audit row of R contains an at-sign, a bearer word or a JWT prefix');
SELECT throws_ok($$UPDATE app.audit_log SET action = 'x' WHERE actor_user_id = '29510000-0000-0000-0000-0000000000a0'$$, 'P0001', NULL, 'the audit rows are insert-only (the existing trigger covers the new action)');
-- the window opens: 29d runs inside it
INSERT INTO app.app_review_window (id, starts_at, ends_at, note) VALUES ('29510000-0000-0000-0000-00000000f003', now() - interval '1 hour', now() + interval '1 hour', 'matrix 29 live');
SELECT is(private.review_window_open_at(now()), true, 'a live window now holds the clock: the predicate says open');
RESET ROLE;

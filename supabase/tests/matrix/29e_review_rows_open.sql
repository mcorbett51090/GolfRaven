-- 29e_review_rows_open.sql
-- 0051: what 29d left behind, then the window CLOSES (its end moves to the past: the half-open boundary, the instant the window ends the account is disabled again).
-- Harness role -> service_role.

\set QUIET 1
SELECT plan(7);
SET ROLE service_role;
CREATE FUNCTION pg_temp.n(p_where text) RETURNS int LANGUAGE plpgsql AS $f$
DECLARE v int;
BEGIN
  EXECUTE 'SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = ''29510000-0000-0000-0000-0000000000a0'' AND ' || p_where INTO v;
  RETURN v;
END
$f$;
SELECT is(pg_temp.n($$action = 'review_account.session_allowed' AND subject_id = '29510000-0000-0000-0000-0000000005a1'$$), 1, 'S1 was allowed twice and audited ONCE as allowed');
SELECT is(pg_temp.n($$action = 'review_account.session_refused' AND subject_id = '29510000-0000-0000-0000-0000000005a1'$$), 1, 'and S1''s earlier REFUSAL row is still there (the log never loses the first answer)');
SELECT is(pg_temp.n($$action = 'review_account.session_allowed' AND subject_id = '29510000-0000-0000-0000-0000000005a3'$$), 1, 'session S3 audited once, allowed');
SELECT is(pg_temp.n($$true$$), 7, 'R now has seven audit rows in total (five refused, two allowed)');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29510000-0000-0000-0000-0000000000a0' AND detail <> jsonb_build_object('outcome', CASE action WHEN 'review_account.session_allowed' THEN 'allowed' ELSE 'refused' END)), 0, 'every row''s detail agrees with its action and holds nothing else');
SELECT is((SELECT count(*)::int FROM app.audit_log WHERE actor_user_id = '29510000-0000-0000-0000-0000000000b0'), 0, 'N still has no audit row');
-- the window ends: move its end to a past instant (its start is an hour ago, so the CHECK holds)
UPDATE app.app_review_window SET ends_at = now() - interval '1 second' WHERE id = '29510000-0000-0000-0000-00000000f003';
SELECT is(private.review_window_open_at(now()), false, 'the live window has ended: the predicate says closed at once');
RESET ROLE;

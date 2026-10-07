-- 29f_review_gate_closed_again_edge.sql
-- 0051: the window that 29e just ended: the SAME account that signed in moments ago is refused again, in the gate and in the binder, with no restart and no cache. Then it removes
-- everything 29a seeded (harness role, as service_role) so the file set is re-runnable.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(4);

BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a3'), 'disabled', 'S3 was allowed an instant ago; the window ended: disabled (a refusal is a NEW row for the session, the allowed row stays)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a4'), 'disabled', 'a brand-new session S4: disabled');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.bind_actor('29510000-0000-0000-0000-0000000000a0')$$, '42501', 'bind_actor: the review account is disabled outside a submission window', 'the binder refuses R again');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('29510000-0000-0000-0000-0000000000b0')$$, 'control: N is still bindable');
ROLLBACK;

-- cleanup (harness role, as service_role): the windows, then both accounts' data (delete_my_data redacts the audit rows' actor to NULL; they are insert-only by design)
\c :"harness_db" :"harness_user"
SET ROLE service_role;
BEGIN;
DELETE FROM app.app_review_window WHERE id::text LIKE '29510000-%';
SELECT count(private.delete_my_data(u)) FROM unnest(ARRAY['29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000000b0']::uuid[]) AS u;
INSERT INTO app.app_review_demo_account (user_id) VALUES ('00000000-0000-0000-0000-5000000000e0') ON CONFLICT DO NOTHING; -- the harness's own review account (helpers.sql), put back
COMMIT;
RESET ROLE;

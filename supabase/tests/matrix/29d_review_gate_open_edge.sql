-- 29d_review_gate_open_edge.sql
-- 0051, the review account INSIDE a window (29c opened one), through a real `edge_gateway` login. Same lanes as 29b.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(11);

BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a1'), 'allowed', 'R inside the window, session S1 (refused earlier): allowed');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a1'), 'allowed', 'the same session again: allowed (and 29e proves one row)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a3'), 'allowed', 'a new session S3: allowed');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000b0', '29510000-0000-0000-0000-0000000005a3'), 'not_review', 'N: not_review');
COMMIT;

-- the binder admits R inside the window
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('29510000-0000-0000-0000-0000000000a0')$$, 'bind_actor(R) inside the window succeeds (the account CAN sign in: AT 14)');
SELECT is(private.actor_uid(), '29510000-0000-0000-0000-0000000000a0'::uuid, 'and R is the bound actor');
-- ...and, bound as R, there is no way to an offer, an entitlement or a special marker (privilege check precedes every constraint: 42501 is the refusal, not a NOT NULL)
SELECT throws_ok($$INSERT INTO app.offer_code DEFAULT VALUES$$, '42501', NULL, 'bound as R: INSERT INTO offer_code is refused');
SELECT throws_ok($$INSERT INTO app.entitlement DEFAULT VALUES$$, '42501', NULL, 'bound as R: INSERT INTO entitlement is refused');
SELECT throws_ok($$INSERT INTO app.special_marker_stock DEFAULT VALUES$$, '42501', NULL, 'bound as R: INSERT INTO special_marker_stock is refused');
SELECT throws_ok($$INSERT INTO app.offer DEFAULT VALUES$$, '42501', NULL, 'bound as R: INSERT INTO offer is refused');
SELECT is((SELECT count(*)::int FROM app.offer_code), 0, 'bound as R: R sees no offer code of its own');
ROLLBACK;

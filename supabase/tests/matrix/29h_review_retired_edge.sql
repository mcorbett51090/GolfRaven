-- 29h_review_retired_edge.sql
-- 0051 (gate review F1), through a real `edge_gateway` login: with a window OPEN, the RETIRED account (29g: Q) is refused by the gate and by the binder, while the new active account (N2) is
-- let through (retiring one does not break the next).

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(8);

BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29520000-0000-0000-0000-00000000000a', '29520000-0000-0000-0000-0000000005a1'), 'disabled', 'the RETIRED account, a window open: disabled');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29520000-0000-0000-0000-00000000000a', '29520000-0000-0000-0000-0000000005a1'), 'disabled', 'and again for the same session: still disabled (one audit row, 29i)');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29520000-0000-0000-0000-00000000000b', '29520000-0000-0000-0000-0000000005a2'), 'allowed', 'the NEW active account, the same window: allowed');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.bind_actor('29520000-0000-0000-0000-00000000000a')$$, '42501', 'bind_actor: the review account is retired', 'bind_actor(retired) is refused, a window open: 42501 "retired"');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('29520000-0000-0000-0000-00000000000b')$$, 'bind_actor(new active account) succeeds inside the window');
-- the refusals that keep applying to a review account are for the ACTIVE one here (bound); the retired one cannot be bound at all
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_none', 'static_pin', NULL, 'k', '1234', now(), NULL, NULL, NULL)), 'review_account', 'the active account is still refused a marker scan');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.activate_offer_code_for_actor(gen_random_uuid(), gen_random_uuid(), 'h', 'activate', NULL)$$, '42501', NULL, 'unbound: no actor, no activation (control for the retired account having no way in)');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29520000-0000-0000-0000-00000000000b', '29520000-0000-0000-0000-0000000005a2'), 'allowed', 'the new account again, same session: allowed');
COMMIT;

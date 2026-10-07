-- 29d_review_gate_open_edge.sql
-- 0051, the review account INSIDE a window (29c opened one), through a real `edge_gateway` login. Same lanes as 29b.

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(19);

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
-- 0051 (MEDIUM-1): the edge_actor-executable definers that CREATE a purchase / credit refuse the review account (status 'review_account', nothing written); the two activations raise 42501.
-- The refusal comes BEFORE argument validation, so these arguments need no fixture: a non-review account with the very same call gets a different, ordinary answer (controls below).
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_none', 'static_pin', NULL, 'k', '1234', now(), NULL, NULL, NULL)), 'review_account', 'bound as R: marker_scan_for_actor refuses with the status review_account');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_none', now(), 'attested', 'fix1', gen_random_uuid())), 'review_account', 'bound as R: marker_cosignal_attach_for_actor refuses with the status review_account');
SELECT throws_ok($$SELECT private.activate_offer_code_for_actor(gen_random_uuid(), gen_random_uuid(), 'h', 'clear', NULL)$$, '42501', 'activate_offer_code_for_actor: the review account may not activate a reward', 'bound as R: activate_offer_code_for_actor is refused');
SELECT throws_ok($$SELECT private.activate_entitlement_for_actor(gen_random_uuid(), gen_random_uuid(), 'h', 'clear', NULL)$$, '42501', 'activate_entitlement_for_actor: the review account may not activate a reward', 'bound as R: activate_entitlement_for_actor is refused');
ROLLBACK;
-- CONTROLS: an ordinary account N makes the very same calls and gets the ordinary answers (the refusals above are about WHO the actor is, nothing else)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('29510000-0000-0000-0000-0000000000b0')$$, 'bind N');
SELECT is((SELECT o_result FROM private.marker_scan_for_actor('fac_none', 'static_pin', NULL, 'k', '1234', now(), NULL, NULL, NULL)), 'no_facility', 'control, bound as N: the same marker scan is answered no_facility');
SELECT is((SELECT o_result FROM private.marker_cosignal_attach_for_actor('fac_none', now(), 'attested', 'fix1', gen_random_uuid())), 'no_pending_purchase', 'control, bound as N: the same co-signal attach is answered no_pending_purchase');
SELECT throws_ok($$SELECT private.activate_offer_code_for_actor(gen_random_uuid(), gen_random_uuid(), 'h', 'clear', NULL)$$, 'P0002', NULL, 'control, bound as N: the same activation is "not yours" (P0002), not the review-account refusal');
ROLLBACK;

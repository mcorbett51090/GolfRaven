-- 29b_review_gate_closed_edge.sql
-- 0051, the review account OUTSIDE every window, through a REAL `edge_gateway` login (SET ROLE is judged by the SESSION user: read 21_device_platform_claim.sql).
-- The state is seeded by 29a (R = the review account, N = an ordinary account; only a past and a future window exist). Every gate call below is its OWN committed
-- transaction, as privileged.ts runs it (openScopedTx("system"): SET LOCAL ROLE edge_system, one statement, commit); 29c reads what they wrote.
-- Re-runnable on one cluster ONLY together with 29f (which removes the seed).

\set QUIET 1
SELECT session_user::text AS harness_user, current_database()::text AS harness_db \gset
\c :"harness_db" edge_gateway
\set QUIET 1
SELECT plan(13);

-- 1. R, session S1: refused, and the call RETURNS (it does not raise: the audit row must commit with the refusal)
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a1'), 'disabled', 'R outside every window, session S1: disabled');
COMMIT;
-- 2. the same session again: still disabled, and 29c proves it wrote NOTHING more (dedupe per session)
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005a1'), 'disabled', 'the same session S1 again: still disabled');
COMMIT;
-- 3. a new session S2 (upper-case id: canonicalised to the same lower-case form)
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', '29510000-0000-0000-0000-0000000005A2'), 'disabled', 'a new session S2: disabled');
COMMIT;
-- 4. a token whose session id is unreadable: refused, and audited on EVERY call (never deduped)
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', 'not-a-uuid'), 'disabled', 'an unreadable session id: disabled');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', 'not-a-uuid'), 'disabled', 'an unreadable session id again: disabled');
COMMIT;
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000a0', NULL), 'disabled', 'no session id at all: disabled');
COMMIT;
-- 5. an ordinary account: not a review account, nothing written
BEGIN;
SET LOCAL ROLE edge_system;
SELECT is(private.review_account_gate('29510000-0000-0000-0000-0000000000b0', '29510000-0000-0000-0000-0000000005a1'), 'not_review', 'N is not a review account: not_review (and 29c proves nothing was written for it)');
COMMIT;
-- 6. malformed argument raises, and writes nothing
BEGIN;
SET LOCAL ROLE edge_system;
SELECT throws_ok($$SELECT private.review_account_gate(NULL, 's')$$, '22023', NULL, 'a NULL uid raises 22023');
ROLLBACK;
-- 7. the actor lane cannot call the gate (it is the system lane's)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.review_account_gate('29510000-0000-0000-0000-0000000000a0', NULL)$$, '42501', NULL, 'edge_actor holds no EXECUTE on the gate');
ROLLBACK;

-- 8. THE BACKSTOP: no Edge path, gate or no gate, can open an actor-bound transaction for a disabled review account
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT throws_ok($$SELECT private.bind_actor('29510000-0000-0000-0000-0000000000a0')$$, '42501', 'bind_actor: the review account is disabled outside a submission window', 'bind_actor(R) outside every window raises 42501');
ROLLBACK;
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT lives_ok($$SELECT private.bind_actor('29510000-0000-0000-0000-0000000000b0')$$, 'control: bind_actor(N) is unaffected');
SELECT is(private.actor_uid(), '29510000-0000-0000-0000-0000000000b0'::uuid, 'control: and N is bound');
ROLLBACK;
-- a refused bind leaves no binding behind: the NEXT transaction on this connection is unbound (fail closed)
BEGIN;
SET LOCAL ROLE edge_actor;
SELECT is(private.actor_uid(), NULL::uuid, 'after the refused bind the next transaction on the connection holds no binding');
ROLLBACK;

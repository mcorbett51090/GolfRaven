-- 29g_review_retired_seed.sql
-- 0051 (gate review F1): a RETIRED review account. Replacing the account must not make the old one an ordinary player (its Auth ban does not revoke a token already issued), so a retired
-- account KEEPS its row, marked retired_at: is_demo_account stays true, and the window gate and the binder refuse it ALWAYS, with a submission window OPEN. This file seeds, committed, what
-- 29h (edge) and 29i (rows, cleanup) use:
--   Q = 29510000-...-0a  RETIRED review account        N2 = 29510000-...-0b  the NEW, active review account        a LIVE window (an hour either side of now)
-- (the harness's own review account, which helpers.sql seeds, is put back by 29i.)

\set QUIET 1
SELECT plan(4);
SET ROLE service_role;
BEGIN;
INSERT INTO auth.users (id) VALUES
  ('29520000-0000-0000-0000-00000000000a'),
  ('29520000-0000-0000-0000-00000000000b')
ON CONFLICT (id) DO NOTHING;
DELETE FROM app.app_review_demo_account;
INSERT INTO app.app_review_demo_account (user_id, retired_at) VALUES ('29520000-0000-0000-0000-00000000000a', now());
INSERT INTO app.app_review_demo_account (user_id) VALUES ('29520000-0000-0000-0000-00000000000b');
INSERT INTO app.app_review_window (id, starts_at, ends_at, note) VALUES ('29520000-0000-0000-0000-00000000f001', now() - interval '1 hour', now() + interval '1 hour', 'matrix 29g live');
COMMIT;
SELECT is((SELECT count(*)::int FROM app.app_review_demo_account WHERE retired_at IS NULL), 1, 'exactly one ACTIVE review account (the new one)');
SELECT is((SELECT count(*)::int FROM app.app_review_demo_account WHERE retired_at IS NOT NULL), 1, 'and one RETIRED, its row kept');
SELECT is(private.review_window_open_at(now()), true, 'a window is OPEN: a refusal of the retired account below cannot be the window');
SELECT is(private.is_demo_account('29520000-0000-0000-0000-00000000000a'), true, 'the retired account is still a review account');
RESET ROLE;

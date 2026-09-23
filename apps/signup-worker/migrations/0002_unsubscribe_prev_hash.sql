-- Gate finding F-S7: keeps every unsubscribe link ever emailed working
-- across a TOKEN_PEPPER rotation, even after TOKEN_PEPPER_PREVIOUS is
-- later unset. See src/index.ts's `rotateAndSendIfAllowed` and
-- README.md "Rotating TOKEN_PEPPER".
--
-- Nullable, additive column — no backfill needed: existing rows keep
-- `unsubscribe_token_hash_prev` NULL until their next resend (the only
-- place that ever populates it), which is harmless (a NULL column value
-- never matches an incoming token's hash).
--
-- Apply with:
--   wrangler d1 execute golfraven-signups --remote --file=./migrations/0002_unsubscribe_prev_hash.sql
-- (drop --remote to apply against the local dev D1 first).

ALTER TABLE signups ADD COLUMN unsubscribe_token_hash_prev TEXT;

-- Looked up on every POST /api/unsubscribe alongside unsubscribe_token_hash
-- (the handler matches the incoming token's hash against EITHER column).
CREATE INDEX idx_signups_unsubscribe_token_hash_prev ON signups (unsubscribe_token_hash_prev);

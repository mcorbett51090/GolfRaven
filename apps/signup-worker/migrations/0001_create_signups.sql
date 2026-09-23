-- K2 signup backend — initial schema (build plan §10 P0, K2; decision 0001
-- Addendum D R3; docs/p0/gate-review.md S6).
--
-- Privacy note: NO IP address or user agent is ever stored here (task
-- requirement) — rate limiting lives entirely in KV (see src/ratelimit.ts)
-- and is TTL'd, never durable. Only token HASHES are stored, never raw
-- tokens (src/tokens.ts).
--
-- Apply with:
--   wrangler d1 execute golfraven-signups --remote --file=./migrations/0001_create_signups.sql
-- (drop --remote to apply against the local dev D1 first).

CREATE TABLE signups (
  id TEXT PRIMARY KEY,
  -- Lower-cased email address. UNIQUE is the source-of-truth enforcement
  -- for "distinct lower-cased emails" (decision 0001 Addendum D R3) — the
  -- K2 count script dedupes defensively too, since its input is an
  -- arbitrary JSON export rather than a live read of this constraint.
  email_lc TEXT NOT NULL UNIQUE,
  -- Which wording of the privacy/consent copy this signup agreed to
  -- (apps/landing/src/main.js CONSENT_VERSION) — must be one of
  -- src/config.ts's ALLOWED_CONSENT_VERSIONS at write time.
  consent_version TEXT NOT NULL,
  -- Always 1: the 16+ attestation is required to create a row at all
  -- (src/validate.ts rejects ageConfirmed !== true before any DB write).
  age_confirmed INTEGER NOT NULL CHECK (age_confirmed = 1),
  -- Optional short attribution string from the signup form/URL (e.g. a
  -- promo channel tag). Free text, length-capped and control-character
  -- stripped in src/validate.ts. Never rendered as HTML.
  source TEXT,
  created_at TEXT NOT NULL,
  -- NULL until the double-opt-in confirmation link is clicked (POST
  -- /api/confirm). This is the field the K2 count reads (decision 0001
  -- Addendum D R3) — an unconfirmed row never counts.
  confirmed_at TEXT,
  -- NULL unless the one-click unsubscribe link/header was used. A fresh
  -- confirmation clears this (re-opens the address) — see src/db.ts
  -- recordConfirmation().
  unsubscribed_at TEXT,
  -- sha256(TOKEN_PEPPER + ":" + raw confirm token). Rotated on every
  -- re-signup of a not-yet-confirmed or unsubscribed address.
  confirm_token_hash TEXT,
  confirm_expires_at TEXT,
  -- sha256(TOKEN_PEPPER + ":" + raw unsubscribe token). Present from row
  -- creation, rotated on every re-signup so a re-signup's confirmation
  -- email always carries a working unsubscribe link.
  unsubscribe_token_hash TEXT NOT NULL
);

-- Looked up on every POST /api/confirm.
CREATE INDEX idx_signups_confirm_token_hash ON signups (confirm_token_hash);
-- Looked up on every POST /api/unsubscribe (including the RFC 8058
-- one-click POST a mail client sends automatically).
CREATE INDEX idx_signups_unsubscribe_token_hash ON signups (unsubscribe_token_hash);

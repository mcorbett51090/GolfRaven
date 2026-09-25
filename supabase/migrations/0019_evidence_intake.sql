-- 0019_evidence_intake.sql
-- P3c: the Edge Function layer for POST /v1/evidence (+ batch),
-- POST /v1/checkin/challenge and checkin-token
-- (docs/golf-trails/02-build-plan.md §4.7.1a inventory; §10 P3 M-staging).
-- Two new tables, both written only by service_role (Edge Functions),
-- matching the "nobody" client-read convention every other system/session
-- table in this schema already follows (checkin_challenge, device_reward_
-- ledger, etc. — build plan §4.4).

-- ============================================================================
-- 1. app.catalog_signing_key — build plan §4.8: "Catalog signing key
--    (Ed25519)... kid keyset of at least 2 keys in the app."
-- ============================================================================
-- ⛔ Deliberately empty by default (no INSERT here) — see
-- supabase/functions/_shared/catalog/classify-version.ts's own header and
-- docs/security/p3-money-path-requirements.md: the §4.8 key-rotation/
-- registration OPERATIONAL workflow and the import pipeline that would
-- ever produce a real signed manifest are both out of this round's scope.
-- This table's SHAPE is real; its CONTENTS are provisioned by that
-- future, not-yet-built workflow. `public_key_b64url` is a PUBLIC key
-- (Ed25519 verification key) — not a secret; no Vault involvement.
CREATE TABLE app.catalog_signing_key (
  kid text PRIMARY KEY,
  public_key_b64url text NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE app.catalog_signing_key IS
  'Ed25519 public-key registry for catalog manifest signatures (build plan §4.8). Empty by default in this migration — see supabase/functions/_shared/catalog/classify-version.ts and docs/security/p3-money-path-requirements.md for why: the key-rotation/registration workflow is out of P3c''s scope. Verification (supabase/functions/_shared/catalog/signature.ts) fails closed with no row present, which is the correct default for an environment with no keys provisioned yet.';

ALTER TABLE app.catalog_signing_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_signing_key FORCE ROW LEVEL SECURITY;
-- No policy for any client role — read only by service_role (bypasses
-- RLS), matching every other "nobody" table's convention (§4.4).
GRANT SELECT, INSERT, UPDATE, DELETE ON app.catalog_signing_key TO service_role;

-- ============================================================================
-- 2. app.checkin_token — the `checkin-token` Edge Function's own session
--    record (build plan §4.7.1a: "it must verify attestation, sign, and
--    record a jti"). A row here is what a later POST /v1/evidence fix's
--    `checkinTokenJti` (supabase/functions/_shared/evidence/derive-fix.ts)
--    resolves against, server-side, for challenge kind + attestation
--    grade — never anything the client claims directly.
-- ============================================================================
CREATE TABLE app.checkin_token (
  jti uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- ON DELETE CASCADE + DEFERRABLE INITIALLY DEFERRED: matches every
  -- other app-internal FK's contract (0014_hardening.sql §3) so
  -- delete_my_data's generic pass can delete app.checkin_challenge and
  -- app.checkin_token in EITHER order within one transaction — a
  -- checkin_token whose challenge is gone has no reason to survive it
  -- either way (H1, 09_delete_my_data.sql's own "every FK referencing a
  -- delete_row table is ON DELETE CASCADE/SET NULL... " check).
  challenge_id uuid NOT NULL REFERENCES app.checkin_challenge (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  user_id uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  -- Same H1 reasoning as challenge_id above — app.device.user_id is also
  -- delete_row classified.
  device_id uuid NOT NULL REFERENCES app.device (id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  facility_id text REFERENCES app.catalog_facility (id),
  attestation_grade app.attestation_grade NOT NULL,
  challenge_kind text NOT NULL CHECK (challenge_kind IN ('live', 'prefetched')),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (challenge_id)
);
CREATE INDEX checkin_token_user_idx ON app.checkin_token (user_id);
COMMENT ON COLUMN app.checkin_token.attestation_grade IS
  'Server-derived at issuance (checkin/token-handler.ts) — never client-supplied. This round grades every submission via the G3-08 "no token" rule (real App Attest/Play Integrity verification is out of P3c''s scope) — see that handler''s own header comment.';

ALTER TABLE app.checkin_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.checkin_token FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.checkin_token TO service_role;

-- ============================================================================
-- 3. private_definer wiring for app.checkin_token's generic delete_my_data
--    pass (0016's pattern, exactly — see that migration's own comments
--    for the full reasoning: SECURITY DEFINER private.delete_my_data runs
--    AS private_definer, which has no grant/policy on this brand-new
--    table until this migration adds one).
-- ============================================================================
GRANT DELETE, SELECT ON app.checkin_token TO private_definer;

CREATE POLICY pd_delete_checkin_token_user_id ON app.checkin_token FOR DELETE TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid);
CREATE POLICY pd_delete_checkin_token_user_id_r ON app.checkin_token FOR SELECT TO private_definer USING (user_id = nullif(current_setting('app.delete_my_data.target_user_id', true), '')::uuid);

-- Register in private.definer_policy_allowlist (0016) — same self
-- -granting CURRENT_USER pattern 0017 uses for its own follow-up
-- registrations (definer_policy_allowlist already has FORCE RLS on by
-- the time this migration runs).
GRANT INSERT, UPDATE ON private.definer_policy_allowlist TO CURRENT_USER;
CREATE POLICY current_user_seed_definer_policy_allowlist_0019 ON private.definer_policy_allowlist
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.definer_policy_allowlist (schema_name, table_name, policy_name, command, scoped, note) VALUES
  ('app', 'checkin_token', 'pd_delete_checkin_token_user_id', 'DELETE', true, 'delete_my_data''s generic pass (pii_retention_policy: checkin_token.user_id = delete_row)'),
  ('app', 'checkin_token', 'pd_delete_checkin_token_user_id_r', 'SELECT', true, 'row-visibility companion to pd_delete_checkin_token_user_id (DELETE ... WHERE needs SELECT-level visibility, confirmed empirically in 0016)');
UPDATE private.definer_policy_allowlist al
SET using_expr = pg_get_expr(pol.polqual, pol.polrelid),
    with_check_expr = pg_get_expr(pol.polwithcheck, pol.polrelid)
FROM pg_policy pol
JOIN pg_class cl ON cl.oid = pol.polrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE n.nspname = al.schema_name AND cl.relname = al.table_name AND pol.polname = al.policy_name
  AND al.table_name = 'checkin_token';
DROP POLICY current_user_seed_definer_policy_allowlist_0019 ON private.definer_policy_allowlist;
REVOKE INSERT, UPDATE ON private.definer_policy_allowlist FROM CURRENT_USER;

-- Declared PII retention (0014's private.pii_retention_policy — every
-- FK-to-auth.users column in `app` MUST be classified here, or
-- private.delete_my_data raises for any account with a row here).
-- 'delete_row': same reasoning as checkin_challenge's own row (0014) —
-- own, short-TTL session data.
--
-- 0014 could INSERT into this table directly because its own inserts ran
-- BEFORE that migration turned on FORCE ROW LEVEL SECURITY on it (later
-- in the same file). By 0019's turn, RLS has been force-enabled since
-- 0014 with no policy ever granting a plain INSERT — same self-granting
-- CURRENT_USER-scoped temporary-policy pattern 0017 uses for
-- private.definer_policy_allowlist (see that migration's own comments).
GRANT INSERT ON private.pii_retention_policy TO CURRENT_USER;
CREATE POLICY current_user_seed_pii_retention_policy_0019 ON private.pii_retention_policy
  FOR ALL TO CURRENT_USER USING (true) WITH CHECK (true);
INSERT INTO private.pii_retention_policy (schema_name, table_name, column_name, action, reason) VALUES
  ('app', 'checkin_token', 'user_id', 'delete_row', 'own, short-TTL checkin-session row (0019; same reasoning as checkin_challenge, line 829)');
DROP POLICY current_user_seed_pii_retention_policy_0019 ON private.pii_retention_policy;
REVOKE INSERT ON private.pii_retention_policy FROM CURRENT_USER;

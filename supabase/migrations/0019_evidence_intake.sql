-- 0019_evidence_intake.sql
-- P3c: the Edge Function layer for POST /v1/evidence (+ batch),
-- POST /v1/checkin/challenge and checkin-token
-- (docs/golf-trails/02-build-plan.md §4.7.1a inventory; §10 P3 M-staging).
-- Two new tables, both written only by service_role (Edge Functions),
-- matching the "nobody" client-read convention every other system/session
-- table in this schema already follows (checkin_challenge, device_reward_
-- ledger, etc. — build plan §4.4).
--
-- P3c gate round 2 (dbe1aaa): four schema fixes folded into this same
-- file, since 0019 is still unmerged (each cross-referenced to the gate
-- item it closes):
--   - app.evidence gets a REAL `local_date date` column (item 1: "a real
--     column is better than the summary->> form"). Backfill-free: no real
--     data exists yet (never deployed), and the table is empty at the
--     point in migration order this ALTER runs.
--   - app.checkin_challenge gets a REAL `kind` column (should-fix
--     "Challenge kind... don't infer it from TTL").
--   - app.checkin_token gets `consumed_at` (item 4: single-use per fix,
--     not "unlimited use for 15 minutes") and its `challenge_kind` column
--     is now populated from the challenge's own stored `kind`, not
--     inferred.
--   - grants narrowed per the gate's "Conditions on the BYPASSRLS design":
--     `catalog_signing_key` is SELECT-only for service_role;
--     `checkin_token` drops the DELETE grant for service_role (the
--     private_definer path already covers deletion via delete_my_data).

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
-- ⛔ FIX (P3c gate round 2, "Conditions on the BYPASSRLS design"):
-- SELECT-only. No Edge Function code this round ever writes a row here
-- (the §4.8 key-rotation/registration workflow that would is still out of
-- scope, per this table's own comment above) — a broader INSERT/UPDATE/
-- DELETE grant was unused privilege, narrowed to what the runtime path
-- actually needs.
GRANT SELECT ON app.catalog_signing_key TO service_role;

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
  -- ⛔ ADDED (P3c gate round 2, item 4): "consume a token for one evidence
  -- row or fix, not unlimited use for 15 minutes." NULL = unconsumed;
  -- Repo#checkinToken.consumeForFix's single atomic UPDATE sets this AND
  -- checks the challenge-window clamp AND the submitting device, all in
  -- one WHERE clause (see privileged.ts) — a token is single-use exactly
  -- like app.checkin_challenge.used_at already is.
  consumed_at timestamptz,
  UNIQUE (challenge_id)
);
CREATE INDEX checkin_token_user_idx ON app.checkin_token (user_id);
COMMENT ON COLUMN app.checkin_token.attestation_grade IS
  'Server-derived at issuance (checkin/token-handler.ts) — never client-supplied. This round grades every submission via the G3-08 "no token" rule (real App Attest/Play Integrity verification is out of P3c''s scope) — see that handler''s own header comment.';

ALTER TABLE app.checkin_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.checkin_token FORCE ROW LEVEL SECURITY;
-- ⛔ FIX (P3c gate round 2, "Conditions on the BYPASSRLS design"): no
-- DELETE grant for service_role — deletion of a checkin_token row is
-- exclusively the private_definer delete_my_data path (granted below) or
-- the ON DELETE CASCADE from its parent checkin_challenge; the runtime
-- Edge Function write path never deletes a row here directly. UPDATE is
-- kept: consumeForFix genuinely needs it (marking consumed_at) as part
-- of normal, non-deferrable request handling — narrowing this further to
-- a dedicated SECURITY DEFINER function is recorded in "Accepted
-- follow-ups" alongside the rest of the BYPASSRLS-narrowing plan, since
-- it does not change today's actual privilege boundary (service_role
-- already bypasses RLS and already holds broad grants across `app`).
GRANT SELECT, INSERT, UPDATE ON app.checkin_token TO service_role;

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

-- ============================================================================
-- 4. app.checkin_challenge gets a REAL `kind` column (should-fix, P3c gate
--    round 2: "store it as a column; don't infer it from TTL"). Existing
--    table from 0005_marker_entitlement.sql (gate-passed) — altered here,
--    not re-created, since 0019 is the current unmerged migration and
--    this column is part of the SAME checkin-session feature slice.
-- ============================================================================
ALTER TABLE app.checkin_challenge ADD COLUMN kind text NOT NULL DEFAULT 'live' CHECK (kind IN ('live', 'prefetched'));
ALTER TABLE app.checkin_challenge ALTER COLUMN kind DROP DEFAULT;
COMMENT ON COLUMN app.checkin_challenge.kind IS
  'Set at issuance by checkin/challenge-handler.ts (live vs. prefetched/offline) — a real column, not inferred from expires_at - issued_at width (P3c gate round 2 should-fix).';

-- ============================================================================
-- 5. app.evidence gets a REAL `local_date date` column (P3c gate round 2,
--    item 1: "a real column is better than the summary->> form, and the
--    coalesce(..., localDate) fail-open must go"). Existing table from
--    0003_player_core.sql (gate-passed) — altered here for the same
--    "0019 is the live unmerged migration for this feature" reason as
--    checkin_challenge.kind above.
--
--    ⛔ FIX (P3c gate round 3, should-fix): "ADD COLUMN local_date date
--    NOT NULL fails on a non-empty table. Add it nullable, backfill from
--    summary->>'localDate' (or capturedAt plus tz), then set NOT NULL."
--    This environment's own app.evidence is always empty at this point in
--    migration order (never deployed) — the original NOT-NULL-with-no-
--    default ALTER worked here for that reason alone — but 0019 is a
--    migration file, not a fact about THIS checkout only: once it is
--    applied against a real deploy that already has rows (even from an
--    EARLIER, non-P3c version of this same table), the bare NOT NULL
--    form fails outright. The nullable -> backfill -> NOT NULL sequence
--    below is correct regardless of how many rows exist at apply time.
-- ============================================================================
ALTER TABLE app.evidence ADD COLUMN local_date date;
-- Backfill priority: the row's own summary.localDate (what evidence/
-- handler.ts already wrote into summary for every pre-0019 row, per
-- 0003's own "incl. course_disambiguated_by, geometry_kind, local_date"
-- comment on that column), then started_at's own calendar date, then
-- today — the same "never leave a NULL a NOT NULL ALTER would reject"
-- discipline every other nullable-then-backfill migration in this schema
-- already uses.
UPDATE app.evidence
SET local_date = COALESCE((summary ->> 'localDate')::date, started_at::date, CURRENT_DATE)
WHERE local_date IS NULL;
ALTER TABLE app.evidence ALTER COLUMN local_date SET NOT NULL;
-- ⛔ FIX (P3c gate round 3, should-fix: "fix the 0019 column comment to
-- match reality"). The PRIOR comment said only "server-derived at intake"
-- without saying HOW — P3c gate round 3's own item 5 fix
-- (evidence/handler.ts) makes that precise and source-dependent: for a
-- FIX-BEARING submission (foreground_checkin/foreground_dwell) this is
-- computed from the fix's own capturedAt resolved into the FACILITY's
-- real IANA tz (app.catalog_facility.tz) — the client's OWN localDate
-- label is validated against that computed value and the request is
-- rejected (422 local_date_mismatch) on any mismatch, never silently
-- overridden. For a DATE-ONLY submission (self_report/health_workout,
-- which carry no client-controlled capturedAt to derive a date from at
-- all) the client's own label IS what is stored, after a window check
-- (facility-local today minus 30 days, plus 1 day — see handler.ts's own
-- SELF_REPORT_WINDOW_DAYS_BACK/FORWARD constants and their own comment
-- for why 30 specifically).
COMMENT ON COLUMN app.evidence.local_date IS
  'The evidence row''s own facility-local date. For a fix-bearing source (foreground_checkin/foreground_dwell) this is SERVER-COMPUTED from the fix''s own capturedAt resolved into the facility''s real tz -- the client''s own localDate label is validated against it and the submission is rejected on mismatch, never silently overridden (P3c gate round 3, item 5). For a date-only source (self_report/health_workout) the client''s own label is stored as-is, after a facility-local-today +-window check. A REAL column, not read out of summary jsonb: Repo#evidence.listForPlay (privileged.ts) filters on it directly, closing the P3c gate round 2 "day-2 evidence" bug (a fail-open coalesce(summary->>''localDate'', $queriedDate) made every prior row match every date queried, unboundedly, across every day).';
CREATE INDEX evidence_user_facility_localdate_idx ON app.evidence (user_id, facility_id, local_date);

-- ============================================================================
-- 7. app.evidence gets a REAL `input_hash text` column (P3c gate round 3,
--    blocking HIGH 1+2, "replay handling" — one fix covering both the
--    changed-replay bypass and the AT 3 regression). A canonical SHA-256
--    hash (hex) of the ENTIRE parsed, validated client submission
--    (evidence/handler.ts's own `computeInputHash`), stored once at
--    insert. Every later request that resolves to the SAME
--    (user_id, source, source_ref) is checked against THIS column,
--    BEFORE any side effect (token consumption, a fraud_signal, a rate-
--    limit hit, a device row) — an exact match returns the ALREADY-
--    PERSISTED outcome (idempotent replay, no new side effects at all,
--    closing the AT 3 regression where an identical retry saw its own
--    token already consumed and got a false 409); a mismatch is rejected
--    outright (409 evidence_conflict) before anything about the NEW,
--    different content is ever acted on (closing the changed-replay
--    bypass, where a replay under a different localDate/course skipped
--    the OLD content-comparison entirely because it queried a
--    listForPlay window the original row was never in).
--    Nullable-then-backfill-then-NOT-NULL for the SAME "a real deploy may
--    not have an empty table" reason as local_date above — pre-existing
--    rows (none in this environment) get a placeholder hash derived from
--    their own immutable source_ref, which is deterministic and unique
--    per row even though it is not a REAL hash of their original raw
--    submission (that raw submission was never captured for a row this
--    column predates); this only matters for a row from BEFORE this
--    column existed, and such a row is unreachable through
--    Repo#evidence.findExisting's own (user, source, source_ref) lookup
--    replaying it would use — that lookup already only ever finds a row
--    among the ones an actual client Might replay against.
-- ============================================================================
ALTER TABLE app.evidence ADD COLUMN input_hash text;
UPDATE app.evidence
SET input_hash = encode(digest(source_ref, 'sha256'), 'hex')
WHERE input_hash IS NULL;
ALTER TABLE app.evidence ALTER COLUMN input_hash SET NOT NULL;
COMMENT ON COLUMN app.evidence.input_hash IS
  'A canonical SHA-256 hash (hex) of the ENTIRE parsed, validated client submission that produced this row (evidence/handler.ts''s computeInputHash) -- compared against on every later request resolving to the SAME (user_id, source, source_ref) so a replay can be told apart from a content-changed resubmission under the same natural id, BEFORE any side effect runs (P3c gate round 3, blocking HIGH 1+2).';

-- ============================================================================
-- 6. app.checkin_challenge / app.checkin_token: `is_uuid_or_null`-shaped
--    guard N/A — deviceId validation moves to the request-shape layer
--    (P3c gate round 2, item 7: "validate deviceId as a UUID"); no schema
--    change needed since app.device.id is already `uuid` (a non-UUID
--    string was never persisted — it failed at the driver/parameter-typing
--    layer instead, surfacing as an unhandled 500 the request-shape fix
--    now catches before any query runs at all).
-- ============================================================================

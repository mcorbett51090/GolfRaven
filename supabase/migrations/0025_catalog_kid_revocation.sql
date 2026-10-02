-- 0025_catalog_kid_revocation.sql
-- P3e round 2 gate, M3: "Enforce revokedKids[] as a hard reject. Record
-- revocations without broadening the catalog_signing_key grant. A
-- separate private revocation table is fine."
--
-- `app.catalog_signing_key` stays SELECT-only for service_role (0019's own
-- "Conditions on the BYPASSRLS design" narrowing) — this migration does
-- NOT touch that grant. Instead a SEPARATE, append-only table records
-- every kid a verified, signed manifest's `revokedKids[]` has ever named.
-- A kid appears here at most once and is never un-revoked (INSERT-only
-- grant: no UPDATE, no DELETE) — a later manifest cannot quietly
-- resurrect a kid an earlier one revoked.
--
-- Readers (`ImporterRepo#catalog.getSigningKey`, `Repo#catalog.signingKey`,
-- privileged.ts) treat a key as revoked when EITHER
-- `catalog_signing_key.revoked_at` is set OR a row exists here.
--
-- Not personal data: no user_id, no PII — nothing for the delete/export
-- coverage lists (private.pii_*_policy) to classify.
CREATE TABLE app.catalog_kid_revocation (
  kid text PRIMARY KEY,
  -- The site version string (yyyymmdd-gitsha7) of the manifest that
  -- first named this kid in its revokedKids[] — audit trail only.
  first_revoked_in_catalog_version text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE app.catalog_kid_revocation IS
  'Append-only record of every signing kid a verified catalog manifest has ever listed in revokedKids[] (P3e round 2 gate M3). Exists so revocations are recorded WITHOUT broadening service_role''s deliberately SELECT-only grant on app.catalog_signing_key. INSERT-only for service_role; never updated or deleted.';

ALTER TABLE app.catalog_kid_revocation ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.catalog_kid_revocation FORCE ROW LEVEL SECURITY;
-- No policy for any client role — service_role bypasses RLS (same
-- "nobody" table convention as app.catalog_signing_key).
GRANT SELECT, INSERT ON app.catalog_kid_revocation TO service_role;

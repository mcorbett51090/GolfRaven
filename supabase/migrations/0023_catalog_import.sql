-- 0023_catalog_import.sql
-- P3e: the `import-catalog` Edge Function (pull + verify + ledger import,
-- build plan §3.3) plus `queued_catalog` draining (§3.3, P3 AT 8 / AT 15 /
-- G3-10). Migration numbering per this task's own constraint: P3e starts
-- at 0023 (0022 is reserved for a concurrent builder).
--
-- Scope, stated plainly (mirrors this codebase's own stub-marking
-- discipline — see catalog/classify-version.ts's header): this migration
-- widens `app.catalog_version` just enough for a REAL importer to record
-- the site's own signed version history (build plan §3.3: "the site
-- publishes a signed, append-only catalog/v1/versions.json... the import
-- records every version listed there, not only the current manifest").
-- It does NOT widen `catalog_facility`/`catalog_course`/`catalog_trail`/
-- etc. to the full §4.1 artifact shape — that remains the TODO 0002's own
-- header already named ("widen these tables to the full catalog artifact
-- shape when the import function is built... anything beyond that is
-- intentionally deferred"). This round's importer pulls and applies
-- `manifest.json` + `versions.json` (both signature-verified) and the
-- `id-ledger.json` shard (build plan line 823: "the full ledger... every
-- ID ever minted") — i.e. "ledger import" exactly as both the P1 and P3
-- scope entries name it ("pull + verify + ledger import"), not a full
-- directory/geometry import.

-- ============================================================================
-- 1. app.catalog_version: record the site's OWN string version
--    (`yyyymmdd-gitsha7`, tools/catalog/src/manifest.ts's
--    CatalogVersionSchema) alongside the existing internal `version int`
--    sequence.
--
--    ⛔ NULLABLE, not NOT NULL — deliberately. `version int` stays the
--    PRIMARY KEY, assigned by the IMPORTER as `max(version)+1` under an
--    advisory lock (privileged.ts's new `withSystemCatalogImport` section)
--    — NOT a `GENERATED ALWAYS AS IDENTITY` column — because two existing,
--    already-gated fixtures insert explicit `version` values with no
--    `site_version` at all: `supabase/tests/helpers.sql:39` (seeds
--    version=1 for the whole pgTAP matrix) and
--    `supabase/tests/integration/_helpers.ts#insertCatalogVersion` (used
--    by the AT 8/AT 15 skew-window tests). Making `site_version` NOT NULL
--    or `version` an identity column would break both on the next test
--    run. `UNIQUE` still holds — Postgres treats multiple NULLs as
--    distinct under a UNIQUE constraint, so any number of pre-existing
--    fixture rows with `site_version IS NULL` coexist fine with the
--    importer's own rows, which always supply a real, non-null value.
-- ============================================================================
ALTER TABLE app.catalog_version ADD COLUMN site_version text;
ALTER TABLE app.catalog_version ADD CONSTRAINT catalog_version_site_version_key UNIQUE (site_version);
COMMENT ON COLUMN app.catalog_version.site_version IS
  'The site''s own yyyymmdd-gitsha7 catalogVersion string (tools/catalog/src/manifest.ts CatalogVersionSchema) for a row the import-catalog Edge Function wrote. NULL for a pre-import-catalog test fixture row (supabase/tests/helpers.sql, supabase/tests/integration/_helpers.ts#insertCatalogVersion) — those predate this column and are never re-derived. UNIQUE (multiple NULLs allowed) so fixture rows coexist with real imported ones.';

-- `contract_version` stays NOT NULL (existing fixtures already supply a
-- literal, e.g. 'v1') — the importer synthesizes 'unknown' for a
-- historical versions.json entry that carries no contractVersion of its
-- own (only {version, publishedAt, kid, sha256} — see manifest.ts's
-- VersionEntrySchema) rather than leaving the column null or fabricating
-- a specific number it doesn't actually know. The CURRENT version (the
-- one manifest.json itself describes) gets the real
-- `String(manifest.contractVersion)`. Documented on the column so this
-- doesn't need re-discovering from the importer's own source comment.
COMMENT ON COLUMN app.catalog_version.contract_version IS
  'For the CURRENT version (the one manifest.json describes), the real contractVersion the manifest carries. For a HISTORICAL version.json entry (which carries no contractVersion field of its own — manifest.ts VersionEntrySchema), the importer stores the literal ''unknown'' rather than fabricate a number it cannot verify. Never NULL (existing pre-import-catalog fixtures already rely on that).';

-- ============================================================================
-- 2. No new tables, no new SECURITY DEFINER functions, no new grants.
--    `app.catalog_version` and `app.catalog_id_ledger` already get full
--    service_role DML from 0009_grants_revokes.sql's dynamic per-table
--    loop over every `app.*` table (it re-runs for every table that
--    exists AT THAT MIGRATION'S OWN apply time — both tables already
--    existed in 0002, well before 0009 — so nothing here needs a fresh
--    GRANT). `app.catalog_signing_key` deliberately STAYS SELECT-only for
--    service_role (0019's own "Conditions on the BYPASSRLS design"
--    narrowing) — this round's importer only READS it (to verify a
--    manifest/versions signature against an already-registered key); it
--    never writes a new key or a revocation. Applying a manifest's own
--    `revokedKids[]` to `app.catalog_signing_key.revoked_at` would need a
--    grant this migration deliberately does NOT add (task instruction:
--    "never broaden a grant to make code work") — recorded as a follow-up
--    in the P3e handback report, not implemented here. In THIS
--    environment `catalog_signing_key` ships empty (0019), so
--    `revokedKids[]` processing is a documented no-op regardless.
-- ============================================================================

-- 0012_storage.sql
-- build plan §4.4 "Storage" section (docs/golf-trails/02-build-plan.md:862-885).
-- "clients never touch Storage directly." Both buckets are created
-- `public = false` with no `storage.objects` policy for anon or
-- authenticated at all — RLS is enabled+forced on `storage.objects`
-- (supabase/tests/shim.sql for the local shape; a real Supabase project
-- already has RLS on it [unverified — training knowledge]), so zero
-- policies for those roles is "denied (no policy)" by construction.

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'receipts',
  'receipts',
  false,
  5 * 1024 * 1024, -- 5 MB (line 865: "rejects bodies > 5 MB")
  ARRAY['image/jpeg', 'image/png', 'image/heic'] -- line 865
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'exports',
  'exports',
  false,
  NULL,
  NULL
)
ON CONFLICT (id) DO NOTHING;

-- No `storage.objects` policy is created for either bucket, for any client
-- role (line 869-870, 877): "grant no select/insert/update/delete to anon
-- or authenticated" / "no storage.objects policy for any client role."
-- Only the receipt/review/settlement-export Edge Functions, running as
-- service_role through withOwnership(), reach these buckets (§4.7.1a).
--
-- TODO(build plan lines 878-881, A66): the 7-day `exports` object lifecycle
-- and the 90-day receipt-image deletion are either a native Storage
-- lifecycle rule (if the P3 week-1 spike finds one
-- [unverified — training knowledge]) or a scheduled `exports-purge` Edge
-- Function — both are out of this stage's scope (Edge Functions/Deno,
-- deploys). Nothing here implements the deletion; only the bucket shape.

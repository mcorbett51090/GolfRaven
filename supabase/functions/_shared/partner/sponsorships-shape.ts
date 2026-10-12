// supabase/functions/_shared/partner/sponsorships-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `sponsorships-admin` (docs/security/partner-auth-design.md 12, 30; slice S6, the Edge half of migration 0059), in the style of
// stock-shape.ts: unknown keys REJECTED, every value checked for its exact shape before any port is touched. Pure: no environment, no database, no logging.
//
//   GET  sponsorships           ?trailId=
//   POST sponsorships           { id?, sponsorOrgId, trailId, category, scope, attributionName, attributionAsset?, placementFee?, startsOn?, endsOn? }
//   POST sponsorships/approve   { id }

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { parseUuid } from "./invites-shape.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const CATEGORIES = new Set(["equipment", "apparel", "tourism", "other"]);
const SCOPES = new Set(["special_marker", "offers", "both"]);

function parseTrailId(v: unknown): string | null {
  return parseFacilityId(v);
}

function parseIsoDate(v: unknown): string | null {
  return typeof v === "string" && DATE_RE.test(v) ? v : null;
}

export function parseSponsorshipsQuery(url: string): ParseResult<{ readonly trailId: string }> {
  const q = parseReadQuery(url, new Set(["trailId"]));
  if (!q.ok) return q;
  const trailId = parseTrailId(q.value.get("trailId"));
  if (trailId === null) return { ok: false, issues: [{ path: "trailId", message: "must be a trail id" }] };
  return { ok: true, value: { trailId } };
}

export interface SponsorshipUpsertBody {
  readonly id: string | null;
  readonly sponsorOrgId: string;
  readonly trailId: string;
  readonly category: string;
  readonly scope: string;
  readonly attributionName: string;
  readonly attributionAsset: string | null;
  readonly placementFee: number | null;
  readonly startsOn: string | null;
  readonly endsOn: string | null;
}

export function parseSponsorshipUpsertBody(raw: unknown): ParseResult<SponsorshipUpsertBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(
    raw,
    new Set([
      "id",
      "sponsorOrgId",
      "trailId",
      "category",
      "scope",
      "attributionName",
      "attributionAsset",
      "placementFee",
      "startsOn",
      "endsOn",
    ]),
    "",
    issues,
  );
  let id: string | null = null;
  let idOk = true;
  if (raw.id !== undefined && raw.id !== null) {
    const u = parseUuid(raw.id);
    if (u === null) idOk = false;
    else id = u;
  }
  const sponsorOrgId = parseUuid(raw.sponsorOrgId);
  const trailId = parseTrailId(raw.trailId);
  const category = typeof raw.category === "string" && CATEGORIES.has(raw.category) ? raw.category : null;
  const scope = typeof raw.scope === "string" && SCOPES.has(raw.scope) ? raw.scope : null;
  const attributionName =
    typeof raw.attributionName === "string" && raw.attributionName.trim() !== "" && raw.attributionName.length <= 200
      ? raw.attributionName
      : null;
  let attributionAsset: string | null = null;
  let assetOk = true;
  if (raw.attributionAsset !== undefined && raw.attributionAsset !== null) {
    if (typeof raw.attributionAsset === "string" && raw.attributionAsset.length <= 500) attributionAsset = raw.attributionAsset;
    else assetOk = false;
  }
  let placementFee: number | null = null;
  let feeOk = true;
  if (raw.placementFee !== undefined && raw.placementFee !== null) {
    if (typeof raw.placementFee === "number" && Number.isFinite(raw.placementFee) && raw.placementFee >= 0) placementFee = raw.placementFee;
    else feeOk = false;
  }
  let startsOn: string | null = null;
  let startsOk = true;
  if (raw.startsOn !== undefined && raw.startsOn !== null) {
    const d = parseIsoDate(raw.startsOn);
    if (d === null) startsOk = false;
    else startsOn = d;
  }
  let endsOn: string | null = null;
  let endsOk = true;
  if (raw.endsOn !== undefined && raw.endsOn !== null) {
    const d = parseIsoDate(raw.endsOn);
    if (d === null) endsOk = false;
    else endsOn = d;
  }

  if (!idOk) issues.push({ path: "id", message: "must be a uuid or null" });
  if (sponsorOrgId === null) issues.push({ path: "sponsorOrgId", message: "must be a uuid" });
  if (trailId === null) issues.push({ path: "trailId", message: "must be a trail id" });
  if (category === null) issues.push({ path: "category", message: "must be equipment, apparel, tourism or other" });
  if (scope === null) issues.push({ path: "scope", message: "must be special_marker, offers or both" });
  if (attributionName === null) issues.push({ path: "attributionName", message: "must be non-empty text of at most 200 characters" });
  if (!assetOk) issues.push({ path: "attributionAsset", message: "must be text of at most 500 characters or null" });
  if (!feeOk) issues.push({ path: "placementFee", message: "must be a non-negative number or null" });
  if (!startsOk) issues.push({ path: "startsOn", message: "must be a YYYY-MM-DD date or null" });
  if (!endsOk) issues.push({ path: "endsOn", message: "must be a YYYY-MM-DD date or null" });

  if (issues.length > 0 || sponsorOrgId === null || trailId === null || category === null || scope === null || attributionName === null) {
    return { ok: false, issues };
  }
  return {
    ok: true,
    value: {
      id,
      sponsorOrgId,
      trailId,
      category,
      scope,
      attributionName,
      attributionAsset,
      placementFee,
      startsOn,
      endsOn,
    },
  };
}

export function parseSponsorshipIdBody(raw: unknown): ParseResult<{ readonly id: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["id"]), "", issues);
  const id = parseUuid(raw.id);
  if (id === null) issues.push({ path: "id", message: "must be a uuid" });
  if (issues.length > 0 || id === null) return { ok: false, issues };
  return { ok: true, value: { id } };
}

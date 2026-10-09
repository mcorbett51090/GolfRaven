// supabase/functions/_shared/partner/programme-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `programme-config` (docs/security/partner-auth-design.md 12, 30; slice S6, the Edge half of migration 0059), in the style of
// stock-shape.ts: unknown keys REJECTED, every value checked for its exact shape before any port is touched. Pure: no environment, no database, no logging.
//
//   GET  programme              ?trailId=
//   POST programme/trail        { trailId, status, markerSource, markerRequiresCompletion, ... }
//   POST programme/facility     { trailId, facilityId, participation, qrMode, ... }
//   GET  rollups/operator       ?trailId=
//   GET  rollups/sponsor        ?sponsorshipId=

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { parseUuid } from "./invites-shape.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const PROGRAMME_STATUSES = new Set(["off", "pilot", "live"]);
const MARKER_SOURCES = new Set(["any_purchase", "programme_marker"]);
const FUNDED_BY = new Set(["trail", "sponsor"]);
const FEE_MODELS = new Set(["flat", "per_redemption", "none"]);
const PARTICIPATIONS = new Set(["invited", "accepted", "declined", "left"]);
const CONNECTIVITIES = new Set(["ok", "weak", "none"]);
const QR_MODES = new Set(["rotating", "static_pin", "both"]);

function parseTrailId(v: unknown): string | null {
  // a trail id has the catalog id alphabet of a facility id
  return parseFacilityId(v);
}

function parseIsoDate(v: unknown): string | null {
  return typeof v === "string" && DATE_RE.test(v) ? v : null;
}

function parseOptionalIsoDate(v: unknown): string | null | undefined {
  if (v === undefined) return undefined;
  if (v === null) return null;
  return parseIsoDate(v);
}

function parseOptionalString(v: unknown, max: number): string | null | undefined | false {
  if (v === undefined) return undefined;
  if (v === null) return null;
  return typeof v === "string" && v.length <= max ? v : false;
}

function parseOptionalUuid(v: unknown): string | null | undefined | false {
  if (v === undefined) return undefined;
  if (v === null) return null;
  const u = parseUuid(v);
  return u === null ? false : u;
}

function parseOptionalNumber(v: unknown): number | null | undefined | false {
  if (v === undefined) return undefined;
  if (v === null) return null;
  return typeof v === "number" && Number.isFinite(v) ? v : false;
}

function parseOptionalBool(v: unknown): boolean | null | undefined | false {
  if (v === undefined) return undefined;
  if (v === null) return null;
  return typeof v === "boolean" ? v : false;
}

export function parseTrailQuery(url: string): ParseResult<{ readonly trailId: string }> {
  const q = parseReadQuery(url, new Set(["trailId"]));
  if (!q.ok) return q;
  const trailId = parseTrailId(q.value.get("trailId"));
  if (trailId === null) return { ok: false, issues: [{ path: "trailId", message: "must be a trail id" }] };
  return { ok: true, value: { trailId } };
}

export function parseSponsorshipQuery(url: string): ParseResult<{ readonly sponsorshipId: string }> {
  const q = parseReadQuery(url, new Set(["sponsorshipId"]));
  if (!q.ok) return q;
  const sponsorshipId = parseUuid(q.value.get("sponsorshipId"));
  if (sponsorshipId === null) return { ok: false, issues: [{ path: "sponsorshipId", message: "must be a uuid" }] };
  return { ok: true, value: { sponsorshipId } };
}

export interface TrailProgrammeUpsertBody {
  readonly trailId: string;
  readonly status: string;
  readonly markerSource: string;
  readonly markerRequiresCompletion: boolean;
  readonly specialMarkerFundedBy: string | null;
  readonly specialMarkerLowThreshold: number;
  readonly webPlayerFlow: boolean;
  readonly specialMarkerSku: string | null;
  readonly specialMarkerSponsorshipId: string | null;
  readonly feeModel: string | null;
  readonly feeAmount: number | null;
  readonly startsOn: string | null;
  readonly endsOn: string | null;
}

export function parseTrailProgrammeUpsertBody(raw: unknown): ParseResult<TrailProgrammeUpsertBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(
    raw,
    new Set([
      "trailId",
      "status",
      "markerSource",
      "markerRequiresCompletion",
      "specialMarkerFundedBy",
      "specialMarkerLowThreshold",
      "webPlayerFlow",
      "specialMarkerSku",
      "specialMarkerSponsorshipId",
      "feeModel",
      "feeAmount",
      "startsOn",
      "endsOn",
    ]),
    "",
    issues,
  );
  const trailId = parseTrailId(raw.trailId);
  const status = typeof raw.status === "string" && PROGRAMME_STATUSES.has(raw.status) ? raw.status : null;
  const markerSource = typeof raw.markerSource === "string" && MARKER_SOURCES.has(raw.markerSource) ? raw.markerSource : null;
  const markerRequiresCompletion = typeof raw.markerRequiresCompletion === "boolean" ? raw.markerRequiresCompletion : null;
  const specialMarkerLowThreshold =
    typeof raw.specialMarkerLowThreshold === "number" && Number.isSafeInteger(raw.specialMarkerLowThreshold) &&
      raw.specialMarkerLowThreshold >= 0 && raw.specialMarkerLowThreshold <= 100000
      ? raw.specialMarkerLowThreshold
      : null;
  const webPlayerFlow = typeof raw.webPlayerFlow === "boolean" ? raw.webPlayerFlow : null;

  let specialMarkerFundedBy: string | null = null;
  let fundedOk = true;
  if (raw.specialMarkerFundedBy !== undefined && raw.specialMarkerFundedBy !== null) {
    if (typeof raw.specialMarkerFundedBy === "string" && FUNDED_BY.has(raw.specialMarkerFundedBy)) specialMarkerFundedBy = raw.specialMarkerFundedBy;
    else fundedOk = false;
  }

  const sku = parseOptionalString(raw.specialMarkerSku, 120);
  const sponsorshipId = parseOptionalUuid(raw.specialMarkerSponsorshipId);
  let feeModel: string | null = null;
  let feeModelOk = true;
  if (raw.feeModel !== undefined && raw.feeModel !== null) {
    if (typeof raw.feeModel === "string" && FEE_MODELS.has(raw.feeModel)) feeModel = raw.feeModel;
    else feeModelOk = false;
  }
  const feeAmount = parseOptionalNumber(raw.feeAmount);
  const startsOn = parseOptionalIsoDate(raw.startsOn);
  const endsOn = parseOptionalIsoDate(raw.endsOn);

  if (trailId === null) issues.push({ path: "trailId", message: "must be a trail id" });
  if (status === null) issues.push({ path: "status", message: "must be off, pilot or live" });
  if (markerSource === null) issues.push({ path: "markerSource", message: "must be any_purchase or programme_marker" });
  if (markerRequiresCompletion === null) issues.push({ path: "markerRequiresCompletion", message: "must be a boolean" });
  if (!fundedOk) issues.push({ path: "specialMarkerFundedBy", message: "must be trail, sponsor or null" });
  if (specialMarkerLowThreshold === null) issues.push({ path: "specialMarkerLowThreshold", message: "must be a whole number from 0 to 100000" });
  if (webPlayerFlow === null) issues.push({ path: "webPlayerFlow", message: "must be a boolean" });
  if (sku === false) issues.push({ path: "specialMarkerSku", message: "must be text of at most 120 characters or null" });
  if (sponsorshipId === false) issues.push({ path: "specialMarkerSponsorshipId", message: "must be a uuid or null" });
  if (!feeModelOk) issues.push({ path: "feeModel", message: "must be flat, per_redemption, none or null" });
  if (feeAmount === false) issues.push({ path: "feeAmount", message: "must be a finite number or null" });
  if (startsOn === undefined) {
    /* optional absent → null */
  } else if (raw.startsOn !== undefined && raw.startsOn !== null && startsOn === null) {
    issues.push({ path: "startsOn", message: "must be a YYYY-MM-DD date or null" });
  }
  if (endsOn === undefined) {
    /* optional */
  } else if (raw.endsOn !== undefined && raw.endsOn !== null && endsOn === null) {
    issues.push({ path: "endsOn", message: "must be a YYYY-MM-DD date or null" });
  }

  if (
    issues.length > 0 || trailId === null || status === null || markerSource === null || markerRequiresCompletion === null ||
    specialMarkerLowThreshold === null || webPlayerFlow === null || sku === false || sponsorshipId === false || feeAmount === false
  ) {
    return { ok: false, issues };
  }
  return {
    ok: true,
    value: {
      trailId,
      status,
      markerSource,
      markerRequiresCompletion,
      specialMarkerFundedBy,
      specialMarkerLowThreshold,
      webPlayerFlow,
      specialMarkerSku: sku === undefined ? null : sku,
      specialMarkerSponsorshipId: sponsorshipId === undefined ? null : sponsorshipId,
      feeModel,
      feeAmount: feeAmount === undefined ? null : feeAmount,
      startsOn: startsOn === undefined ? null : startsOn,
      endsOn: endsOn === undefined ? null : endsOn,
    },
  };
}

export interface FacilityProgrammeUpsertBody {
  readonly trailId: string;
  readonly facilityId: string;
  readonly participation: string;
  readonly stocksMarkers: boolean | null;
  readonly holdsSpecialMarker: boolean | null;
  readonly connectivity: string | null;
  readonly staffNetwork: boolean | null;
  readonly wifiNote: string | null;
  readonly qrMode: string;
}

export function parseFacilityProgrammeUpsertBody(raw: unknown): ParseResult<FacilityProgrammeUpsertBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(
    raw,
    new Set([
      "trailId",
      "facilityId",
      "participation",
      "stocksMarkers",
      "holdsSpecialMarker",
      "connectivity",
      "staffNetwork",
      "wifiNote",
      "qrMode",
    ]),
    "",
    issues,
  );
  const trailId = parseTrailId(raw.trailId);
  const facilityId = parseFacilityId(raw.facilityId);
  const participation = typeof raw.participation === "string" && PARTICIPATIONS.has(raw.participation) ? raw.participation : null;
  const qrMode = typeof raw.qrMode === "string" && QR_MODES.has(raw.qrMode) ? raw.qrMode : null;
  const stocksMarkers = parseOptionalBool(raw.stocksMarkers);
  const holdsSpecialMarker = parseOptionalBool(raw.holdsSpecialMarker);
  const staffNetwork = parseOptionalBool(raw.staffNetwork);
  let connectivity: string | null = null;
  let connectivityOk = true;
  if (raw.connectivity !== undefined && raw.connectivity !== null) {
    if (typeof raw.connectivity === "string" && CONNECTIVITIES.has(raw.connectivity)) connectivity = raw.connectivity;
    else connectivityOk = false;
  }
  const wifiNote = parseOptionalString(raw.wifiNote, 500);

  if (trailId === null) issues.push({ path: "trailId", message: "must be a trail id" });
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (participation === null) issues.push({ path: "participation", message: "must be invited, accepted, declined or left" });
  if (qrMode === null) issues.push({ path: "qrMode", message: "must be rotating, static_pin or both" });
  if (stocksMarkers === false) issues.push({ path: "stocksMarkers", message: "must be a boolean or null" });
  if (holdsSpecialMarker === false) issues.push({ path: "holdsSpecialMarker", message: "must be a boolean or null" });
  if (staffNetwork === false) issues.push({ path: "staffNetwork", message: "must be a boolean or null" });
  if (!connectivityOk) issues.push({ path: "connectivity", message: "must be ok, weak, none or null" });
  if (wifiNote === false) issues.push({ path: "wifiNote", message: "must be text of at most 500 characters or null" });

  if (
    issues.length > 0 || trailId === null || facilityId === null || participation === null || qrMode === null ||
    stocksMarkers === false || holdsSpecialMarker === false || staffNetwork === false || wifiNote === false
  ) {
    return { ok: false, issues };
  }
  return {
    ok: true,
    value: {
      trailId,
      facilityId,
      participation,
      stocksMarkers: stocksMarkers === undefined ? null : stocksMarkers,
      holdsSpecialMarker: holdsSpecialMarker === undefined ? null : holdsSpecialMarker,
      connectivity,
      staffNetwork: staffNetwork === undefined ? null : staffNetwork,
      wifiNote: wifiNote === undefined ? null : wifiNote,
      qrMode,
    },
  };
}

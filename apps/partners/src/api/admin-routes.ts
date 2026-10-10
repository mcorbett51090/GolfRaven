/**
 * Typed wrappers for the S7d/S7 manager/operator/admin screens: `programme-config`, `offers-admin`,
 * `sponsorships-admin`, `partner-review` and `settlement-export` (docs/security/partner-auth-design.md 30, 31, 32, 33).
 *
 * Every call goes through `PartnerApi.call`, so the bearer, the function allow-list and the closed
 * route/query shapes apply. Response bodies are checked field-by-field: a malformed answer is
 * `malformed_response`, never trusted into the UI. Settlement signed URLs are returned to the UI only;
 * callers must never log the token.
 */

import type { PartnerApi } from "./client";
import { PartnerApiError } from "./errors";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isString = (v: unknown): v is string => typeof v === "string";
const isStringOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";
const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

function malformed(): never {
  throw new PartnerApiError("malformed_response");
}

export interface TrailProgramme {
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

export interface FacilityProgramme {
  readonly facilityId: string;
  readonly participation: string;
  readonly stocksMarkers: boolean | null;
  readonly holdsSpecialMarker: boolean | null;
  readonly connectivity: string | null;
  readonly staffNetwork: boolean | null;
  readonly wifiNote: string | null;
  readonly qrMode: string;
  readonly pinEpoch: number;
}

export interface TrailProgrammeUpsert {
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

export interface FacilityProgrammeUpsert {
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

export interface OfferAdmin {
  readonly id: string;
  readonly termsId: string;
  readonly trailId: string;
  readonly facilityId: string;
  readonly eligibility: unknown;
  readonly funder: string;
  readonly sponsorshipId: string | null;
  readonly budgetCap: number;
  readonly budgetUsed: number;
  readonly budgetReserved: number;
  readonly maxRedemptions: number | null;
  readonly faceValue: number;
  readonly validFrom: string;
  readonly validTo: string;
  readonly status: string;
}

export interface OfferUpsert {
  readonly id: string | null;
  readonly trailId: string;
  readonly facilityId: string;
  readonly eligibility: unknown;
  readonly funder: string;
  readonly sponsorshipId: string | null;
  readonly budgetCap: number;
  readonly maxRedemptions: number | null;
  readonly faceValue: number;
  readonly validFrom: string;
  readonly validTo: string;
}

export interface Sponsorship {
  readonly id: string;
  readonly sponsorOrgId: string;
  readonly trailId: string;
  readonly category: string;
  readonly scope: string;
  readonly attributionName: string;
  readonly attributionAsset: string | null;
  readonly placementFee: number | null;
  readonly startsOn: string | null;
  readonly endsOn: string | null;
  readonly operatorApprovedAt: string | null;
  readonly status: string;
}

export interface SponsorshipUpsert {
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

export interface ReviewQueueItem {
  readonly kind: string;
  readonly id: string;
  readonly subjectTable: string;
  readonly subjectId: string;
  readonly userId: string;
  readonly handle: string;
  readonly facilityId: string | null;
  readonly trailId: string | null;
  readonly holdDetail: string | null;
  readonly reservedAmount: number | null;
  readonly heldAt: string;
  readonly slaBreached: boolean;
  readonly reviewKind: string | null;
}

export interface ReviewSla {
  readonly heldOfferCodes: number;
  readonly heldEntitlements: number;
  readonly openReviewItems: number;
  readonly slaBreachedRewards: number;
  readonly slaBreachedReviewItems: number;
  readonly slaHours: number;
}

export interface OperatorRollup {
  readonly trailId: string;
  readonly month: string;
  readonly metric: string;
  readonly value: number;
  readonly cohortN: number;
}

export interface SponsorRollup {
  readonly sponsorshipId: string;
  readonly month: string;
  readonly metric: string;
  readonly value: number;
  readonly cohortN: number;
}

function parseTrail(data: unknown): TrailProgramme {
  if (
    !isObject(data) || !isString(data["trailId"]) || !isString(data["status"]) || !isString(data["markerSource"]) ||
    !isBool(data["markerRequiresCompletion"]) || !isStringOrNull(data["specialMarkerFundedBy"] ?? null) ||
    !isNum(data["specialMarkerLowThreshold"]) || !isBool(data["webPlayerFlow"]) ||
    !isStringOrNull(data["specialMarkerSku"] ?? null) || !isStringOrNull(data["specialMarkerSponsorshipId"] ?? null) ||
    !isStringOrNull(data["feeModel"] ?? null) || !(data["feeAmount"] === null || isNum(data["feeAmount"])) ||
    !isStringOrNull(data["startsOn"] ?? null) || !isStringOrNull(data["endsOn"] ?? null)
  ) malformed();
  return {
    trailId: data["trailId"],
    status: data["status"],
    markerSource: data["markerSource"],
    markerRequiresCompletion: data["markerRequiresCompletion"],
    specialMarkerFundedBy: (data["specialMarkerFundedBy"] as string | null) ?? null,
    specialMarkerLowThreshold: data["specialMarkerLowThreshold"],
    webPlayerFlow: data["webPlayerFlow"],
    specialMarkerSku: (data["specialMarkerSku"] as string | null) ?? null,
    specialMarkerSponsorshipId: (data["specialMarkerSponsorshipId"] as string | null) ?? null,
    feeModel: (data["feeModel"] as string | null) ?? null,
    feeAmount: (data["feeAmount"] as number | null) ?? null,
    startsOn: (data["startsOn"] as string | null) ?? null,
    endsOn: (data["endsOn"] as string | null) ?? null,
  };
}

function parseFacility(data: unknown): FacilityProgramme {
  if (
    !isObject(data) || !isString(data["facilityId"]) || !isString(data["participation"]) ||
    !(data["stocksMarkers"] === null || isBool(data["stocksMarkers"])) ||
    !(data["holdsSpecialMarker"] === null || isBool(data["holdsSpecialMarker"])) ||
    !isStringOrNull(data["connectivity"] ?? null) ||
    !(data["staffNetwork"] === null || isBool(data["staffNetwork"])) ||
    !isStringOrNull(data["wifiNote"] ?? null) || !isString(data["qrMode"]) || !isNum(data["pinEpoch"])
  ) malformed();
  return {
    facilityId: data["facilityId"],
    participation: data["participation"],
    stocksMarkers: (data["stocksMarkers"] as boolean | null) ?? null,
    holdsSpecialMarker: (data["holdsSpecialMarker"] as boolean | null) ?? null,
    connectivity: (data["connectivity"] as string | null) ?? null,
    staffNetwork: (data["staffNetwork"] as boolean | null) ?? null,
    wifiNote: (data["wifiNote"] as string | null) ?? null,
    qrMode: data["qrMode"],
    pinEpoch: data["pinEpoch"],
  };
}

function parseOffer(data: unknown): OfferAdmin {
  if (
    !isObject(data) || !isString(data["id"]) || !isString(data["termsId"]) || !isString(data["trailId"]) ||
    !isString(data["facilityId"]) || data["eligibility"] === undefined || !isString(data["funder"]) ||
    !isStringOrNull(data["sponsorshipId"] ?? null) || !isNum(data["budgetCap"]) || !isNum(data["budgetUsed"]) ||
    !isNum(data["budgetReserved"]) || !(data["maxRedemptions"] === null || isNum(data["maxRedemptions"])) ||
    !isNum(data["faceValue"]) || !isString(data["validFrom"]) || !isString(data["validTo"]) || !isString(data["status"])
  ) malformed();
  return {
    id: data["id"],
    termsId: data["termsId"],
    trailId: data["trailId"],
    facilityId: data["facilityId"],
    eligibility: data["eligibility"],
    funder: data["funder"],
    sponsorshipId: (data["sponsorshipId"] as string | null) ?? null,
    budgetCap: data["budgetCap"],
    budgetUsed: data["budgetUsed"],
    budgetReserved: data["budgetReserved"],
    maxRedemptions: (data["maxRedemptions"] as number | null) ?? null,
    faceValue: data["faceValue"],
    validFrom: data["validFrom"],
    validTo: data["validTo"],
    status: data["status"],
  };
}

function parseSponsorship(data: unknown): Sponsorship {
  if (
    !isObject(data) || !isString(data["id"]) || !isString(data["sponsorOrgId"]) || !isString(data["trailId"]) ||
    !isString(data["category"]) || !isString(data["scope"]) || !isString(data["attributionName"]) ||
    !isStringOrNull(data["attributionAsset"] ?? null) || !(data["placementFee"] === null || isNum(data["placementFee"])) ||
    !isStringOrNull(data["startsOn"] ?? null) || !isStringOrNull(data["endsOn"] ?? null) ||
    !isStringOrNull(data["operatorApprovedAt"] ?? null) || !isString(data["status"])
  ) malformed();
  return {
    id: data["id"],
    sponsorOrgId: data["sponsorOrgId"],
    trailId: data["trailId"],
    category: data["category"],
    scope: data["scope"],
    attributionName: data["attributionName"],
    attributionAsset: (data["attributionAsset"] as string | null) ?? null,
    placementFee: (data["placementFee"] as number | null) ?? null,
    startsOn: (data["startsOn"] as string | null) ?? null,
    endsOn: (data["endsOn"] as string | null) ?? null,
    operatorApprovedAt: (data["operatorApprovedAt"] as string | null) ?? null,
    status: data["status"],
  };
}

function parseReviewItem(data: unknown): ReviewQueueItem {
  if (
    !isObject(data) || !isString(data["kind"]) || !isString(data["id"]) || !isString(data["subjectTable"]) ||
    !isString(data["subjectId"]) || !isString(data["userId"]) || !isString(data["handle"]) ||
    !isStringOrNull(data["facilityId"] ?? null) || !isStringOrNull(data["trailId"] ?? null) ||
    !isStringOrNull(data["holdDetail"] ?? null) || !(data["reservedAmount"] === null || isNum(data["reservedAmount"])) ||
    !isString(data["heldAt"]) || !isBool(data["slaBreached"]) || !isStringOrNull(data["reviewKind"] ?? null)
  ) malformed();
  return {
    kind: data["kind"],
    id: data["id"],
    subjectTable: data["subjectTable"],
    subjectId: data["subjectId"],
    userId: data["userId"],
    handle: data["handle"],
    facilityId: (data["facilityId"] as string | null) ?? null,
    trailId: (data["trailId"] as string | null) ?? null,
    holdDetail: (data["holdDetail"] as string | null) ?? null,
    reservedAmount: (data["reservedAmount"] as number | null) ?? null,
    heldAt: data["heldAt"],
    slaBreached: data["slaBreached"],
    reviewKind: (data["reviewKind"] as string | null) ?? null,
  };
}

function parseOk(data: unknown): void {
  if (!isObject(data) || data["ok"] !== true) malformed();
}

function parseId(data: unknown): string {
  if (!isObject(data) || !isString(data["id"])) malformed();
  return data["id"];
}

export async function getProgramme(api: PartnerApi, trailId: string): Promise<{ trail: TrailProgramme; facilities: readonly FacilityProgramme[] }> {
  const data = await api.call("GET", "programme-config", "programme", undefined, { trailId });
  if (!isObject(data) || !Array.isArray(data["facilities"])) malformed();
  return { trail: parseTrail(data["trail"]), facilities: data["facilities"].map(parseFacility) };
}

export async function postTrailProgramme(api: PartnerApi, body: TrailProgrammeUpsert): Promise<void> {
  parseOk(await api.call("POST", "programme-config", "programme/trail", body));
}

export async function postFacilityProgramme(api: PartnerApi, body: FacilityProgrammeUpsert): Promise<void> {
  parseOk(await api.call("POST", "programme-config", "programme/facility", body));
}

export async function getOperatorRollups(api: PartnerApi, trailId: string): Promise<readonly OperatorRollup[]> {
  const data = await api.call("GET", "programme-config", "rollups/operator", undefined, { trailId });
  if (!isObject(data) || !Array.isArray(data["rollups"])) malformed();
  return data["rollups"].map((r) => {
    if (!isObject(r) || !isString(r["trailId"]) || !isString(r["month"]) || !isString(r["metric"]) || !isNum(r["value"]) || !isNum(r["cohortN"])) malformed();
    return { trailId: r["trailId"], month: r["month"], metric: r["metric"], value: r["value"], cohortN: r["cohortN"] };
  });
}

export async function getSponsorRollups(api: PartnerApi, sponsorshipId: string): Promise<readonly SponsorRollup[]> {
  const data = await api.call("GET", "programme-config", "rollups/sponsor", undefined, { sponsorshipId });
  if (!isObject(data) || !Array.isArray(data["rollups"])) malformed();
  return data["rollups"].map((r) => {
    if (!isObject(r) || !isString(r["sponsorshipId"]) || !isString(r["month"]) || !isString(r["metric"]) || !isNum(r["value"]) || !isNum(r["cohortN"])) malformed();
    return { sponsorshipId: r["sponsorshipId"], month: r["month"], metric: r["metric"], value: r["value"], cohortN: r["cohortN"] };
  });
}

export async function getOffers(api: PartnerApi, trailId: string): Promise<readonly OfferAdmin[]> {
  const data = await api.call("GET", "offers-admin", "offers", undefined, { trailId });
  if (!isObject(data) || !Array.isArray(data["offers"])) malformed();
  return data["offers"].map(parseOffer);
}

export async function postOffer(api: PartnerApi, body: OfferUpsert): Promise<string> {
  return parseId(await api.call("POST", "offers-admin", "offers", body));
}

export async function postOfferApprove(api: PartnerApi, id: string): Promise<void> {
  parseOk(await api.call("POST", "offers-admin", "offers/approve", { id }));
}

export async function postOfferEnd(api: PartnerApi, id: string): Promise<void> {
  parseOk(await api.call("POST", "offers-admin", "offers/end", { id }));
}

export async function getSponsorships(api: PartnerApi, trailId: string): Promise<readonly Sponsorship[]> {
  const data = await api.call("GET", "sponsorships-admin", "sponsorships", undefined, { trailId });
  if (!isObject(data) || !Array.isArray(data["sponsorships"])) malformed();
  return data["sponsorships"].map(parseSponsorship);
}

export async function postSponsorship(api: PartnerApi, body: SponsorshipUpsert): Promise<string> {
  return parseId(await api.call("POST", "sponsorships-admin", "sponsorships", body));
}

export async function postSponsorshipApprove(api: PartnerApi, id: string): Promise<void> {
  parseOk(await api.call("POST", "sponsorships-admin", "sponsorships/approve", { id }));
}

export async function getReviewQueue(api: PartnerApi): Promise<readonly ReviewQueueItem[]> {
  const data = await api.call("GET", "partner-review", "queue");
  if (!isObject(data) || !Array.isArray(data["items"])) malformed();
  return data["items"].map(parseReviewItem);
}

export async function getReviewSla(api: PartnerApi): Promise<ReviewSla> {
  const data = await api.call("GET", "partner-review", "sla");
  if (
    !isObject(data) || !isNum(data["heldOfferCodes"]) || !isNum(data["heldEntitlements"]) ||
    !isNum(data["openReviewItems"]) || !isNum(data["slaBreachedRewards"]) ||
    !isNum(data["slaBreachedReviewItems"]) || !isNum(data["slaHours"])
  ) malformed();
  return {
    heldOfferCodes: data["heldOfferCodes"],
    heldEntitlements: data["heldEntitlements"],
    openReviewItems: data["openReviewItems"],
    slaBreachedRewards: data["slaBreachedRewards"],
    slaBreachedReviewItems: data["slaBreachedReviewItems"],
    slaHours: data["slaHours"],
  };
}

export async function postResolveOfferCode(api: PartnerApi, id: string, approve: boolean): Promise<{ state: string }> {
  const data = await api.call("POST", "partner-review", "resolve/offer-code", { id, approve });
  if (!isObject(data) || !isString(data["state"])) malformed();
  return { state: data["state"] };
}

export async function postResolveEntitlement(api: PartnerApi, id: string, approve: boolean): Promise<{ state: string }> {
  const data = await api.call("POST", "partner-review", "resolve/entitlement", { id, approve });
  if (!isObject(data) || !isString(data["state"])) malformed();
  return { state: data["state"] };
}

/** §48/§49: approve or reject an open `receipt_cross_user_match` review item (A3 admin). */
export async function postResolveReceiptCrossUser(api: PartnerApi, id: string, approve: boolean): Promise<{ state: string }> {
  const data = await api.call("POST", "partner-review", "resolve/receipt-cross-user", { id, approve });
  if (!isObject(data) || !isString(data["state"])) malformed();
  return { state: data["state"] };
}

/** Opaque label + short-lived signed URL for a receipt image. Never log `signedUrl`. */
export interface ReceiptPreviewImage {
  readonly label: "subject" | "matched";
  readonly signedUrl: string;
}

/** §51: preview images for an open `receipt_cross_user_match` (A0 admin). Never log signed URLs. */
export interface ReceiptCrossUserPreview {
  readonly images: readonly ReceiptPreviewImage[];
  readonly expiresAt: string;
}

/** §51: short-lived signed URLs for subject (+ matched) receipt images on an open review item. */
export async function getReceiptCrossUserPreview(api: PartnerApi, id: string): Promise<ReceiptCrossUserPreview> {
  const data = await api.call("GET", "partner-review", "preview/receipt-cross-user", undefined, { id });
  if (!isObject(data) || !Array.isArray(data["images"]) || !isString(data["expiresAt"])) malformed();
  const images: ReceiptPreviewImage[] = [];
  for (const raw of data["images"]) {
    if (!isObject(raw) || (raw["label"] !== "subject" && raw["label"] !== "matched") || !isString(raw["signedUrl"])) malformed();
    images.push({ label: raw["label"], signedUrl: raw["signedUrl"] });
  }
  if (images.length === 0) malformed();
  return { images, expiresAt: data["expiresAt"] };
}

export interface SettlementLine {
  readonly facilityId: string;
  readonly month: string;
  readonly funder: string;
  readonly sponsorshipId: string | null;
  readonly redemptions: number;
  readonly offlineCount: number;
  readonly unconfirmedCount: number;
  readonly faceValueTotal: number;
}

/** AT(17): time-limited signed URL for the CSV. Never log `signedUrl`. */
export interface SettlementExport {
  readonly path: string;
  readonly signedUrl: string;
  readonly expiresAt: string;
  readonly lines: readonly SettlementLine[];
}

function parseSettlementLine(data: unknown): SettlementLine {
  if (
    !isObject(data) || !isString(data["facilityId"]) || !isString(data["month"]) || !isString(data["funder"]) ||
    !isStringOrNull(data["sponsorshipId"] ?? null) || !isNum(data["redemptions"]) || !isNum(data["offlineCount"]) ||
    !isNum(data["unconfirmedCount"]) || !isNum(data["faceValueTotal"])
  ) malformed();
  return {
    facilityId: data["facilityId"],
    month: data["month"],
    funder: data["funder"],
    sponsorshipId: (data["sponsorshipId"] as string | null) ?? null,
    redemptions: data["redemptions"],
    offlineCount: data["offlineCount"],
    unconfirmedCount: data["unconfirmedCount"],
    faceValueTotal: data["faceValueTotal"],
  };
}

export async function postSettlementExport(api: PartnerApi, trailId: string, month: string): Promise<SettlementExport> {
  const data = await api.call("POST", "settlement-export", "export", { trailId, month });
  if (
    !isObject(data) || !isString(data["path"]) || !isString(data["signedUrl"]) || !isString(data["expiresAt"]) ||
    !Array.isArray(data["lines"])
  ) malformed();
  return {
    path: data["path"],
    signedUrl: data["signedUrl"],
    expiresAt: data["expiresAt"],
    lines: data["lines"].map(parseSettlementLine),
  };
}

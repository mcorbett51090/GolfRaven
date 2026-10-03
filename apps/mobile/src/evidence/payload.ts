/**
 * The evidence payload: what an outbox item's `payload` holds for a play, and how it becomes the request body `POST /v1/evidence` (and one
 * element of `POST /v1/evidence/batch`) accepts.
 *
 * The wire shape is the server's `parseEvidenceSubmission` (`supabase/functions/_shared/evidence/request-shape.ts`): a strict whitelist (an unknown key
 * is a 400), `courseId` OMITTED rather than null, `deviceId` a UUID, `catalogVersion` a `yyyymmdd-gitsha7` site version, `localDate` a real calendar
 * date, fixes with `fixId` / `checkinTokenJti` as unpadded base64url. NOTHING that is a trust fact is ever sent: no attestation grade, no
 * verification tier, no challenge kind, no `holes`; the server derives all of them (the `checkinTokenJti` only NAMES a token the server minted).
 * `test/evidence-wire.test.ts` compares the bodies built here with the `request` recorded next to each real handler answer.
 *
 * What is stored vs derived at send time:
 *  - stored in `item.payload` (this file's `EvidencePayload`): the submission template, the device id, the facility, the local date, and one
 *    `FixChallenge` per fix (the check-in challenge consumed for it, or why there is none);
 *  - taken from the ITEM at send time: `courseId` and `catalogVersion` (a 422 `catalog_stale` re-match rewrites them, `outbox/machine.ts`).
 */
import { z } from "zod";
import type { JsonValue, OutboxItem } from "../outbox";

export const EVIDENCE_PAYLOAD_VERSION = 1;

const ID_LIKE = /^[A-Za-z0-9_.:-]{1,128}$/;
const B64URL_ID = /^[A-Za-z0-9_-]{1,128}$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const SITE_VERSION = /^\d{8}-[0-9a-f]{7}$/;
const BASE64_STD = /^[A-Za-z0-9+/]{1,256}={0,2}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MIN_EPOCH_MS = Date.UTC(2020, 0, 1);
const MAX_EPOCH_MS = Date.UTC(2100, 0, 1);

function isRealDate(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, m, d] = s.split("-").map(Number) as [number, number, number];
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

const epochMs = z.number().finite().gte(MIN_EPOCH_MS).lt(MAX_EPOCH_MS);

export const fixTemplateSchema = z
  .object({
    fixId: z.string().regex(B64URL_ID),
    lat: z.number().finite().gte(-90).lte(90),
    lng: z.number().finite().gte(-180).lte(180),
    accuracyMeters: z.number().finite().gte(0),
    capturedAt: epochMs,
    simulated: z.boolean(),
    foreground: z.boolean(),
    fromApp: z.boolean(),
  })
  .strict();
export type FixTemplate = z.infer<typeof fixTemplateSchema>;

export const submissionTemplateSchema = z.discriminatedUnion("source", [
  z.object({ source: z.literal("foreground_checkin"), fix: fixTemplateSchema }).strict(),
  z.object({ source: z.literal("foreground_dwell"), checkinFix: fixTemplateSchema, checkoutFix: fixTemplateSchema, apartMinutes: z.number().finite().gte(0) }).strict(),
  z.object({ source: z.literal("self_report") }).strict(),
  z.object({ source: z.literal("health_workout") }).strict(),
]);
export type SubmissionTemplate = z.infer<typeof submissionTemplateSchema>;

/** Why a fix carries no challenge. Every one of these means the server grades the fix with no co-signal and applies the x0.6 device-weight
 * penalty (build plan §4.5, §7.6 FM-10); `evidencePenaltyApplies` reports it so the item says so. */
export const NO_CHALLENGE_REASONS = [
  "none_available", // no unexpired, unconsumed prefetched challenge was left at check-in time, and no live one could be had
  "expired", // a challenge was consumed offline but had expired before the item was sent: never used
  "unusable", // the server refused to redeem it (already used / expired / not ours): never used
] as const;
export type NoChallengeReason = (typeof NO_CHALLENGE_REASONS)[number];

export const fixChallengeSchema = z.discriminatedUnion("state", [
  z.object({ state: z.literal("none"), reason: z.enum(NO_CHALLENGE_REASONS) }).strict(),
  /** Consumed locally for this fix (it can never be given to another), not yet redeemed at `checkin-token`. */
  z
    .object({
      state: z.literal("held"),
      challengeId: z.string().min(1).max(128),
      nonce: z.string().regex(/^[A-Za-z0-9_-]{1,512}$/),
      kind: z.enum(["live", "prefetched"]),
      expiresAt: z.number().finite(),
    })
    .strict(),
  /** Redeemed: the server minted `jti` for it. The body of every later send carries this exact jti (a replay with different content is a 409). */
  z
    .object({
      state: z.literal("redeemed"),
      challengeId: z.string().min(1).max(128),
      kind: z.enum(["live", "prefetched"]),
      jti: z.string().regex(B64URL_ID),
      grade: z.enum(["attested", "unattestable", "failed"]),
    })
    .strict(),
]);
export type FixChallenge = z.infer<typeof fixChallengeSchema>;

export const manifestSigSchema = z
  .object({
    catalogVersion: z.string().regex(SITE_VERSION),
    kid: z.string().regex(ID_LIKE),
    contractVersion: z.number().int().gte(0),
    sig: z.string().regex(BASE64_STD).refine((s) => s.length % 4 === 0),
    manifestSha: z.string().regex(SHA256_HEX),
  })
  .strict();

export const evidencePayloadSchema = z
  .object({
    v: z.literal(EVIDENCE_PAYLOAD_VERSION),
    /** `import`: a historic import (first Health sync, a file batch): sent through `POST /v1/evidence/batch`, date-only sources only. */
    origin: z.enum(["live", "import"]),
    deviceId: z.string().regex(UUID),
    facilityId: z.string().regex(ID_LIKE),
    localDate: z.string().refine(isRealDate),
    manifestSig: manifestSigSchema.optional(),
    submission: submissionTemplateSchema,
    /** One entry per fix of the submission, keyed by `fixId`. Date-only sources have none. */
    challenges: z.record(z.string(), fixChallengeSchema),
  })
  .strict()
  .superRefine((p, ctx) => {
    const fixIds = fixesOf(p.submission).map((f) => f.fixId);
    const keys = Object.keys(p.challenges);
    if (keys.length !== fixIds.length || !fixIds.every((id) => id in p.challenges)) ctx.addIssue({ code: "custom", message: "challenges must have exactly one entry per fix" });
    if (p.origin === "import" && fixIds.length > 0) ctx.addIssue({ code: "custom", message: "a historic import carries no fixes (date-only sources)" });
  });
export type EvidencePayload = z.infer<typeof evidencePayloadSchema>;

export function fixesOf(s: SubmissionTemplate): FixTemplate[] {
  if (s.source === "foreground_checkin") return [s.fix];
  if (s.source === "foreground_dwell") return [s.checkinFix, s.checkoutFix];
  return [];
}

export type ParsedPayload = { ok: true; payload: EvidencePayload } | { ok: false; message: string };

/** Strict: anything that is not exactly an `EvidencePayload` is not sent (the item becomes a local `unsendable` dead letter). */
export function parseEvidencePayload(raw: JsonValue | unknown): ParsedPayload {
  const r = evidencePayloadSchema.safeParse(raw);
  if (r.success) return { ok: true, payload: r.data };
  const first = r.error.issues[0];
  return { ok: false, message: `invalid evidence payload${first ? ` at ${first.path.join(".") || "(root)"}: ${first.message}` : ""}` };
}

/** The same payload as the JSON value an outbox item stores. */
export function toJsonValue(p: EvidencePayload): JsonValue {
  return JSON.parse(JSON.stringify(p)) as JsonValue;
}

/** True when some fix of the item will be sent with no challenge: the server then applies the x0.6 penalty (§4.5). */
export function evidencePenaltyApplies(p: EvidencePayload): boolean {
  return Object.values(p.challenges).some((c) => c.state === "none");
}

/** The instant the play happened, for ordering batches (FM-28: sorted by event time). A fix-bearing play: its first fix; a date-only play:
 * midnight UTC of its local date. */
export function eventTimeMs(p: EvidencePayload): number {
  const first = fixesOf(p.submission)[0];
  return first ? first.capturedAt : Date.parse(`${p.localDate}T00:00:00Z`);
}

export type WireFix = FixTemplate & { checkinTokenJti?: string };

export type WireBody = Record<string, unknown>;

export type BuildBody = { ok: true; body: WireBody } | { ok: false; code: "invalid_payload" | "no_course" | "no_catalog_version"; message: string };

function wireFix(f: FixTemplate, c: FixChallenge | undefined): WireFix {
  const out: WireFix = { fixId: f.fixId, lat: f.lat, lng: f.lng, accuracyMeters: f.accuracyMeters, capturedAt: f.capturedAt, simulated: f.simulated, foreground: f.foreground, fromApp: f.fromApp };
  if (c && c.state === "redeemed") out.checkinTokenJti = c.jti;
  return out;
}

/** The request body for one item. `item.courseId` / `item.catalogVersion` are used (not the payload's): a re-match rewrites them. A
 * `manifestSig` is sent only when it is for the version being sent (the server rebuilds the signed statement from the submission's own
 * `catalogVersion`, so a signature for another version could only be refused). A fix whose challenge is `held` (not yet redeemed) is a bug of the
 * caller, not something to send quietly without its challenge: the send step redeems first (`evidence/send.ts`). */
export function buildEvidenceBody(item: Pick<OutboxItem, "courseId" | "catalogVersion">, p: EvidencePayload): BuildBody {
  if (item.courseId === null || !ID_LIKE.test(item.courseId)) return { ok: false, code: "no_course", message: "the item has no course id" };
  if (item.catalogVersion === null || !SITE_VERSION.test(item.catalogVersion)) return { ok: false, code: "no_catalog_version", message: "the item has no site catalog version" };
  const common: WireBody = { deviceId: p.deviceId, facilityId: p.facilityId, courseId: item.courseId, localDate: p.localDate, catalogVersion: item.catalogVersion };
  if (p.manifestSig && p.manifestSig.catalogVersion === item.catalogVersion) {
    common["manifestSig"] = { kid: p.manifestSig.kid, contractVersion: p.manifestSig.contractVersion, sig: p.manifestSig.sig, manifestSha: p.manifestSig.manifestSha };
  }
  const s = p.submission;
  for (const f of fixesOf(s)) {
    if (p.challenges[f.fixId]?.state === "held") return { ok: false, code: "invalid_payload", message: "a fix still holds an unredeemed challenge" };
  }
  switch (s.source) {
    case "foreground_checkin":
      return { ok: true, body: { source: s.source, ...common, fix: wireFix(s.fix, p.challenges[s.fix.fixId]) } };
    case "foreground_dwell":
      return {
        ok: true,
        body: {
          source: s.source,
          ...common,
          checkinFix: wireFix(s.checkinFix, p.challenges[s.checkinFix.fixId]),
          checkoutFix: wireFix(s.checkoutFix, p.challenges[s.checkoutFix.fixId]),
          apartMinutes: s.apartMinutes,
        },
      };
    case "self_report":
    case "health_workout":
      return { ok: true, body: { source: s.source, ...common } };
  }
}

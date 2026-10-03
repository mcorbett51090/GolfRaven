/** Helpers for the evidence-lane tests: payloads built from the REAL request bodies the server handlers were recorded with. */
import { createItem, type OutboxItem } from "../../src/outbox";
import { EVIDENCE_PAYLOAD_VERSION, toJsonValue, type EvidencePayload, type FixChallenge } from "../../src/evidence";
import { recordedRequest } from "./edge-fixtures";

type Wire = Record<string, unknown>;
type WireFix = { fixId: string; checkinTokenJti?: string } & Record<string, unknown>;

function strip(f: WireFix): { template: Record<string, unknown>; jti?: string } {
  const { checkinTokenJti, ...template } = f;
  return { template, ...(checkinTokenJti !== undefined ? { jti: checkinTokenJti } : {}) };
}

/** The payload that `buildEvidenceBody` turns back into `wire` (a body the server accepted). */
export function payloadFromWire(wire: Wire, over: Partial<EvidencePayload> = {}): EvidencePayload {
  const challenges: Record<string, FixChallenge> = {};
  const fixFrom = (f: WireFix): Record<string, unknown> => {
    const { template, jti } = strip(f);
    challenges[f.fixId] = jti !== undefined ? { state: "redeemed", challengeId: `chal_for_${f.fixId}`, kind: "prefetched", jti, grade: "unattestable" } : { state: "none", reason: "none_available" };
    return template;
  };
  const source = wire["source"] as string;
  let submission: Record<string, unknown>;
  if (source === "foreground_checkin") submission = { source, fix: fixFrom(wire["fix"] as WireFix) };
  else if (source === "foreground_dwell") submission = { source, checkinFix: fixFrom(wire["checkinFix"] as WireFix), checkoutFix: fixFrom(wire["checkoutFix"] as WireFix), apartMinutes: wire["apartMinutes"] };
  else submission = { source };
  const sig = wire["manifestSig"] as { kid: string; contractVersion: number; sig: string; manifestSha: string } | undefined;
  return {
    v: EVIDENCE_PAYLOAD_VERSION,
    origin: "live",
    deviceId: wire["deviceId"] as string,
    facilityId: wire["facilityId"] as string,
    localDate: wire["localDate"] as string,
    ...(sig ? { manifestSig: { catalogVersion: wire["catalogVersion"] as string, ...sig } } : {}),
    submission: submission as EvidencePayload["submission"],
    challenges,
    ...over,
  };
}

export const T0 = 1_800_000_000_000;

/** An outbox item for `payload`, listed on `courseId` / `catalogVersion` taken from the wire body. */
export function itemFor(wire: Wire, n: number, owner = "user-a", payloadOver: Partial<EvidencePayload> = {}, at = T0 + n * 1000): OutboxItem {
  const payload = payloadFromWire(wire, payloadOver);
  return createItem(
    { id: `ev${n}`, sourceRef: `ref${n}`, ownerUserId: owner, courseId: wire["courseId"] as string, catalogVersion: wire["catalogVersion"] as string, payload: toJsonValue(payload) },
    at,
  );
}

export const wireOf = (name: string): Wire => recordedRequest(name);

// supabase/tests/unit/marker-scan-world.ts
//
// The shared fixture of the marker-scan unit tests AND the mobile edge-contract recorder (apps/mobile/scripts/record-edge-contract.rec.ts): a server `FakeState` with a facility whose polygon
// contains the fix, a printed QR, a programme, the two Ed25519 verification keys, and helpers that seed what POST /v1/checkin/challenge + /token leave in the database (a challenge window
// containing the fix, a token redeemed against it) and a rotating token the staff lane would have issued. Test-only; nothing under supabase/functions imports it.

import { createHash } from "node:crypto";
import { parseMarkerScanBody, type MarkerScanBody } from "../../functions/_shared/course-qr/request-shape.ts";
import { FAKE_DEVICE_ID, makeFakeRepo, makeFakeState, type FakeState } from "./fake-repo.ts";
import { markerScanState } from "./fake-marker-scan-repo.ts";
import { generateTestSigningKey, mintRotatingToken, type TestSigningKey } from "./course-qr-test-keys.ts";

export const UID = "user-a";
export const FAC = "fac_x";
export const sha256Hex = async (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
export const deps = { sha256Hex };

export interface World {
  state: FakeState;
  ms: ReturnType<typeof markerScanState>;
  rotKey: TestSigningKey;
  prtKey: TestSigningKey;
  repo: ReturnType<typeof makeFakeRepo>;
  nowMs: number;
}

export async function world(over: { programme?: string[] | null; rotKey?: TestSigningKey; prtKey?: TestSigningKey } = {}): Promise<World> {
  const state = makeFakeState();
  const ms = markerScanState(state);
  const rotKey = over.rotKey ?? (await generateTestSigningKey());
  const prtKey = over.prtKey ?? (await generateTestSigningKey());
  ms.keys.set("rotating_token:rk1", { publicKeyB64Url: rotKey.publicKeyB64Url, revoked: false });
  ms.keys.set("printed_qr:pq1", { publicKeyB64Url: prtKey.publicKeyB64Url, revoked: false });
  ms.facilityQr.set(FAC, "pq1");
  ms.pins.set(FAC, "4321");
  if (over.programme !== null) ms.programme.set(FAC, over.programme ?? ["trl_t"]);
  // a facility whose polygon contains the fix: the default for the happy path
  state.facilityMatches.set(FAC, { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true });
  return { state, ms, rotKey, prtKey, repo: makeFakeRepo(state, UID), nowMs: state.now.getTime() };
}

let jtiCounter = 0;
/** What POST /v1/checkin/challenge + /v1/checkin/token leave in the database: a challenge window containing the fix, and the token redeemed against it. */
export function seedToken(w: World, o: { grade?: "attested" | "unattestable" | "failed"; kind?: "live" | "prefetched"; facilityId?: string | null; deviceId?: string; uid?: string; challengeIssuedAgoMs?: number } = {}): string {
  jtiCounter += 1;
  const jti = `jti${jtiCounter}`;
  const uid = o.uid ?? UID;
  w.state.challenges.set(`ch${jtiCounter}`, {
    id: `ch${jtiCounter}`,
    userId: uid,
    staffUserId: null,
    deviceId: o.deviceId ?? FAKE_DEVICE_ID,
    facilityId: o.facilityId === undefined ? FAC : o.facilityId,
    nonceHash: "x",
    kind: o.kind ?? "prefetched",
    issuedAt: new Date(w.nowMs - (o.challengeIssuedAgoMs ?? 3_600_000)).toISOString(),
    expiresAt: new Date(w.nowMs + 3_600_000).toISOString(),
    usedAt: null,
  });
  w.state.checkinTokens.set(jti, {
    jti,
    userId: uid,
    deviceId: o.deviceId ?? FAKE_DEVICE_ID,
    facilityId: o.facilityId === undefined ? FAC : o.facilityId,
    attestationGrade: o.grade ?? "attested",
    challengeKind: o.kind ?? "prefetched",
    challengeId: `ch${jtiCounter}`,
    expiresAt: new Date(w.nowMs + 900_000).toISOString(),
    issuedAt: new Date(w.nowMs - 60_000).toISOString(),
    consumedAt: null,
  });
  return jti;
}

let fixCounter = 0;
export function fixAt(w: World, offsetMs = -10_000, over: Record<string, unknown> = {}) {
  fixCounter += 1;
  return { fixId: `fixid${fixCounter}`, lat: 36.1, lng: -86.8, accuracyMeters: 8, capturedAt: w.nowMs + offsetMs, simulated: false, foreground: true, fromApp: true, ...over };
}

export function body(o: Record<string, unknown>): MarkerScanBody {
  const parsed = parseMarkerScanBody({ facilityId: FAC, ...o });
  if (!parsed.ok) throw new Error(`test body invalid: ${JSON.stringify(parsed.issues)}`);
  return parsed.value;
}

export async function seedRotating(w: World, o: { iatOffsetSec?: number; facilityId?: string; kid?: string; key?: TestSigningKey; nonce?: Uint8Array } = {}) {
  const iat = Math.floor(w.nowMs / 1000) + (o.iatOffsetSec ?? -5);
  const m = await mintRotatingToken({ key: o.key ?? w.rotKey, kid: o.kid ?? "rk1", facilityId: o.facilityId ?? FAC, iat, ...(o.nonce ? { nonce: o.nonce } : {}) });
  const hash = createHash("sha256").update(Buffer.from(m.nonce)).digest("hex");
  w.ms.tokens.set(hash, { facilityId: FAC, issuedAtMs: iat * 1000, used: false });
  return { token: m.token, hash };
}

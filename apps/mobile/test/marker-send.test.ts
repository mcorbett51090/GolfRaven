import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../src/api/errors";
import type { CheckinTokenResult } from "../src/api/types";
import { AttestationDeferred } from "../src/attest";
import {
  MARKER_COSIGNAL_RETRY_MS,
  MemoryMarkerCosignalStore,
  drainMarkerCoSignals,
  sendMarkerCoSignal,
  type MarkerCosignal,
} from "../src/marker";

const JTI = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"; // b64url-ish id
const NOW = 1_700_000_000_000;

function token(grade: CheckinTokenResult["attestationGrade"] = "attested"): CheckinTokenResult {
  return { jti: JTI, expiresAt: new Date(NOW + 900_000).toISOString(), attestationGrade: grade };
}

function heldRecord(over: Partial<MarkerCosignal> = {}): MarkerCosignal {
  return {
    id: "rec1",
    ownerUserId: "user-a",
    facilityId: "fac_x",
    catalogVersion: "20251010-abcdef0",
    deviceId: "dev1",
    fix: {
      fixId: "fix1",
      lat: 45.5,
      lng: -73.5,
      accuracyMeters: 10,
      capturedAt: NOW - 60_000,
      simulated: false,
      foreground: true,
      fromApp: true,
    },
    challenge: {
      state: "held",
      challengeId: "ch1",
      nonce: "nonce_value_1",
      kind: "prefetched",
      expiresAt: NOW + 3_600_000,
    },
    createdAt: NOW - 60_000,
    ...over,
  };
}

function okResult() {
  return {
    outcome: "pending" as const,
    facilityId: "fac_x",
    localDate: null,
    cosignal: "counted" as const,
    purchases: [],
  };
}

describe("sendMarkerCoSignal", () => {
  it("redeems a held challenge, persists jti, POSTs scanMarker without qr, then deletes", async () => {
    const store = new MemoryMarkerCosignalStore();
    const record = heldRecord();
    await store.insert(record);
    const redeem = vi.fn(async () => token("attested"));
    const scanMarker = vi.fn(async (req: unknown) => {
      expect(req).toEqual({
        facilityId: "fac_x",
        deviceId: "dev1",
        fix: record.fix,
        jti: JTI,
      });
      expect(req).not.toHaveProperty("qr");
      return okResult();
    });
    const out = await sendMarkerCoSignal(
      { now: () => NOW, redeem, scan: { scanMarker }, store },
      record,
      { userId: "user-a", accessToken: "t" },
    );
    expect(out).toEqual({ kind: "sent", result: okResult() });
    expect(redeem).toHaveBeenCalledOnce();
    expect(scanMarker).toHaveBeenCalledOnce();
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("retries no_pending_purchase within 7 days and keeps the redeemed record", async () => {
    const store = new MemoryMarkerCosignalStore();
    const record = heldRecord();
    await store.insert(record);
    const redeem = vi.fn(async () => token("unattestable"));
    const scanMarker = vi.fn(async () => {
      throw new ApiError({ kind: "rejected", status: 422, code: "no_pending_purchase" });
    });
    const out = await sendMarkerCoSignal(
      { now: () => NOW, redeem, scan: { scanMarker }, store },
      record,
      { userId: "user-a", accessToken: "t" },
    );
    expect(out).toEqual({ kind: "retry", reason: "no_pending_purchase", code: "no_pending_purchase" });
    const left = await store.listByOwner("user-a");
    expect(left).toHaveLength(1);
    expect(left[0]?.challenge).toMatchObject({ state: "redeemed", jti: JTI });
  });

  it("drops past the 7-day retry bound", async () => {
    const store = new MemoryMarkerCosignalStore();
    const record = heldRecord({
      fix: { ...heldRecord().fix, capturedAt: NOW - MARKER_COSIGNAL_RETRY_MS - 1 },
    });
    await store.insert(record);
    const out = await sendMarkerCoSignal(
      {
        now: () => NOW,
        redeem: vi.fn(),
        scan: { scanMarker: vi.fn() },
        store,
      },
      record,
      { userId: "user-a", accessToken: "t" },
    );
    expect(out).toEqual({ kind: "dropped", reason: "past_retry" });
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("keeps the row on transport failure after redeem", async () => {
    const store = new MemoryMarkerCosignalStore();
    const record = heldRecord();
    await store.insert(record);
    const out = await sendMarkerCoSignal(
      {
        now: () => NOW,
        redeem: async () => token("attested"),
        scan: {
          scanMarker: async () => {
            throw new ApiError({ kind: "network", message: "offline" });
          },
        },
        store,
      },
      record,
      { userId: "user-a", accessToken: "t" },
    );
    expect(out.kind).toBe("retry");
    expect((await store.listByOwner("user-a"))[0]?.challenge).toMatchObject({ state: "redeemed", jti: JTI });
  });

  it("defers when attestation is deferred", async () => {
    const store = new MemoryMarkerCosignalStore();
    const record = heldRecord();
    await store.insert(record);
    const out = await sendMarkerCoSignal(
      {
        now: () => NOW,
        redeem: async () => {
          throw new AttestationDeferred("no_key");
        },
        scan: { scanMarker: vi.fn() },
        store,
      },
      record,
      { userId: "user-a", accessToken: "t" },
    );
    expect(out).toMatchObject({ kind: "retry", reason: "attestation_deferred" });
    expect((await store.listByOwner("user-a"))[0]?.challenge).toMatchObject({ state: "held", attestDeferrals: 1 });
  });
});

describe("drainMarkerCoSignals", () => {
  it("skips when signed out; sends when signed in", async () => {
    const store = new MemoryMarkerCosignalStore();
    await store.insert(heldRecord());
    expect(
      await drainMarkerCoSignals({
        now: () => NOW,
        redeem: vi.fn(),
        scan: { scanMarker: vi.fn() },
        store,
        currentUserId: () => null,
        accessTokenFor: async () => "t",
      }),
    ).toEqual([]);
    const scanMarker = vi.fn(async () => okResult());
    const outs = await drainMarkerCoSignals({
      now: () => NOW,
      redeem: async () => token("attested"),
      scan: { scanMarker },
      store,
      currentUserId: () => "user-a",
      accessTokenFor: async () => "t",
    });
    expect(outs).toHaveLength(1);
    expect(outs[0]?.kind).toBe("sent");
    expect(scanMarker).toHaveBeenCalledOnce();
  });
});

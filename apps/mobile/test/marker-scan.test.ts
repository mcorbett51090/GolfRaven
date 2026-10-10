import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../src/api/errors";
import type { CheckinTokenResult } from "../src/api/types";
import { scanMarkerFromLink, type MarkerScanDeps } from "../src/marker";
import { DEVICE, NOW0, entryOf, facility, makeRig, rawFix } from "./support/checkin-rig";

const TOKEN = "aa.bb.cc";
const SIG86 = "A".repeat(86);
const JTI = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const E = entryOf(facility());

function token(): CheckinTokenResult {
  return { jti: JTI, expiresAt: new Date(NOW0 + 900_000).toISOString(), attestationGrade: "attested" };
}

describe("scanMarkerFromLink", () => {
  function setup(over: Partial<MarkerScanDeps> = {}) {
    const rig = makeRig();
    const scanMarker = vi.fn(async () => ({
      outcome: "credited" as const,
      facilityId: "fac_x",
      localDate: "2026-10-10",
      cosignal: "counted" as const,
      purchases: [],
    }));
    const deps: MarkerScanDeps = {
      enabled: true,
      location: rig.location,
      currentUserId: () => rig.who.user,
      accessTokenFor: async () => "t",
      challenges: rig.challenges,
      redeem: async () => token(),
      scan: { scanMarker },
      deviceId: async () => DEVICE,
      newFixId: () => "fix1",
      now: () => rig.clock.now,
      ...over,
    };
    return { rig, deps, scanMarker };
  }

  it("refuses while disabled or signed out", async () => {
    const { deps } = setup();
    expect(await scanMarkerFromLink({ ...deps, enabled: false }, { entry: E, link: `https://golfraven.app/q/m#${TOKEN}` })).toEqual({ kind: "disabled" });
    expect(await scanMarkerFromLink({ ...deps, currentUserId: () => null }, { entry: E, link: `https://golfraven.app/q/m#${TOKEN}` })).toEqual({ kind: "signed_out" });
  });

  it("posts rotating qr + fix + jti when at the facility (live challenge)", async () => {
    const { rig, deps, scanMarker } = setup();
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000) }];
    const out = await scanMarkerFromLink(deps, { entry: E, link: `https://golfraven.app/q/m#${TOKEN}` });
    expect(out.kind).toBe("scanned");
    expect(scanMarker).toHaveBeenCalledOnce();
    expect(scanMarker.mock.calls[0]?.[0]).toMatchObject({
      facilityId: "fac_x",
      qr: { variant: "rotating", token: TOKEN },
      deviceId: DEVICE,
      jti: "jti_live1",
    });
  });

  it("falls back to a prefetched challenge when live is unavailable", async () => {
    const { rig, deps, scanMarker } = setup();
    rig.api.online = false;
    await rig.seedPool(10, NOW0 - 3_600_000);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000) }];
    const out = await scanMarkerFromLink(deps, { entry: E, link: `https://golfraven.app/q/m#${TOKEN}` });
    expect(out.kind).toBe("scanned");
    expect(scanMarker.mock.calls[0]?.[0]).toMatchObject({ jti: JTI, qr: { variant: "rotating", token: TOKEN } });
  });

  it("requires a 4-digit PIN for printed QR and checks the facility slug", async () => {
    const { rig, deps, scanMarker } = setup();
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000) }];
    const link = `https://golfraven.app/q/f/${E.facility.slug}#kid1.${SIG86}`;
    expect(await scanMarkerFromLink(deps, { entry: E, link })).toEqual({ kind: "need_pin" });
    expect(await scanMarkerFromLink(deps, { entry: E, link, pin: "12" })).toEqual({ kind: "invalid_pin" });
    const wrong = entryOf({ ...facility(), slug: "other-club" });
    expect(await scanMarkerFromLink(deps, { entry: wrong, link, pin: "1234" })).toEqual({ kind: "wrong_facility" });
    const out = await scanMarkerFromLink(deps, { entry: E, link, pin: "1234" });
    expect(out.kind).toBe("scanned");
    expect(scanMarker.mock.calls.at(-1)?.[0]).toMatchObject({
      qr: { variant: "static_pin", kid: "kid1", sig: SIG86, pin: "1234" },
    });
  });

  it("maps server refusals", async () => {
    const { rig, deps } = setup({
      scan: {
        scanMarker: async () => {
          throw new ApiError({ kind: "rejected", status: 422, code: "invalid_pin" });
        },
      },
    });
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000) }];
    expect(await scanMarkerFromLink(deps, { entry: E, link: `https://golfraven.app/q/m#${TOKEN}` })).toEqual({
      kind: "rejected",
      code: "invalid_pin",
      status: 422,
    });
  });
});

/** P4.2c: the `expo-location` adapter (`src/checkin/expo-location.ts`) over a mocked native module: what each call maps to, which native functions it uses, and that nothing is asked for when only a status is read. */
import { beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({
  getForegroundPermissionsAsync: vi.fn(),
  requestForegroundPermissionsAsync: vi.fn(),
  hasServicesEnabledAsync: vi.fn(),
  getCurrentPositionAsync: vi.fn(),
  // anything of the background half that is touched fails the test loudly
  requestBackgroundPermissionsAsync: vi.fn(() => {
    throw new Error("background permission requested");
  }),
  startLocationUpdatesAsync: vi.fn(() => {
    throw new Error("background updates started");
  }),
  startGeofencingAsync: vi.fn(() => {
    throw new Error("geofencing started");
  }),
  watchPositionAsync: vi.fn(() => {
    throw new Error("position watch started");
  }),
}));

vi.mock("expo-location", () => ({
  ...native,
  PermissionStatus: { GRANTED: "granted", DENIED: "denied", UNDETERMINED: "undetermined" },
  Accuracy: { Lowest: 1, Low: 2, Balanced: 3, High: 4, Highest: 5, BestForNavigation: 6 },
}));

import { createExpoLocationPort } from "../src/checkin/expo-location";

const resp = (o: Partial<{ granted: boolean; status: string; canAskAgain: boolean; android: { accuracy: string }; ios: { scope: string; accuracy: string } }>) => ({ granted: false, status: "denied", canAskAgain: true, expires: "never", ...o });
const pos = (over: Record<string, unknown> = {}, coords: Record<string, unknown> = {}) => ({
  coords: { latitude: 36.1, longitude: -86.7, accuracy: 7.5, altitude: null, altitudeAccuracy: null, heading: null, speed: null, ...coords },
  timestamp: 1_800_000_000_000,
  ...over,
});

beforeEach(() => {
  for (const f of Object.values(native)) f.mockClear();
});

describe("permission mapping", () => {
  it("granted (precise), granted with a coarse-only Android grant (approximate), undetermined, denied-but-askable, denied for good", async () => {
    const port = createExpoLocationPort("android");
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted", android: { accuracy: "fine" } }));
    expect(await port.permission()).toEqual({ status: "granted", approximate: false });
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted", android: { accuracy: "coarse" } }));
    expect(await port.permission()).toEqual({ status: "granted", approximate: true });
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ status: "undetermined", canAskAgain: true }));
    expect(await port.permission()).toEqual({ status: "undetermined" });
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ status: "denied", canAskAgain: true }));
    expect(await port.permission()).toEqual({ status: "denied", canAskAgain: true });
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ status: "denied", canAskAgain: false }));
    expect(await port.permission()).toEqual({ status: "denied", canAskAgain: false });
  });

  it("LOW-3: iOS 14+ 'Precise Location: Off' (`ios.accuracy: 'reduced'`) is approximate; 'full' is not; an iOS grant with no accuracy field (below iOS 14) is not", async () => {
    const port = createExpoLocationPort("ios");
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted", ios: { scope: "whenInUse", accuracy: "reduced" } }));
    expect(await port.permission()).toEqual({ status: "granted", approximate: true });
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted", ios: { scope: "whenInUse", accuracy: "full" } }));
    expect(await port.permission()).toEqual({ status: "granted", approximate: false });
    native.getForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted" }));
    expect(await port.permission()).toEqual({ status: "granted", approximate: false });
    // the same through the prompt
    native.requestForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted", ios: { scope: "whenInUse", accuracy: "reduced" } }));
    expect(await port.requestPermission()).toEqual({ status: "granted", approximate: true });
  });

  it("reading the permission NEVER shows the prompt; only `requestPermission` does, and it uses the FOREGROUND request", async () => {
    const port = createExpoLocationPort("ios");
    native.getForegroundPermissionsAsync.mockResolvedValue(resp({ status: "undetermined" }));
    await port.permission();
    await port.servicesEnabled();
    expect(native.requestForegroundPermissionsAsync).not.toHaveBeenCalled();
    native.requestForegroundPermissionsAsync.mockResolvedValueOnce(resp({ granted: true, status: "granted" }));
    expect(await port.requestPermission()).toEqual({ status: "granted", approximate: false });
    expect(native.requestForegroundPermissionsAsync).toHaveBeenCalledTimes(1);
    expect(native.requestBackgroundPermissionsAsync).not.toHaveBeenCalled();
  });

  it("a native failure is 'denied for good' (never an exception, never a prompt loop)", async () => {
    const port = createExpoLocationPort("ios");
    native.getForegroundPermissionsAsync.mockRejectedValueOnce(new Error("boom"));
    expect(await port.permission()).toEqual({ status: "denied", canAskAgain: false });
    native.requestForegroundPermissionsAsync.mockRejectedValueOnce(new Error("boom"));
    expect(await port.requestPermission()).toEqual({ status: "denied", canAskAgain: false });
    native.hasServicesEnabledAsync.mockRejectedValueOnce(new Error("boom"));
    expect(await port.servicesEnabled()).toBe(false);
  });
});

describe("currentFix", () => {
  it("asks for HIGH accuracy and maps the position (the fix's own timestamp, the reported accuracy)", async () => {
    native.getCurrentPositionAsync.mockResolvedValueOnce(pos({ mocked: false }));
    const r = await createExpoLocationPort("android").currentFix({ timeoutMs: 1000 });
    expect(native.getCurrentPositionAsync).toHaveBeenCalledWith({ accuracy: 4 });
    expect(r).toEqual({ ok: true, fix: { latitude: 36.1, longitude: -86.7, accuracyMeters: 7.5, timestamp: 1_800_000_000_000, simulated: false } });
  });

  it("the simulated flag: Android needs an explicit `mocked: false` (an absent flag is NOT trusted); iOS has none, so only an explicit true counts", async () => {
    const at = async (platform: string, mocked: unknown) => {
      native.getCurrentPositionAsync.mockResolvedValueOnce(pos(mocked === undefined ? {} : { mocked }));
      const r = await createExpoLocationPort(platform).currentFix({ timeoutMs: 1000 });
      return r.ok && r.fix.simulated;
    };
    expect(await at("android", false)).toBe(false);
    expect(await at("android", true)).toBe(true);
    expect(await at("android", undefined)).toBe(true);
    expect(await at("ios", undefined)).toBe(false);
    expect(await at("ios", true)).toBe(true);
  });

  it("no accuracy reported -> null (the flow refuses a fix with no accuracy)", async () => {
    native.getCurrentPositionAsync.mockResolvedValueOnce(pos({ mocked: false }, { accuracy: null }));
    const r = await createExpoLocationPort("android").currentFix({ timeoutMs: 1000 });
    expect(r.ok && r.fix.accuracyMeters).toBeNull();
  });

  it("gives up after the timeout (the native call has none) and a late answer is dropped; a rejection is 'unavailable'", async () => {
    native.getCurrentPositionAsync.mockImplementationOnce(() => new Promise(() => undefined));
    expect(await createExpoLocationPort("ios").currentFix({ timeoutMs: 20 })).toEqual({ ok: false, reason: "timeout" });
    native.getCurrentPositionAsync.mockRejectedValueOnce(new Error("no provider"));
    expect(await createExpoLocationPort("ios").currentFix({ timeoutMs: 1000 })).toEqual({ ok: false, reason: "unavailable" });
  });

  it("nothing of the background half is ever called", async () => {
    native.getForegroundPermissionsAsync.mockResolvedValue(resp({ granted: true, status: "granted" }));
    native.hasServicesEnabledAsync.mockResolvedValue(true);
    native.getCurrentPositionAsync.mockResolvedValue(pos({ mocked: false }));
    const port = createExpoLocationPort("android");
    await port.permission();
    await port.servicesEnabled();
    await port.currentFix({ timeoutMs: 1000 });
    for (const name of ["requestBackgroundPermissionsAsync", "startLocationUpdatesAsync", "startGeofencingAsync", "watchPositionAsync"] as const) expect(native[name], name).not.toHaveBeenCalled();
  });
});

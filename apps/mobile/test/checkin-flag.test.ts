/**
 * P4.2c: the build switches. `CHECKIN_UI_ENABLED` and `MARKER_COSIGNAL_UI_ENABLED` are `false`: nothing of the check-in is reachable in a release build (the course page shows the old
 * button, no card is rendered, the flow refuses, no permission prompt, no challenge prefetch). With the switch injected `true`, each of those turns on.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { prefetchChallenges } from "../src/challenges";
import { checkinUiAvailable, markerCosignalUiAvailable } from "../src/checkin";
import { CHECKIN_UI_ENABLED, MARKER_COSIGNAL_UI_ENABLED } from "../src/features";
import { captureMarkerCoSignal } from "../src/marker";
import { MemoryMarkerCosignalStore } from "../src/marker";
import { NOW0, SITE_VERSION, entryOf, facility, makeRig, rawFix } from "./support/checkin-rig";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
const read = (f: string): string => strip(readFileSync(join(root, f), "utf8"));

describe("the switches ship OFF", () => {
  it("are literally false", () => {
    expect([CHECKIN_UI_ENABLED, MARKER_COSIGNAL_UI_ENABLED]).toEqual([false, false]);
    expect(read("src/features.ts")).toMatch(/export const CHECKIN_UI_ENABLED = false;/);
    expect(read("src/features.ts")).toMatch(/export const MARKER_COSIGNAL_UI_ENABLED = false;/);
  });

  it("the gates answer false in this build and follow an injected value (so the tests can reach both states)", () => {
    expect(checkinUiAvailable()).toBe(false);
    expect(checkinUiAvailable(true)).toBe(true);
    expect(markerCosignalUiAvailable()).toBe(false);
    expect(markerCosignalUiAvailable(true, false)).toBe(false);
    expect(markerCosignalUiAvailable(false, true)).toBe(false);
    expect(markerCosignalUiAvailable(true, true)).toBe(true);
  });
});

describe("OFF: nothing is reachable", () => {
  it("the check-in flow refuses without reading the permission, prompting, taking a fix or touching a challenge", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    await rig.seedPool(3, NOW0 - 3600_000);
    const o = await rig.run(entryOf(facility()), { enabled: checkinUiAvailable() });
    expect(o).toEqual({ kind: "disabled" });
    expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
    expect(rig.api.requests).toEqual([]);
    expect(await rig.challengeStore.countUsable("user-a", "11111111-1111-4111-8111-111111111111", NOW0)).toBe(3);
    expect(await rig.outbox.list()).toEqual([]);
  });

  it("the marker capture refuses the same way", async () => {
    const rig = makeRig();
    rig.location.perm = { status: "undetermined" };
    const store = new MemoryMarkerCosignalStore();
    const o = await captureMarkerCoSignal(
      { enabled: markerCosignalUiAvailable(), location: rig.location, currentUserId: () => "user-a", challenges: rig.challenges, store, deviceId: () => Promise.resolve("d"), newId: () => "m", newFixId: () => "f", now: () => NOW0 },
      { entry: entryOf(facility()), catalogVersion: SITE_VERSION },
    );
    expect(o).toEqual({ kind: "disabled" });
    expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("challenge prefetch does nothing while the switch is off, and runs when it is on (the existing gate)", async () => {
    const calls: string[] = [];
    const manager = { prefetch: () => (calls.push("prefetch"), Promise.resolve({})) };
    await prefetchChallenges(manager);
    expect(calls).toEqual([]);
    await prefetchChallenges(manager, checkinUiAvailable(true));
    expect(calls).toEqual(["prefetch"]);
  });

  it("the composition root gates both services on the gates (not on a literal), and refuses at the service as well as at the screen", () => {
    const s = read("src/runtime/services.ts");
    expect(s).toMatch(/enabled: checkinUiAvailable\(\)/);
    expect(s).toMatch(/enabled: markerCosignalUiAvailable\(\)/);
    expect(read("src/checkin/flow.ts")).toMatch(/if \(!deps\.enabled\) return \{ kind: "disabled" \};/);
    expect(read("src/marker/capture.ts")).toMatch(/if \(!deps\.enabled\) return \{ kind: "disabled" \};/);
  });

  it("the course page renders the check-in card ONLY in the true branch of `checkinUiAvailable()`; the false branch is the old button that says recording is unavailable", () => {
    const c = read("app/course/[id].tsx");
    expect(c).toMatch(/\{checkinUiAvailable\(\) \? \(\s*<>\s*<CheckInCard entry=\{entry\} \/>[\s\S]*?\) : \(\s*<Row>\s*<Button title=\{t\("course\.checkIn"\)\} onPress=\{record\} \/>/);
    expect(c).toMatch(/Alert\.alert\(t\("course\.checkIn\.unavailable"\)\)/);
    expect(c.match(/<CheckInCard/g)).toHaveLength(1); // the one use (the import is the other mention)
    expect(c.match(/import \{ CheckInCard \}/g)).toHaveLength(1);
  });

  it("the facility page renders the marker card only behind BOTH switches", () => {
    const f = read("app/facility/[id].tsx");
    expect(f).toMatch(/\{markerCosignalUiAvailable\(\) && facility\.courses\[0\] \? <MarkerCard/);
    expect(f.match(/<MarkerCard/g)).toHaveLength(1);
    expect(f.match(/import \{ MarkerCard \}/g)).toHaveLength(1);
  });

  it("the cards are imported by no one else", () => {
    for (const f of ["app/(tabs)/me.tsx", "app/(tabs)/index.tsx", "app/(tabs)/played.tsx", "app/(tabs)/wallet.tsx", "app/trail/[id].tsx", "src/runtime/AppProvider.tsx"]) {
      expect(read(f), f).not.toMatch(/CheckInCard|MarkerCard/);
    }
  });
});

describe("ON (injected): the same code does the work", () => {
  it("the flow runs with the gate true: it reads the permission and takes a fix", async () => {
    const rig = makeRig();
    rig.api.online = false;
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    const o = await rig.run(entryOf(facility()), { enabled: checkinUiAvailable(true) });
    expect(o.kind).toBe("queued");
    expect(rig.location.calls.fix).toBe(1);
  });
});

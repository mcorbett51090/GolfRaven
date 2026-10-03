/** Push-token registration: the permission prompt is player-initiated only, and the client call is real. */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError } from "../src/api";
import { enablePushNotifications, unavailablePushAdapter, type PushAdapter, type PushDeps } from "../src/push";

function deps(adapter: PushAdapter, over: Partial<PushDeps> = {}) {
  const calls: unknown[] = [];
  const d: PushDeps = {
    adapter,
    api: { registerPushToken: (req) => (calls.push(req), Promise.resolve({ deviceId: req.deviceId, updatedAt: "2026-10-03T00:00:00.000Z" })) },
    deviceId: () => Promise.resolve("22222222-2222-4222-8222-222222222222"),
    platform: "ios",
    ...over,
  };
  return { d, calls };
}
const granting = (token = "ExponentPushToken[abc]"): PushAdapter & { asked: number } => {
  const a = { asked: 0, isAvailable: () => true, requestPermissionAndToken: () => (a.asked++, Promise.resolve({ status: "granted" as const, expoToken: token })) };
  return a;
};

describe("enablePushNotifications", () => {
  it("granted: registers the token for this device id and platform (the me-push-token request shape)", async () => {
    const a = granting();
    const { d, calls } = deps(a);
    expect(await enablePushNotifications(d)).toEqual({ status: "registered", updatedAt: "2026-10-03T00:00:00.000Z" });
    expect(a.asked).toBe(1);
    expect(calls).toEqual([{ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "ExponentPushToken[abc]", platform: "ios" }]);
  });

  it("denied: no request is made", async () => {
    const a: PushAdapter = { isAvailable: () => true, requestPermissionAndToken: () => Promise.resolve({ status: "denied" }) };
    const { d, calls } = deps(a);
    expect(await enablePushNotifications(d)).toEqual({ status: "denied" });
    expect(calls).toEqual([]);
  });

  it("this build has no notification module: 'unavailable', the prompt is never asked and nothing is sent", async () => {
    const { d, calls } = deps(unavailablePushAdapter());
    expect(await enablePushNotifications(d)).toEqual({ status: "unavailable" });
    expect(calls).toEqual([]);
    await expect(unavailablePushAdapter().requestPermissionAndToken()).rejects.toThrow();
  });

  it("an adapter failure and a server failure are reported, with the ApiError kept", async () => {
    const boom = new Error("native");
    expect(await enablePushNotifications(deps({ isAvailable: () => true, requestPermissionAndToken: () => Promise.reject(boom) }).d)).toEqual({ status: "failed", error: boom });
    const err = new ApiError({ kind: "rejected", status: 422, code: "device_limit_exceeded" });
    const r = await enablePushNotifications(deps(granting(), { api: { registerPushToken: () => Promise.reject(err) } }).d);
    expect(r).toEqual({ status: "failed", error: err });
  });

  it("platform omitted when it is neither ios nor android", async () => {
    const { d, calls } = deps(granting(), { platform: null });
    await enablePushNotifications(d);
    expect(calls[0]).toEqual({ deviceId: "22222222-2222-4222-8222-222222222222", expoToken: "ExponentPushToken[abc]" });
  });
});

describe("never at launch: the permission prompt has exactly one caller, a button handler", () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const files = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : /\.tsx?$/.test(n) ? [join(dir, n)] : []));
  const all = [...files(join(root, "src")), ...files(join(root, "app"))];
  const where = (needle: RegExp): string[] => all.filter((f) => needle.test(readFileSync(f, "utf8"))).map((f) => relative(root, f));

  it("`requestPermissionAndToken` is referenced only inside src/push", () => {
    expect(where(/requestPermissionAndToken/)).toEqual(["src/push/index.ts"]);
  });

  it("`enablePushNotifications` is called from the Me screen's tap handler only, never from the composition root or a provider", () => {
    expect(where(/enablePushNotifications/).sort()).toEqual(["app/(tabs)/me.tsx", "src/push/index.ts"]);
    const me = readFileSync(join(root, "app/(tabs)/me.tsx"), "utf8");
    expect(me).toMatch(/onPress=\{\(\) => void turnOnNotifications\(\)\}/);
    expect(me).not.toMatch(/useEffect[\s\S]{0,200}turnOnNotifications/);
  });

  it("no notification module is installed in this build, so nothing can prompt (it is a P4.2 follow-up)", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { dependencies: Record<string, string> };
    expect(Object.keys(pkg.dependencies)).not.toContain("expo-notifications");
  });
});

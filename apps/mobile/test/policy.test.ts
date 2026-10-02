/**
 * Store-policy gates that can be checked without a device:
 *  - P4 AT 5: no `Always` / background-location permission (config, manifest, Info.plist);
 *  - P4 AT 7: no ads or analytics SDK in the lockfile.
 */
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DENIED_SDKS,
  findDeniedSdks,
  lockfilePackageNames,
  scanAndroidManifest,
  scanAppConfig,
  scanInfoPlist,
} from "./support/policy-scan";

const here = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
const appJson = JSON.parse(readFileSync(here("../app.json"), "utf8")) as Parameters<typeof scanAppConfig>[0];
const lock = readFileSync(here("../../../pnpm-lock.yaml"), "utf8");

describe("AT 5 — no Always / background location: app.json", () => {
  it("the real app.json is clean and blocks the background-location permissions", () => {
    expect(scanAppConfig(appJson)).toEqual([]);
    const blocked = appJson.expo?.android?.blockedPermissions ?? [];
    expect(blocked).toContain("android.permission.ACCESS_BACKGROUND_LOCATION");
    expect(blocked).toContain("android.permission.FOREGROUND_SERVICE_LOCATION");
  });

  const base = (): NonNullable<typeof appJson.expo> => structuredClone(appJson.expo!);

  it("fails when an Android background permission is requested", () => {
    const e = base();
    e.android = { ...e.android, permissions: [...(e.android?.permissions ?? []), "android.permission.ACCESS_BACKGROUND_LOCATION"] };
    expect(scanAppConfig({ expo: e }).map((v) => v.rule)).toContain("android-permission");
  });

  it("fails when a background permission is no longer explicitly blocked", () => {
    const e = base();
    e.android = { ...e.android, blockedPermissions: [] };
    expect(scanAppConfig({ expo: e }).map((v) => v.rule)).toContain("android-blocked-permission-missing");
  });

  it("fails on an iOS Always usage string or a location background mode", () => {
    const e = base();
    e.ios = { ...e.ios, infoPlist: { NSLocationAlwaysAndWhenInUseUsageDescription: "x", UIBackgroundModes: ["location"] } };
    const rules = scanAppConfig({ expo: e }).map((v) => v.rule);
    expect(rules).toContain("ios-infoplist");
    expect(rules).toContain("ios-background-modes");
  });

  it("fails when expo-location is configured for background use", () => {
    for (const props of [{ isAndroidBackgroundLocationEnabled: true }, { isIosBackgroundLocationEnabled: true }, { locationAlwaysAndWhenInUsePermission: "x" }]) {
      const e = base();
      e.plugins = [...(e.plugins ?? []), ["expo-location", props]];
      expect(scanAppConfig({ expo: e }).map((v) => v.rule)).toContain("plugin-prop");
    }
  });

  it("an expo-location plugin that turns background OFF is fine", () => {
    const e = base();
    e.plugins = [...(e.plugins ?? []), ["expo-location", { isAndroidBackgroundLocationEnabled: false, isIosBackgroundLocationEnabled: false }]];
    expect(scanAppConfig({ expo: e })).toEqual([]);
  });

  it("fails on background-only plugins", () => {
    const e = base();
    e.plugins = [...(e.plugins ?? []), "expo-task-manager"];
    expect(scanAppConfig({ expo: e }).map((v) => v.rule)).toContain("plugin");
  });
});

describe("AT 5 — generated manifest and Info.plist scanners", () => {
  it("Android: a granted background permission fails; a removed one does not; foreground location is allowed", () => {
    const granted = '<manifest><uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/></manifest>';
    const removed = '<manifest><uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" tools:node="remove"/></manifest>';
    const foreground = '<manifest><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>';
    expect(scanAndroidManifest(granted)).toHaveLength(1);
    expect(scanAndroidManifest(removed)).toEqual([]);
    expect(scanAndroidManifest(foreground)).toEqual([]);
    expect(scanAndroidManifest('<uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION"/>')).toHaveLength(1);
  });

  it("iOS: an Always usage string or a location background mode fails", () => {
    const always = "<plist><dict><key>NSLocationAlwaysAndWhenInUseUsageDescription</key><string>x</string></dict></plist>";
    const mode = "<plist><dict><key>UIBackgroundModes</key><array><string>fetch</string><string>location</string></array></dict></plist>";
    const whenInUse = "<plist><dict><key>NSLocationWhenInUseUsageDescription</key><string>x</string><key>UIBackgroundModes</key><array><string>fetch</string></array></dict></plist>";
    expect(scanInfoPlist(always)).toHaveLength(1);
    expect(scanInfoPlist(mode)).toHaveLength(1);
    expect(scanInfoPlist(whenInUse)).toEqual([]);
  });

  // `expo prebuild --no-install` writes android/ and ios/ (gitignored). When a
  // developer has run it, scan what it actually generated: this is the literal
  // "manifest + Info.plist scan" of AT 5. Skipped (not passed) when absent.
  const manifestPath = here("../android/app/src/main/AndroidManifest.xml");
  const plistPath = here("../ios/GolfRaven/Info.plist");
  it.skipIf(!existsSync(manifestPath))("the generated AndroidManifest.xml is clean", () => {
    expect(scanAndroidManifest(readFileSync(manifestPath, "utf8"))).toEqual([]);
  });
  it.skipIf(!existsSync(plistPath))("the generated Info.plist is clean", () => {
    expect(scanInfoPlist(readFileSync(plistPath, "utf8"))).toEqual([]);
  });
});

describe("AT 7 — no ads or analytics SDK in the lockfile", () => {
  it("parses a plausible number of packages (the scan is not vacuous)", () => {
    const names = lockfilePackageNames(lock);
    expect(names.length).toBeGreaterThan(500);
    expect(names).toContain("expo");
    expect(names).toContain("@noble/curves");
    expect(names).toContain("react-native-health-connect");
  });

  it("the real pnpm-lock.yaml contains none", () => {
    expect(findDeniedSdks(lock)).toEqual([]);
  });

  it("the scanner catches each denied pattern in a synthetic lockfile", () => {
    for (const d of DENIED_SDKS) {
      const name = d.pattern.endsWith("/") ? `${d.pattern}core` : d.pattern;
      const scoped = name.startsWith("@") ? `'${name}@1.2.3'` : `${name}@1.2.3`;
      const fake = `lockfileVersion: '9.0'\n\npackages:\n\n  ${scoped}:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  ${scoped}: {}\n`;
      expect(findDeniedSdks(fake).map((h) => h.name), d.pattern).toEqual([name]);
    }
  });

  it("does not flag look-alike names", () => {
    const fake = "lockfileVersion: '9.0'\n\npackages:\n\n  expo-insights-viewer-not-really@1.0.0:\n    resolution: {x}\n\n  amplitude-ish@1.0.0:\n    resolution: {x}\n\nsnapshots:\n";
    expect(findDeniedSdks(fake)).toEqual([]);
  });
});

/**
 * Store-policy gates that can be checked without a device:
 *  - P4 AT 5: no `Always` / background-location permission (config, resolved config, manifest, Info.plist);
 *  - the under-age flag cannot leave the device through a backup (`allowBackup`);
 *  - P4 AT 7: no ads or analytics SDK in the lockfile.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ALLOWED_PLUGINS,
  DENIED_SDKS,
  findDeniedSdks,
  findDynamicConfigs,
  lockfilePackageNames,
  ALLOWED_GRANTED_ANDROID_PERMISSIONS,
  ALLOWED_IOS_ENTITLEMENTS,
  grantedAndroidPermissions,
  normalizeAndroidPermission,
  scanAndroidGrantedPermissions,
  scanAndroidManifest,
  scanAppConfig,
  scanEntitlements,
  scanInfoPlist,
} from "./support/policy-scan";

const here = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
const appDir = here("..");
const appJson = JSON.parse(readFileSync(here("../app.json"), "utf8")) as Parameters<typeof scanAppConfig>[0];
const lock = readFileSync(here("../../../pnpm-lock.yaml"), "utf8");
const rules = (c: Parameters<typeof scanAppConfig>[0]): string[] => scanAppConfig(c).map((v) => v.rule);

describe("AT 5 — no dynamic Expo config can hide anything from the scan", () => {
  it("there is no app.config.* next to app.json (it could add permissions the app.json scan never sees)", () => {
    expect(findDynamicConfigs(readdirSync(appDir))).toEqual([]);
  });

  it("the detector recognises every dynamic-config spelling and ignores app.json", () => {
    expect(findDynamicConfigs(["app.json", "app.config.ts", "app.config.js", "app.config.mjs", "app.config.cjs", "app.config.json", "package.json", "app.configs"])).toEqual([
      "app.config.ts",
      "app.config.js",
      "app.config.mjs",
      "app.config.cjs",
      "app.config.json",
    ]);
  });

  // `@expo/config` is Expo's own resolver (what `expo prebuild` reads); it is in the lockfile as a dependency
  // of `expo`, so it is resolved THROUGH expo rather than added as a dependency of this app.
  it("the config Expo actually resolves is clean too", () => {
    const fromExpo = createRequire(createRequire(import.meta.url).resolve("expo/package.json"));
    const { getConfig } = fromExpo("@expo/config") as { getConfig: (root: string, o: Record<string, unknown>) => { exp: NonNullable<Parameters<typeof scanAppConfig>[0]["expo"]> } };
    const resolved = getConfig(dirname(appDir + "/app.json"), { skipSDKVersionRequirement: true, isPublicConfig: false });
    expect(resolved.exp.plugins?.length, "the resolved config must not be empty (the scan would be vacuous)").toBeGreaterThan(0);
    expect(scanAppConfig({ expo: resolved.exp })).toEqual([]);
  });
});

describe("AT 5 — no Always / background location: app.json", () => {
  it("the real app.json is clean and blocks the background-location permissions", () => {
    expect(scanAppConfig(appJson)).toEqual([]);
    const blocked = appJson.expo?.android?.blockedPermissions ?? [];
    expect(blocked).toContain("android.permission.ACCESS_BACKGROUND_LOCATION");
    expect(blocked).toContain("android.permission.FOREGROUND_SERVICE_LOCATION");
    expect(blocked).toContain("android.permission.SYSTEM_ALERT_WINDOW");
  });

  it("the real app.json turns Android backup off (the device-local under-age flag must not be copied off the device)", () => {
    expect(appJson.expo?.android?.allowBackup).toBe(false);
  });

  const base = (): NonNullable<typeof appJson.expo> => structuredClone(appJson.expo!);

  it("fails when an Android background permission is requested", () => {
    const e = base();
    e.android = { ...e.android, permissions: [...(e.android?.permissions ?? []), "android.permission.ACCESS_BACKGROUND_LOCATION"] };
    expect(rules({ expo: e })).toContain("android-permission");
  });

  it("recognises the SHORT permission name (Expo and Android both accept it)", () => {
    expect(normalizeAndroidPermission("ACCESS_BACKGROUND_LOCATION")).toBe(normalizeAndroidPermission("android.permission.ACCESS_BACKGROUND_LOCATION"));
    const e = base();
    e.android = { ...e.android, permissions: ["ACCESS_BACKGROUND_LOCATION"] };
    expect(rules({ expo: e })).toContain("android-permission");
    // and a short name in blockedPermissions counts as blocking it
    const ok = base();
    ok.android = { ...ok.android, blockedPermissions: ["ACCESS_BACKGROUND_LOCATION", "FOREGROUND_SERVICE_LOCATION", "SYSTEM_ALERT_WINDOW"] };
    expect(rules({ expo: ok })).toEqual([]);
  });

  it("fails when a background permission (or SYSTEM_ALERT_WINDOW) is no longer explicitly blocked", () => {
    for (const keep of [[], ["android.permission.FOREGROUND_SERVICE_LOCATION", "android.permission.SYSTEM_ALERT_WINDOW"], ["android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.FOREGROUND_SERVICE_LOCATION"]]) {
      const e = base();
      e.android = { ...e.android, blockedPermissions: keep };
      expect(rules({ expo: e }), keep.join(",")).toContain("android-blocked-permission-missing");
    }
  });

  it("fails when Android backup is on, or merely not stated", () => {
    for (const v of [true, undefined]) {
      const e = base();
      e.android = { ...e.android };
      if (v === undefined) delete e.android.allowBackup;
      else e.android.allowBackup = v;
      expect(rules({ expo: e }), String(v)).toContain("android-allow-backup");
    }
  });

  it("fails on an iOS Always usage string or a location background mode", () => {
    const e = base();
    e.ios = { ...e.ios, infoPlist: { NSLocationAlwaysAndWhenInUseUsageDescription: "x", UIBackgroundModes: ["location"] } };
    const r = rules({ expo: e });
    expect(r).toContain("ios-infoplist");
    expect(r).toContain("ios-background-modes");
  });

  it("fails when expo-location is configured for background use (it is not even on the allow-list)", () => {
    for (const props of [{ isAndroidBackgroundLocationEnabled: true }, { isIosBackgroundLocationEnabled: true }, { locationAlwaysAndWhenInUsePermission: "x" }]) {
      const e = base();
      e.plugins = [...(e.plugins ?? []), ["expo-location", props]];
      expect(rules({ expo: e })).toContain("plugin-prop");
      expect(rules({ expo: e })).toContain("plugin");
    }
  });

  it("fails on ANY plugin outside the allow-list — even expo-location with no props, a background-geolocation library, or a local plugin", () => {
    for (const p of ["expo-location", ["expo-location"], "react-native-background-geolocation", "@transistorsoft/react-native-background-geolocation", "expo-task-manager", "./plugins/with-anything"]) {
      const e = base();
      e.plugins = [...(e.plugins ?? []), p];
      expect(rules({ expo: e }), JSON.stringify(p)).toContain("plugin");
    }
  });

  it("fails on a plugin that is not a package name (a function in a dynamic config cannot be audited)", () => {
    const e = base();
    e.plugins = [...(e.plugins ?? []), () => undefined, [() => undefined, {}]];
    expect(rules({ expo: e }).filter((r) => r === "plugin")).toHaveLength(2);
  });

  it("an allow-listed plugin that turns a background prop on still fails, and every allow-listed plugin is in the real app.json", () => {
    const e = base();
    e.plugins = [...(e.plugins ?? []), ["expo-localization", { isAndroidBackgroundLocationEnabled: true }]];
    expect(rules({ expo: e })).toContain("plugin-prop");
    const used = (appJson.expo?.plugins ?? []).map((p) => (Array.isArray(p) ? p[0] : p));
    expect([...ALLOWED_PLUGINS].sort()).toEqual([...used].sort());
  });

  it("an expo-location-style prop explicitly set to false is not itself a violation", () => {
    const e = base();
    e.plugins = [...(e.plugins ?? []).filter((p) => p !== "expo-router"), ["expo-router", { isAndroidBackgroundLocationEnabled: false }]];
    expect(rules({ expo: e })).toEqual([]);
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
    expect(scanAndroidManifest('<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>')).toHaveLength(1);
  });

  it("Android: the short permission name, single-quoted attributes and attribute order are all caught", () => {
    expect(scanAndroidManifest('<manifest><uses-permission android:name="ACCESS_BACKGROUND_LOCATION"/></manifest>')).toHaveLength(1);
    expect(scanAndroidManifest("<manifest><uses-permission android:name='android.permission.ACCESS_BACKGROUND_LOCATION'/></manifest>")).toHaveLength(1);
    expect(scanAndroidManifest("<manifest><uses-permission android:name='ACCESS_BACKGROUND_LOCATION' /></manifest>")).toHaveLength(1);
    expect(scanAndroidManifest('<manifest><uses-permission tools:node="replace" android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/></manifest>')).toHaveLength(1);
    expect(scanAndroidManifest('<manifest><uses-permission-sdk-23 android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/></manifest>')).toHaveLength(1);
    // removal is honoured in either quote style
    expect(scanAndroidManifest("<manifest><uses-permission android:name='ACCESS_BACKGROUND_LOCATION' tools:node='remove'/></manifest>")).toEqual([]);
    expect(scanAndroidManifest("<manifest><uses-permission tools:node='remove' android:name='android.permission.SYSTEM_ALERT_WINDOW'/></manifest>")).toEqual([]);
  });

  it("Android: <application> must say allowBackup=false (either quote style); no <application> is not a violation of its own", () => {
    const app = (attrs: string): string => `<manifest><application android:name=".MainApplication" ${attrs} android:theme="@style/AppTheme"></application></manifest>`;
    expect(scanAndroidManifest(app('android:allowBackup="false"'))).toEqual([]);
    expect(scanAndroidManifest(app("android:allowBackup='false'"))).toEqual([]);
    expect(scanAndroidManifest(app('android:allowBackup="true"')).map((v) => v.rule)).toEqual(["android-allow-backup"]);
    expect(scanAndroidManifest(app("android:allowBackup='true'")).map((v) => v.rule)).toEqual(["android-allow-backup"]);
    expect(scanAndroidManifest(app("")).map((v) => v.rule)).toEqual(["android-allow-backup"]);
  });

  it("iOS: an Always usage string or a location background mode fails", () => {
    const always = "<plist><dict><key>NSLocationAlwaysAndWhenInUseUsageDescription</key><string>x</string></dict></plist>";
    const mode = "<plist><dict><key>UIBackgroundModes</key><array><string>fetch</string><string>location</string></array></dict></plist>";
    const whenInUse = "<plist><dict><key>NSLocationWhenInUseUsageDescription</key><string>x</string><key>UIBackgroundModes</key><array><string>fetch</string></array></dict></plist>";
    expect(scanInfoPlist(always)).toHaveLength(1);
    expect(scanInfoPlist(mode)).toHaveLength(1);
    expect(scanInfoPlist(whenInUse)).toEqual([]);
  });

  // `expo prebuild --no-install` writes android/ and ios/ (gitignored). Scanning what it actually generated is
  // the literal "manifest + Info.plist scan" of AT 5. Locally these skip when you have not run prebuild; in CI
  // (`CI` is set, and the workflow runs prebuild before the tests) a missing file is a FAILURE, never a skip.
  const inCi = Boolean(process.env["CI"]);
  const generated = (name: string, path: string, scan: (text: string) => unknown[]): void => {
    const run = (): void => {
      expect(existsSync(path), `${path} is missing: run \`expo prebuild --no-install\` in apps/mobile first (CI does)`).toBe(true);
      expect(scan(readFileSync(path, "utf8"))).toEqual([]);
    };
    if (existsSync(path) || inCi) it(name, run);
    else it.skip(name, run);
  };
  generated("the generated AndroidManifest.xml is clean (and has allowBackup=false)", here("../android/app/src/main/AndroidManifest.xml"), scanAndroidManifest);
  generated("the generated Info.plist is clean", here("../ios/GolfRaven/Info.plist"), scanInfoPlist);
  generated("the generated AndroidManifest.xml grants only the allow-listed permissions (a native module adds none; P4.2b-2)", here("../android/app/src/main/AndroidManifest.xml"), scanAndroidGrantedPermissions);
  generated("the generated entitlements are the allow-listed ones: Sign in with Apple and App Attest (development | production), nothing else (P4.2b-2)", here("../ios/GolfRaven/GolfRaven.entitlements"), scanEntitlements);
});

describe("P4.2b-2 — a native module means a new prebuild: the allow-lists it must stay inside", () => {
  const plist = (body: string): string => `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>${body}</dict></plist>`;
  const SIWA = "<key>com.apple.developer.applesignin</key><array><string>Default</string></array>";
  const ATTEST = (v: string): string => `<key>com.apple.developer.devicecheck.appattest-environment</key><string>${v}</string>`;

  it("the entitlement scanner accepts exactly the two allow-listed entitlements, and the App Attest value only as development | production", () => {
    expect(scanEntitlements(plist(SIWA + ATTEST("production")))).toEqual([]);
    expect(scanEntitlements(plist(SIWA + ATTEST("development")))).toEqual([]);
    expect(scanEntitlements(plist(ATTEST("staging"))).map((v) => v.rule)).toEqual(["ios-entitlement-value"]);
    expect(scanEntitlements(plist(SIWA + "<key>aps-environment</key><string>production</string>")).map((v) => v.rule)).toEqual(["ios-entitlement"]);
    expect(scanEntitlements(plist(SIWA + "<key>com.apple.developer.healthkit</key><true/>")).map((v) => v.rule)).toEqual(["ios-entitlement"]);
    expect(scanEntitlements(plist(`<key>com.apple.developer.applesignin</key><array><string>Other</string></array>`)).map((v) => v.rule)).toEqual(["ios-entitlement-value"]);
    expect(Object.keys(ALLOWED_IOS_ENTITLEMENTS).sort()).toEqual(["com.apple.developer.applesignin", "com.apple.developer.devicecheck.appattest-environment"]);
  });

  it("PR #42 gate LOW-2: the entitlement scan FAILS CLOSED: an unknown key is a violation whatever its value element is (integer, empty string, data, date, real, dict, array, boolean), and an allow-listed key must hold a string or an array of strings", () => {
    const unknownValues = ["<integer>1</integer>", "<string/>", "<string></string>", "<data>AAAA</data>", "<date>2026-01-01T00:00:00Z</date>", "<real>1.5</real>", "<dict><key>x</key><string>y</string></dict>", "<array/>", "<array><integer>1</integer></array>", "<true/>", "<false/>"];
    for (const v of unknownValues) {
      const r = scanEntitlements(plist(SIWA + `<key>com.apple.developer.healthkit</key>${v}`));
      // (a nested dict's own keys are reported too: stricter, never looser)
      expect(r.filter((x) => x.rule === "ios-entitlement" && x.detail.includes("com.apple.developer.healthkit")), v).toHaveLength(1);
    }
    // the unknown key FIRST, then an allowed one: neither hides the other
    expect(scanEntitlements(plist(`<key>aps-environment</key><integer>1</integer>${SIWA}`)).map((x) => x.rule)).toEqual(["ios-entitlement"]);
    for (const bad of ["<integer>1</integer>", "<string/>", "<true/>", "<data>AAAA</data>", "<dict/>", "<array/>", "<array><integer>1</integer></array>", "<array><string>Default</string><dict/></array>"]) {
      expect(scanEntitlements(plist(`<key>com.apple.developer.applesignin</key>${bad}`)).map((x) => x.rule), bad).toEqual(["ios-entitlement-value"]);
      expect(scanEntitlements(plist(`<key>com.apple.developer.devicecheck.appattest-environment</key>${bad}`)).map((x) => x.rule), bad).toEqual(["ios-entitlement-value"]);
    }
    // an empty file (no keys at all) is not a violation by itself, a malformed value for a known key still is
    expect(scanEntitlements(plist(""))).toEqual([]);
    expect(scanEntitlements(plist(SIWA + ATTEST("production")))).toEqual([]);
  });

  it("app.json sets no entitlement directly (the App Attest one comes from the audited plugin); one that is not allow-listed fails the config scan", () => {
    expect(appJson.expo?.ios?.entitlements).toBeUndefined();
    const e = structuredClone(appJson.expo!);
    e.ios = { ...e.ios, entitlements: { "com.apple.developer.healthkit": true } };
    expect(rules({ expo: e })).toContain("ios-entitlement");
    e.ios = { ...e.ios, entitlements: { "com.apple.developer.devicecheck.appattest-environment": "production" } };
    expect(rules({ expo: e })).not.toContain("ios-entitlement");
  });

  it("the local attestation plugin is the one allow-listed local plugin, and it is in the real app.json", () => {
    const local = [...ALLOWED_PLUGINS].filter((p) => p.startsWith("."));
    expect(local).toEqual(["./modules/golfraven-attest/app.plugin.js"]);
    const used = (appJson.expo?.plugins ?? []).map((p) => (Array.isArray(p) ? p[0] : p));
    expect(used).toContain("./modules/golfraven-attest/app.plugin.js");
    expect(existsSync(here("../modules/golfraven-attest/app.plugin.js"))).toBe(true);
  });

  it("the Android granted-permission scan: the allow-listed three pass; removals do not count as granted; any new permission (a dangerous one included) fails", () => {
    const m = (body: string): string => `<manifest xmlns:tools="x">${body}</manifest>`;
    const grant = (n: string): string => `<uses-permission android:name="${n}"/>`;
    expect(scanAndroidGrantedPermissions(m([...ALLOWED_GRANTED_ANDROID_PERMISSIONS].map(grant).join("")))).toEqual([]);
    expect(scanAndroidGrantedPermissions(m('<uses-permission android:name="android.permission.CAMERA" tools:node="remove"/>'))).toEqual([]);
    for (const bad of ["android.permission.CAMERA", "android.permission.READ_PHONE_STATE", "android.permission.ACCESS_FINE_LOCATION", "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE", "READ_CONTACTS"]) {
      expect(scanAndroidGrantedPermissions(m(grant(bad))).map((v) => v.rule), bad).toEqual(["android-new-permission"]);
    }
    expect(grantedAndroidPermissions(m(grant("VIBRATE") + grant("android.permission.INTERNET")))).toEqual(["android.permission.INTERNET", "android.permission.VIBRATE"]);
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

describe("PR #42 gate LOW-1 — the gitleaks allowlist for the fixture's scripted integrity token is anchored", () => {
  const toml = readFileSync(here("../../../.gitleaks.toml"), "utf8");
  const entry = toml.slice(toml.lastIndexOf("[[allowlists]]"));
  const regex = /regexes = \['''(.+)'''\]/.exec(entry)?.[1] ?? "";
  const re = new RegExp(regex);
  const TOKEN = `it-${"A".repeat(43)}`;

  it("the entry is the last one, names the scripted token, has no `paths` (gitleaks 8.30.1 skips a path-allowlisted file entirely, even under AND) and anchors the WHOLE line", () => {
    expect(entry).toMatch(/integrityToken/);
    expect(entry).not.toMatch(/^paths\s*=/m);
    expect(regex.startsWith("^")).toBe(true);
    expect(regex.endsWith("$")).toBe(true);
  });

  it("it matches exactly the fixture's member lines and nothing wider", () => {
    expect(re.test(`        "integrityToken": "${TOKEN}"`)).toBe(true);
    expect(re.test(`        "integrityToken": "${TOKEN}",`)).toBe(true);
    for (const wider of [`"integrityToken": "${TOKEN}", "x": "ghp_${"a1B2".repeat(9)}"`, `x "integrityToken": "${TOKEN}"`, `"integrityToken": "${TOKEN}A"`, `"integrityToken": "eyJhbGciOi.${"a".repeat(40)}"`, `"integrityToken": "it-${"A".repeat(42)}"`, `"integrityToken": "${TOKEN}" // ${["AK", "IA"].join("")}-shaped trailing text`]) {
      expect(re.test(wider), wider).toBe(false);
    }
  });
});

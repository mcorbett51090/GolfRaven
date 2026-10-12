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
  EXPO_LOCATION_REQUIRED_FALSE,
  scanLocationDeclarations,
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

  it("P4.2c: foreground location is NOT blocked (the manifest merger would remove it and the check-in could never get a fix); the expo-location plugin is configured foreground-only", () => {
    const blocked = appJson.expo?.android?.blockedPermissions ?? [];
    expect(blocked).not.toContain("android.permission.ACCESS_FINE_LOCATION");
    expect(blocked).not.toContain("android.permission.ACCESS_COARSE_LOCATION");
    const entry = (appJson.expo?.plugins ?? []).find((p) => Array.isArray(p) && p[0] === "expo-location") as [string, Record<string, unknown>] | undefined;
    expect(entry, "expo-location must be configured with props (a bare entry writes the Always usage strings)").toBeDefined();
    for (const prop of EXPO_LOCATION_REQUIRED_FALSE) expect(entry![1][prop], prop).toBe(false);
    expect(String(entry![1]["locationWhenInUsePermission"])).toMatch(/only while the app is open/i);
    expect(String(entry![1]["locationWhenInUsePermission"])).toMatch(/never tracks you in the background/i);
  });

  it("P4.2c / P5 §50: the iOS usage descriptions have fr-CA translations that say the same things", () => {
    const locales = (appJson.expo as { locales?: Record<string, string> }).locales ?? {};
    expect(locales["fr-CA"]).toBe("./locales/fr-CA.json");
    const fr = JSON.parse(readFileSync(here("../locales/fr-CA.json"), "utf8")) as Record<string, string>;
    expect(Object.keys(fr).sort()).toEqual(["NSLocationWhenInUseUsageDescription", "NSPhotoLibraryUsageDescription"]);
    expect(fr["NSLocationWhenInUseUsageDescription"]).toMatch(/seulement lorsque l'app est ouverte/);
    expect(fr["NSLocationWhenInUseUsageDescription"]).toMatch(/jamais en arrière-plan/);
    expect(fr["NSPhotoLibraryUsageDescription"]).toMatch(/photothèque/);
    expect(fr["NSPhotoLibraryUsageDescription"]).toMatch(/caméra|camera/i);
  });

  it("P5 §50: expo-image-picker is library-only (camera and microphone blocked) with an honest photos usage string", () => {
    const blocked = appJson.expo?.android?.blockedPermissions ?? [];
    expect(blocked).toContain("android.permission.CAMERA");
    const entry = (appJson.expo?.plugins ?? []).find((p) => Array.isArray(p) && p[0] === "expo-image-picker") as [string, Record<string, unknown>] | undefined;
    expect(entry, "expo-image-picker must be configured").toBeDefined();
    expect(entry![1]["cameraPermission"]).toBe(false);
    expect(entry![1]["microphonePermission"]).toBe(false);
    expect(String(entry![1]["photosPermission"])).toMatch(/photo library/i);
    expect(String(entry![1]["photosPermission"])).toMatch(/does not access your camera/i);
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

  const withLocation = (over: Record<string, unknown>): ReturnType<typeof base> => {
    const e = base();
    e.plugins = (e.plugins ?? []).map((p) => (Array.isArray(p) && p[0] === "expo-location" ? ["expo-location", { ...(p[1] as Record<string, unknown>), ...over }] : p));
    return e;
  };

  it("fails when expo-location is configured for background use, with the prop that did it named", () => {
    for (const props of [{ isAndroidBackgroundLocationEnabled: true }, { isIosBackgroundLocationEnabled: true }, { locationAlwaysAndWhenInUsePermission: "x" }, { locationAlwaysPermission: "x" }, { isAndroidForegroundServiceEnabled: true }]) {
      expect(rules({ expo: withLocation(props) }), JSON.stringify(props)).toContain("plugin-prop");
    }
  });

  it("expo-location is allowed ONLY with every background / Always / motion prop explicitly false: absent, true or a string all fail (the plugin's defaults write the Always usage strings)", () => {
    expect(rules({ expo: withLocation({}) })).toEqual([]);
    for (const prop of EXPO_LOCATION_REQUIRED_FALSE) {
      for (const v of [undefined, true, "x"]) {
        const e = withLocation({ [prop]: v });
        const r = rules({ expo: e });
        expect(r.includes("plugin-prop-missing") || r.includes("plugin-prop"), `${prop}=${String(v)}`).toBe(true);
      }
    }
    // bare entries, string or one-element array, are the defaults: refused
    for (const bare of ["expo-location", ["expo-location"], ["expo-location", {}]]) {
      const e = base();
      e.plugins = [...(e.plugins ?? []).filter((p) => !(Array.isArray(p) && p[0] === "expo-location")), bare];
      expect(rules({ expo: e }), JSON.stringify(bare)).toContain("plugin-prop-missing");
    }
    // an empty or missing usage string is refused too
    for (const v of [undefined, "", "short"]) expect(rules({ expo: withLocation({ locationWhenInUsePermission: v }) }), String(v)).toContain("plugin-prop-missing");
  });

  it("fails on ANY plugin outside the allow-list — a background-geolocation library, a task manager, or a local plugin", () => {
    for (const p of ["react-native-background-geolocation", "@transistorsoft/react-native-background-geolocation", "expo-task-manager", "./plugins/with-anything"]) {
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
  const readIf = (path: string): string | undefined => (existsSync(path) ? readFileSync(path, "utf8") : undefined);
  const genLoc = (name: string, files: () => { infoPlist?: string; androidManifest?: string }, paths: string[]): void => {
    const run = (): void => {
      for (const p of paths) expect(existsSync(p), `${p} is missing: run \`expo prebuild --no-install\` in apps/mobile first (CI does)`).toBe(true);
      expect(scanLocationDeclarations(files())).toEqual([]);
    };
    if (paths.every((p) => existsSync(p)) || inCi) it(name, run);
    else it.skip(name, run);
  };
  genLoc("P4 AT 5 (iOS): the generated Info.plist has NSLocationWhenInUseUsageDescription, no NSLocationAlways* key, no motion string and no `location` background mode", () => ({ infoPlist: readIf(here("../ios/GolfRaven/Info.plist")) as string }), [here("../ios/GolfRaven/Info.plist")]);
  genLoc("P4 AT 5 (Android): the generated manifest grants ACCESS_FINE_LOCATION and ACCESS_COARSE_LOCATION and NO other location permission (no ACCESS_BACKGROUND_LOCATION)", () => ({ androidManifest: readIf(here("../android/app/src/main/AndroidManifest.xml")) as string }), [here("../android/app/src/main/AndroidManifest.xml")]);
  generated("the generated entitlements are the allow-listed ones: Sign in with Apple and App Attest (development | production), nothing else (P4.2b-2)", here("../ios/GolfRaven/GolfRaven.entitlements"), scanEntitlements);
});

describe("P4.2c — the location declarations scanner (proved on failing fixtures as well as the real files)", () => {
  const plist = (body: string): string => `<?xml version="1.0"?><plist version="1.0"><dict>${body}</dict></plist>`;
  const WHEN = "<key>NSLocationWhenInUseUsageDescription</key><string>GolfRaven uses your location only while the app is open.</string>";
  const SERVICE_REMOVED = '<application><service android:name="expo.modules.location.services.LocationTaskService" tools:node="remove"/></application>';
  const man = (...perms: string[]): string => `<manifest xmlns:tools="x">${perms.map((p) => `<uses-permission android:name="${p}"/>`).join("")}${SERVICE_REMOVED}</manifest>`;
  const FINE = "android.permission.ACCESS_FINE_LOCATION";
  const COARSE = "android.permission.ACCESS_COARSE_LOCATION";

  it("iOS: a clean when-in-use file passes; an Always key, a motion string, a location background mode, or a missing / empty usage string each fail with their own rule", () => {
    expect(scanLocationDeclarations({ infoPlist: plist(WHEN) })).toEqual([]);
    expect(scanLocationDeclarations({ infoPlist: plist(WHEN + "<key>NSLocationAlwaysAndWhenInUseUsageDescription</key><string>x</string>") }).map((v) => v.rule)).toEqual(["ios-location-always"]);
    expect(scanLocationDeclarations({ infoPlist: plist(WHEN + "<key>NSLocationAlwaysUsageDescription</key><string>x</string>") }).map((v) => v.rule)).toEqual(["ios-location-always"]);
    expect(scanLocationDeclarations({ infoPlist: plist(WHEN + "<key>NSMotionUsageDescription</key><string>x</string>") }).map((v) => v.rule)).toEqual(["ios-motion"]);
    expect(scanLocationDeclarations({ infoPlist: plist(WHEN + "<key>UIBackgroundModes</key><array><string>location</string></array>") }).map((v) => v.rule)).toEqual(["ios-background-modes"]);
    expect(scanLocationDeclarations({ infoPlist: plist("") }).map((v) => v.rule)).toEqual(["ios-location-when-in-use"]);
    expect(scanLocationDeclarations({ infoPlist: plist("<key>NSLocationWhenInUseUsageDescription</key><string></string>") }).map((v) => v.rule)).toEqual(["ios-location-when-in-use"]);
  });

  it("Android: FINE + COARSE only passes; a missing one, a background / foreground-service-location / activity-recognition permission fail; a tools:node=remove entry grants nothing", () => {
    expect(scanLocationDeclarations({ androidManifest: man(FINE, COARSE) })).toEqual([]);
    expect(scanLocationDeclarations({ androidManifest: man(FINE) }).map((v) => v.rule)).toEqual(["android-location-missing"]);
    expect(scanLocationDeclarations({ androidManifest: man(FINE, COARSE, "android.permission.ACCESS_BACKGROUND_LOCATION") }).map((v) => v.rule)).toEqual(["android-location-extra"]);
    expect(scanLocationDeclarations({ androidManifest: man(FINE, COARSE, "android.permission.FOREGROUND_SERVICE_LOCATION") }).map((v) => v.rule)).toEqual(["android-location-extra"]);
    expect(scanLocationDeclarations({ androidManifest: man(FINE, COARSE, "android.permission.ACTIVITY_RECOGNITION") }).map((v) => v.rule)).toEqual(["android-location-extra"]);
    const removed = `<manifest xmlns:tools="x"><uses-permission android:name="${FINE}"/><uses-permission android:name="${COARSE}"/><uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" tools:node="remove"/>${SERVICE_REMOVED}</manifest>`;
    expect(scanLocationDeclarations({ androidManifest: removed })).toEqual([]);
    // the SHORT permission name is understood too
    expect(scanLocationDeclarations({ androidManifest: man("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION") }).map((v) => v.rule)).toEqual(["android-location-extra"]);
  });

  it("P4.2c-1: expo-location's LocationTaskService must be REMOVED from the merged manifest: absent, present-and-kept, a relative name (matches nothing in the app manifest) or another node action all fail", () => {
    const base = `<manifest xmlns:tools="x"><uses-permission android:name="${FINE}"/><uses-permission android:name="${COARSE}"/>`;
    const rules = (svc: string): string[] => scanLocationDeclarations({ androidManifest: `${base}<application>${svc}</application></manifest>` }).map((v) => v.rule);
    const NAME = "expo.modules.location.services.LocationTaskService";
    expect(rules(`<service android:name="${NAME}" tools:node="remove"/>`)).toEqual([]);
    expect(rules(`<service tools:node='remove' android:name='${NAME}' />`)).toEqual([]);
    expect(rules("")).toEqual(["android-location-service"]);
    expect(rules(`<service android:name="${NAME}" android:foregroundServiceType="location"/>`)).toEqual(["android-location-service"]);
    expect(rules(`<service android:name="${NAME}" tools:node="replace"/>`)).toEqual(["android-location-service"]);
    expect(rules('<service android:name=".services.LocationTaskService" tools:node="remove"/>')).toEqual(["android-location-service"]);
    expect(rules('<service android:name="com.other.Service" tools:node="remove"/>')).toEqual(["android-location-service"]);
  });

  it("P4.2c-1: the config plugin writes exactly that entry (idempotent, adds the tools namespace, keeps other services) and is the second allow-listed local plugin", () => {
    const require = createRequire(import.meta.url);
    const plugin = require("../plugins/with-no-location-service.js") as { applyToManifest: (m: unknown) => { manifest: { $: Record<string, string>; application: { service?: { $: Record<string, string> }[] }[] } }; SERVICE: string };
    expect(plugin.SERVICE).toBe("expo.modules.location.services.LocationTaskService");
    const file = { manifest: { $: {}, application: [{ $: { "android:name": ".MainApplication" }, service: [{ $: { "android:name": "com.keep.Me" } }] }] } };
    const once = plugin.applyToManifest(structuredClone(file));
    expect(once.manifest.$["xmlns:tools"]).toBe("http://schemas.android.com/tools");
    expect(once.manifest.application[0]!.service).toEqual([{ $: { "android:name": "com.keep.Me" } }, { $: { "android:name": plugin.SERVICE, "tools:node": "remove" } }]);
    expect(plugin.applyToManifest(structuredClone(once))).toEqual(once);
    const kept = structuredClone(file);
    kept.manifest.application[0]!.service.push({ $: { "android:name": plugin.SERVICE } });
    expect(plugin.applyToManifest(kept).manifest.application[0]!.service!.at(-1)!.$["tools:node"]).toBe("remove");
    expect([...ALLOWED_PLUGINS].filter((p) => p.startsWith(".")).sort()).toEqual(["./modules/golfraven-attest/app.plugin.js", "./plugins/with-no-location-service.js"]);
    expect((appJson.expo?.plugins ?? []).map((p) => (Array.isArray(p) ? p[0] : p))).toContain("./plugins/with-no-location-service.js");
  });

  it("the allow-lists carry the two foreground permissions and nothing background", () => {
    expect([...ALLOWED_GRANTED_ANDROID_PERMISSIONS].filter((p) => /LOCATION/.test(p)).sort()).toEqual([COARSE, FINE]);
  });
});

describe("P4.2b-2 — a native module means a new prebuild: the allow-lists it must stay inside", () => {
  const plist = (body: string): string => `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>${body}</dict></plist>`;
  const SIWA = "<key>com.apple.developer.applesignin</key><array><string>Default</string></array>";
  const ATTEST = (v: string): string => `<key>com.apple.developer.devicecheck.appattest-environment</key><string>${v}</string>`;

  const APPLINKS = "<key>com.apple.developer.associated-domains</key><array><string>applinks:golfraven.app</string></array>";

  it("the entitlement scanner accepts exactly the allow-listed entitlements, and the App Attest value only as development | production", () => {
    expect(scanEntitlements(plist(SIWA + ATTEST("production") + APPLINKS))).toEqual([]);
    expect(scanEntitlements(plist(SIWA + ATTEST("development")))).toEqual([]);
    expect(scanEntitlements(plist(ATTEST("staging"))).map((v) => v.rule)).toEqual(["ios-entitlement-value"]);
    expect(scanEntitlements(plist(SIWA + "<key>aps-environment</key><string>production</string>")).map((v) => v.rule)).toEqual(["ios-entitlement"]);
    expect(scanEntitlements(plist(SIWA + "<key>com.apple.developer.healthkit</key><true/>")).map((v) => v.rule)).toEqual(["ios-entitlement"]);
    expect(scanEntitlements(plist(`<key>com.apple.developer.applesignin</key><array><string>Other</string></array>`)).map((v) => v.rule)).toEqual(["ios-entitlement-value"]);
    expect(scanEntitlements(plist(`<key>com.apple.developer.associated-domains</key><array><string>applinks:evil.example</string></array>`)).map((v) => v.rule)).toEqual([
      "ios-entitlement-value",
    ]);
    expect(Object.keys(ALLOWED_IOS_ENTITLEMENTS).sort()).toEqual([
      "com.apple.developer.applesignin",
      "com.apple.developer.associated-domains",
      "com.apple.developer.devicecheck.appattest-environment",
    ]);
  });

  it("app.json claims course-QR App Links for golfraven.app only (P5 §54)", () => {
    const ios = appJson.expo?.ios as { associatedDomains?: string[] } | undefined;
    const android = appJson.expo?.android as { intentFilters?: unknown[] } | undefined;
    expect(ios?.associatedDomains).toEqual(["applinks:golfraven.app"]);
    const filters = android?.intentFilters ?? [];
    expect(JSON.stringify(filters)).toContain("golfraven.app");
    expect(JSON.stringify(filters)).toContain("/q/m");
    expect(JSON.stringify(filters)).toContain("/q/f");
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

  it("the local attestation plugin is an allow-listed local plugin, and it is in the real app.json", () => {
    const local = [...ALLOWED_PLUGINS].filter((p) => p.startsWith(".")).sort();
    expect(local).toEqual(["./modules/golfraven-attest/app.plugin.js", "./plugins/with-no-location-service.js"]);
    const used = (appJson.expo?.plugins ?? []).map((p) => (Array.isArray(p) ? p[0] : p));
    expect(used).toContain("./modules/golfraven-attest/app.plugin.js");
    expect(existsSync(here("../modules/golfraven-attest/app.plugin.js"))).toBe(true);
  });

  it("the Android granted-permission scan: the allow-listed three pass; removals do not count as granted; any new permission (a dangerous one included) fails", () => {
    const m = (body: string): string => `<manifest xmlns:tools="x">${body}</manifest>`;
    const grant = (n: string): string => `<uses-permission android:name="${n}"/>`;
    expect(scanAndroidGrantedPermissions(m([...ALLOWED_GRANTED_ANDROID_PERMISSIONS].map(grant).join("")))).toEqual([]);
    expect(scanAndroidGrantedPermissions(m('<uses-permission android:name="android.permission.CAMERA" tools:node="remove"/>'))).toEqual([]);
    for (const bad of ["android.permission.CAMERA", "android.permission.READ_PHONE_STATE", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.ACTIVITY_RECOGNITION", "android.permission.FOREGROUND_SERVICE_LOCATION", "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE", "READ_CONTACTS"]) {
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

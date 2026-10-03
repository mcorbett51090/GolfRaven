/**
 * P4.2b-2: the LOCAL Expo module `modules/golfraven-attest`. Swift and Kotlin cannot be compiled here, so what can be checked is checked as text: the module is declared the way
 * Expo's autolinking discovers local modules, its function names equal the JS contract's, the one external Gradle dependency is pinned exactly, the native code is declarative
 * (it hashes nothing, keeps no state, retries nothing), and no third-party attestation package entered the JS dependencies.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findDeniedSdks, lockfilePackageNames } from "./support/policy-scan";

const here = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
const MOD = here("../modules/golfraven-attest");
const read = (rel: string): string => readFileSync(`${MOD}/${rel}`, "utf8");
const swift = read("ios/GolfravenAttestModule.swift");
const kotlin = read("android/src/main/java/expo/modules/golfravenattest/GolfravenAttestModule.kt");
const gradle = read("android/build.gradle");
const config = JSON.parse(read("expo-module.config.json")) as { platforms: string[]; apple: { modules: string[] }; android: { modules: string[] } };
const contract = readFileSync(here("../src/attest/native-module.ts"), "utf8");

/** The names the JS contract (`NativeAttestModule`) declares as methods. */
const CONTRACT_FUNCTIONS = ["capability", "generateKey", "attestKey", "generateAssertion", "deviceCheckToken", "integrityToken", "installLinkId"];

describe("the module is declared the way Expo autolinking finds a local module (modules/<name>/expo-module.config.json)", () => {
  it("expo-module.config.json names both platforms and the exact classes", () => {
    expect(config.platforms).toEqual(["apple", "android"]);
    expect(config.apple.modules).toEqual(["GolfravenAttestModule"]);
    expect(config.android.modules).toEqual(["expo.modules.golfravenattest.GolfravenAttestModule"]);
    expect(swift).toMatch(/public class GolfravenAttestModule: Module/);
    expect(kotlin).toMatch(/^package expo\.modules\.golfravenattest$/m);
    expect(kotlin).toMatch(/class GolfravenAttestModule : Module\(\)/);
  });

  it("both sides name the module `GolfravenAttest`, which is what the JS loader looks up", () => {
    expect(swift).toMatch(/Name\("GolfravenAttest"\)/);
    expect(kotlin).toMatch(/Name\("GolfravenAttest"\)/);
    expect(readFileSync(here("../src/attest/native-module-loader.ts"), "utf8")).toMatch(/NATIVE_MODULE_NAME = "GolfravenAttest"/);
  });

  it("the podspec and Gradle file exist where autolinking looks (ios/*.podspec, android/build.gradle) and the namespace matches the Kotlin package", () => {
    expect(readdirSync(`${MOD}/ios`).some((f) => f.endsWith(".podspec"))).toBe(true);
    expect(read("ios/GolfravenAttest.podspec")).toMatch(/s\.dependency 'ExpoModulesCore'/);
    expect(gradle).toMatch(/namespace "expo\.modules\.golfravenattest"/);
    expect(gradle).toMatch(/id 'expo-module-gradle-plugin'/);
    expect(existsSync(`${MOD}/android/src/main/AndroidManifest.xml`)).toBe(true);
  });

  it("the module's manifest asks for NO permission", () => {
    expect(read("android/src/main/AndroidManifest.xml")).not.toMatch(/uses-permission/);
  });
});

describe("the native function names are exactly the JS contract's", () => {
  const names = (src: string): string[] => [...src.matchAll(/AsyncFunction\("([A-Za-z]+)"\)/g)].map((m) => m[1]!).sort();
  it("Swift and Kotlin declare the same set, equal to the methods of `NativeAttestModule`", () => {
    expect(names(swift)).toEqual([...CONTRACT_FUNCTIONS].sort());
    expect(names(kotlin)).toEqual([...CONTRACT_FUNCTIONS].sort());
    for (const f of CONTRACT_FUNCTIONS) expect(contract, f).toMatch(new RegExp(`\\b${f}\\(`));
  });

  it("both report platform errors as a RESULT ({ ok:false, code, message }), with the closed code set the JS side switches on", () => {
    for (const src of [swift, kotlin]) {
      expect(src).toMatch(/"ok" to false|"ok": false/);
      for (const code of ["unsupported", "unavailable", "other"]) expect(src, code).toContain(`"${code}"`);
    }
    expect(swift).toContain('"invalid_key"'); // App Attest only
    expect(swift).toMatch(/case \.invalidKey/);
    expect(contract).toMatch(/"unsupported" \| "invalid_key" \| "unavailable" \| "other"|"unsupported" \/\/.*\n\s*\| "invalid_key"/);
  });
});

describe("the native code is declarative: it calls the platform API and reports the answer", () => {
  it("iOS uses the four App Attest / DeviceCheck calls and nothing else of substance", () => {
    for (const call of ["DCAppAttestService.shared.isSupported", "generateKey", "attestKey(keyId, clientDataHash: hash)", "generateAssertion(keyId, clientDataHash: hash)", "DCDevice.current.generateToken"]) expect(swift, call).toContain(call);
  });

  it("Android uses Play Integrity STANDARD requests: prepareIntegrityToken(cloudProjectNumber) then request(requestHash)", () => {
    for (const call of ["IntegrityManagerFactory.createStandard", "prepareIntegrityToken", "setCloudProjectNumber(project)", "StandardIntegrityTokenRequest.builder().setRequestHash(requestHash)"]) expect(kotlin, call).toContain(call);
    expect(kotlin).not.toMatch(/IntegrityManagerFactory\.create\(/); // not the classic request
  });

  it("neither side hashes, signs, retries or persists: the bindings are JS (tested against the server's vectors); there is no SHA / digest / retry / store in the native code", () => {
    for (const [name, src] of [["swift", swift], ["kotlin", kotlin]] as const) {
      const code = src.replace(/\/\/.*$/gm, "");
      expect(code, name).not.toMatch(/sha-?256|CC_SHA|CryptoKit|CommonCrypto|MessageDigest|digest\(/i);
      expect(code, name).not.toMatch(/retry|UserDefaults|SharedPreferences|Keychain/i);
    }
  });

  it("Android: every synchronous Play Integrity call is guarded (a throw resolves { ok:false }, never reaches the bridge), and permanent error codes map to `unsupported` while the rest are `unavailable`", () => {
    const code = kotlin.replace(/\/\/.*$/gm, "");
    expect((code.match(/catch \(e: Exception\)/g) ?? []).length).toBeGreaterThanOrEqual(3);
    expect(code).toMatch(/PERMANENT_CODES = setOf\(/);
    expect(code).toMatch(/failure\("unsupported", message\) else failure\("unavailable", message\)/);
    expect(code).toMatch(/StandardIntegrityException/);
  });

  it("the Cloud project number comes from the JS call (EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER), not from native code: no number is hard-coded", () => {
    expect(kotlin).not.toMatch(/\b\d{9,}\b/);
    expect(kotlin).toMatch(/cloudProjectNumber\.toLongOrNull\(\)/);
  });
});

describe("the one new external dependency is pinned exactly", () => {
  it("android/build.gradle depends on com.google.android.play:integrity at an exact x.y.z version: no '+', no range, no latest", () => {
    const deps = [...gradle.matchAll(/^\s*(?:implementation|api|compileOnly|runtimeOnly)\s+['"]([^'"]+)['"]/gm)].map((m) => m[1]!);
    expect(deps).toEqual(["com.google.android.play:integrity:1.6.0"]);
    expect(deps[0]).toMatch(/^[a-z.]+:[a-z-]+:\d+\.\d+\.\d+$/);
    expect(deps[0]).not.toMatch(/[+\[\](),]|latest/);
  });

  it("no other native dependency: no podspec dependency beyond ExpoModulesCore", () => {
    const deps = [...read("ios/GolfravenAttest.podspec").matchAll(/s\.dependency '([^']+)'/g)].map((m) => m[1]);
    expect(deps).toEqual(["ExpoModulesCore"]);
  });
});

describe("NO third-party npm attestation package", () => {
  const pkg = JSON.parse(readFileSync(here("../package.json"), "utf8")) as { dependencies: Record<string, string>; devDependencies: Record<string, string> };
  const lock = readFileSync(here("../../../pnpm-lock.yaml"), "utf8");
  const SUSPECT = /attest|integrity|app-check|appcheck|devicecheck|safetynet|play-integrity|jail|root-?detect/i;

  it("package.json gained no dependency with an attestation-shaped name, and `expo-modules-core` is NOT added (it stays a transitive dependency of expo)", () => {
    const all = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    expect(all.filter((n) => SUSPECT.test(n))).toEqual([]);
    expect(all).not.toContain("expo-modules-core");
    expect(all).not.toContain("@expo/app-integrity");
  });

  it("the lockfile has no attestation / integrity package either (and the denied-SDK scan stays clean)", () => {
    const names = lockfilePackageNames(lock);
    expect(names.filter((n) => /app-integrity|react-native-attest|play-integrity|expo-app-attest|appcheck|app-check/i.test(n))).toEqual([]);
    expect(findDeniedSdks(lock)).toEqual([]);
    expect(names).toContain("expo-modules-core"); // present, as a transitive dependency of expo
  });

  it("the JS reaches the module through `expo`'s own `requireOptionalNativeModule`, in ONE file the rest of src/attest never imports", () => {
    const loader = readFileSync(here("../src/attest/native-module-loader.ts"), "utf8");
    expect(loader).toMatch(/import \{ requireOptionalNativeModule \} from "expo";/);
    expect(readFileSync(here("../src/attest/index.ts"), "utf8")).not.toMatch(/native-module-loader/);
    const importers = readdirSync(here("../src"), { recursive: true, withFileTypes: false })
      .map(String)
      .filter((f) => /\.(ts|tsx)$/.test(f))
      .filter((f) => /from "[^"]*native-module-loader"/.test(readFileSync(here(`../src/${f}`), "utf8")));
    expect(importers.sort()).toEqual(["runtime/services.ts"]);
  });
});

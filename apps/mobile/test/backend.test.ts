/**
 * "Release builds never construct the mock." Three independent layers (see `src/dev-guard.ts`): selection, construction, bundling.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createMockApi } from "../src/api/mock";
import { createMockAuth, MOCK_OTP_CODE } from "../src/auth/mock-auth";
import { assertDevOnly, devOnly, MockInReleaseError, type DevOnly } from "../src/dev-guard";
import { createBackend, createUnconfiguredAuth, isBackendConfigured, selectBackendKind, type BackendConfig, type BackendDeps, type DevMocks } from "../src/runtime/backend";
import { MemorySecureStore } from "../src/secure";
import { createFakeGoTrue } from "./support/gotrue";
import { scriptedFetch } from "./support/edge-fixtures";

const FULL: BackendConfig = { apiBaseUrl: "https://p.supabase.co/functions/v1", supabaseUrl: "https://p.supabase.co", supabaseAnonKey: "sb_publishable_placeholder_000000" };
const NONE: BackendConfig = { apiBaseUrl: null, supabaseUrl: null, supabaseAnonKey: null };
const PARTIALS: BackendConfig[] = [
  { ...FULL, apiBaseUrl: null },
  { ...FULL, supabaseUrl: null },
  { ...FULL, supabaseAnonKey: null },
  { apiBaseUrl: FULL.apiBaseUrl, supabaseUrl: null, supabaseAnonKey: null },
];

function deps(over: Partial<BackendDeps> & { isDev: boolean; config: BackendConfig }): { d: BackendDeps; loaded: number[]; authBuilt: number[] } {
  const loaded: number[] = [];
  const authBuilt: number[] = [];
  const d: BackendDeps = {
    secure: new MemorySecureStore(),
    fetch: scriptedFetch({ status: 200, body: "{}" }).fetch,
    createAuth: () => {
      authBuilt.push(1);
      return createUnconfiguredAuth();
    },
    loadDevMocks: () => {
      loaded.push(1);
      const guard = devOnly(true);
      const api = createMockApi(guard);
      return { api, auth: createMockAuth(guard), apple: { availability: () => Promise.resolve("available"), authenticate: () => Promise.reject(new Error("x")) }, google: { availability: () => Promise.resolve("available"), authenticate: () => Promise.reject(new Error("x")) }, handle: api } satisfies DevMocks;
    },
    ...over,
  };
  return { d, loaded, authBuilt };
}

describe("layer 1 — selection: a release build is never 'demo'", () => {
  const table: [boolean, BackendConfig, string][] = [
    [true, FULL, "real"],
    [false, FULL, "real"],
    [true, NONE, "demo"],
    [false, NONE, "unconfigured"],
    ...PARTIALS.flatMap((c): [boolean, BackendConfig, string][] => [
      [true, c, "demo"],
      [false, c, "unconfigured"],
    ]),
  ];
  it.each(table)("isDev=%s config=%j => %s", (isDev, config, want) => {
    expect(selectBackendKind({ isDev, config })).toBe(want);
  });

  it("half a configuration is no configuration", () => {
    for (const c of PARTIALS) expect(isBackendConfigured(c)).toBe(false);
    expect(isBackendConfigured(FULL)).toBe(true);
  });
});

describe("layer 1+2 — createBackend in a RELEASE build never loads or builds a mock, whatever the config", () => {
  const configs: [string, BackendConfig][] = [["full", FULL], ["none", NONE], ...PARTIALS.map((c, i): [string, BackendConfig] => [`partial ${i}`, c])];
  it.each(configs)("%s", (_name, config) => {
    const { d, loaded } = deps({ isDev: false, config });
    const b = createBackend(d);
    expect(["real", "unconfigured"]).toContain(b.kind);
    expect(loaded).toEqual([]); // the dev mock loader was never called
    expect(b.devHandle).toBeNull();
    expect(b.demoAdapters).toBeNull();
  });

  it("a release build with no loader at all (the app passes null outside __DEV__) still works", () => {
    const { d } = deps({ isDev: false, config: NONE, loadDevMocks: null });
    expect(createBackend(d).kind).toBe("unconfigured");
  });

  it("release + configured => the real client and the real auth service are built (not the mock)", () => {
    const { d, authBuilt } = deps({ isDev: false, config: FULL });
    const b = createBackend(d);
    expect(b.kind).toBe("real");
    expect(authBuilt).toHaveLength(1);
  });

  it("the unconfigured release backend refuses network calls rather than faking data", async () => {
    const { d } = deps({ isDev: false, config: NONE });
    const b = createBackend(d);
    await expect(b.api.listSignInMethods()).rejects.toMatchObject({ kind: "not_configured" });
    await expect(b.auth.verifyEmailCode("a@b.co", MOCK_OTP_CODE)).rejects.toMatchObject({ name: "AuthError" });
    expect(b.auth.current()).toBeNull();
  });

  it("a debug build with no config gets the demo mocks (labelled), and only then", () => {
    const { d, loaded } = deps({ isDev: true, config: NONE });
    const b = createBackend(d);
    expect(b.kind).toBe("demo");
    expect(loaded).toHaveLength(1);
    expect(b.auth.current()).toBeNull();
    expect(b.demoAdapters).not.toBeNull();
  });

  it("demo selected but no loader present => a hard error, never a silent fallback to something else", () => {
    const { d } = deps({ isDev: true, config: NONE, loadDevMocks: null });
    expect(() => createBackend(d)).toThrow(/no dev mock loader/);
  });
});

describe("layer 2 — construction: a mock cannot be built without a token that only devOnly(true) can issue", () => {
  it("devOnly(false) throws MockInReleaseError", () => {
    expect(() => devOnly(false)).toThrow(MockInReleaseError);
  });

  it("the mock factories refuse a missing, forged or hand-made token", () => {
    for (const bad of [undefined, null, {}, Object.freeze({}), "token", 1]) {
      expect(() => createMockApi(bad as unknown as DevOnly)).toThrow(MockInReleaseError);
      expect(() => createMockAuth(bad as unknown as DevOnly)).toThrow(MockInReleaseError);
      expect(() => assertDevOnly(bad)).toThrow(MockInReleaseError);
    }
  });

  it("a real token works, and demo sessions are marked stub", async () => {
    const guard = devOnly(true);
    const auth = createMockAuth(guard);
    const s = await auth.signInWithIdToken({ provider: "apple", idToken: "x", nonce: "n" });
    expect(s.stub).toBe(true);
    expect(createMockApi(guard)).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------------------------------------------------------------------------
// Layer 3 — bundling. Source scans (the same technique as `policy.test.ts`'s lockfile scan): nothing may import a mock module statically, because
// a static import ships it in the release bundle even if it is never called. The one `require` sits under `__DEV__` so Metro drops it.
// ---------------------------------------------------------------------------------------------------------------------------------------------
const root = dirname(dirname(fileURLToPath(import.meta.url)));
function sources(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? sources(p) : /\.(ts|tsx)$/.test(n) ? [p] : [];
  });
}
const appFiles = [...sources(join(root, "src")), ...sources(join(root, "app"))];
const rel = (f: string): string => relative(root, f);
const text = (f: string): string => readFileSync(f, "utf8");

describe("layer 3 — bundling: no static path to a mock module from app code", () => {
  it("the scan is not vacuous", () => {
    expect(appFiles.length).toBeGreaterThan(50);
    expect(appFiles.map(rel)).toContain("src/runtime/dev-backend.ts");
  });

  it("no file statically imports or re-exports api/mock or auth/mock-auth", () => {
    // `import type` / `export type` are erased by the compiler and ship nothing, so they are not a bundling path.
    const re = /(?:import|export)\s[^;]*?from\s*["'][^"']*(?:\/mock|\/mock-auth|api\/mock|auth\/mock-auth)["']/;
    const hits = appFiles.filter((f) => re.test(text(f).replace(/(?:import|export) type\s[^;]*;/g, ""))).map(rel);
    expect(hits).toEqual([]);
  });

  it("the mock modules are required in exactly one file, under a __DEV__ conditional", () => {
    const requirers = appFiles.filter((f) => /require\(\s*["'][^"']*(?:\/mock|mock-auth)["']\s*\)/.test(text(f))).map(rel);
    expect(requirers).toEqual(["src/runtime/dev-backend.ts"]);
    const src = text(join(root, "src/runtime/dev-backend.ts"));
    expect(src).toMatch(/__DEV__\s*\?\s*\(\)\s*=>/); // `__DEV__ ? () => {… require(...) …} : null`
    expect(src).toMatch(/:\s*null;\s*$/m);
  });

  it("api/index.ts and auth/index.ts do not re-export the mocks", () => {
    expect(text(join(root, "src/api/index.ts")).replace(/\/\/.*$/gm, "")).not.toMatch(/mock/i);
    expect(text(join(root, "src/auth/index.ts")).replace(/\/\/.*$/gm, "")).not.toMatch(/mock/i);
  });

  it("the composition root takes its mocks only from loadDevMocks, and the dev panel narrows a handle instead of importing the mock", () => {
    const services = text(join(root, "src/runtime/services.ts"));
    expect(services).toMatch(/loadDevMocks/);
    expect(services).not.toMatch(/createMockApi|createMockAuth/);
    expect(text(join(root, "src/screens/DevPanel.tsx"))).toMatch(/import type \{ MockApi \}/);
  });
});

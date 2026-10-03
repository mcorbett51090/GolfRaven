/** `EXPO_PUBLIC_API_BASE_URL` / `EXPO_PUBLIC_SUPABASE_URL` / `EXPO_PUBLIC_SUPABASE_ANON_KEY`: public values only, validated. */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseApiBaseUrl, parseCatalogBaseUrl, parseSupabaseAnonKey, parseSupabaseUrl } from "../src/config-values";
import { b64url } from "./support/fakes";

const jwtWithRole = (role: unknown): string => `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify({ iss: "supabase", role }))}.${b64url("signature-signature-signature")}`;

describe("parseApiBaseUrl (same pattern as the catalog URL)", () => {
  it("accepts https only; local http only for a development build", () => {
    expect(parseApiBaseUrl("https://p.supabase.co/functions/v1")).toBe("https://p.supabase.co/functions/v1");
    expect(parseApiBaseUrl("https://p.supabase.co/functions/v1/")).toBe("https://p.supabase.co/functions/v1");
    expect(parseApiBaseUrl("http://p.supabase.co/functions/v1")).toBeNull();
    expect(parseApiBaseUrl("http://localhost:54321/functions/v1")).toBeNull();
    expect(parseApiBaseUrl("http://localhost:54321/functions/v1", { allowLocalHttp: true })).toBe("http://localhost:54321/functions/v1");
    expect(parseApiBaseUrl("http://evil.example/functions/v1", { allowLocalHttp: true })).toBeNull();
    for (const bad of [undefined, null, "", "   ", "ftp://x.co", "https://", "https://user:pw@host/x", "https://host/ path", "javascript:alert(1)", "//host/x"]) expect(parseApiBaseUrl(bad as string)).toBeNull();
  });

  it("is literally the catalog URL rule (one pattern, two uses)", () => {
    for (const v of ["https://a.co/x", "http://localhost:1/x", "https://a.co:8443/y/", "nope"]) {
      expect(parseApiBaseUrl(v, { allowLocalHttp: true })).toBe(parseCatalogBaseUrl(v, { allowLocalHttp: true }));
    }
  });
});

describe("parseSupabaseUrl: an origin, no path", () => {
  it("accepts the project origin only", () => {
    expect(parseSupabaseUrl("https://abc.supabase.co")).toBe("https://abc.supabase.co");
    expect(parseSupabaseUrl("https://abc.supabase.co/")).toBe("https://abc.supabase.co");
    expect(parseSupabaseUrl("https://abc.supabase.co/auth/v1")).toBeNull();
    expect(parseSupabaseUrl("http://abc.supabase.co")).toBeNull();
    expect(parseSupabaseUrl("http://10.0.2.2:54321", { allowLocalHttp: true })).toBe("http://10.0.2.2:54321");
    expect(parseSupabaseUrl(undefined)).toBeNull();
  });
});

describe("parseSupabaseAnonKey: only a PUBLIC key can be bundled", () => {
  it("accepts a legacy anon JWT and a publishable key", () => {
    const anon = jwtWithRole("anon");
    expect(parseSupabaseAnonKey(anon)).toBe(anon);
    expect(parseSupabaseAnonKey(` ${anon}\n`)).toBe(anon);
    expect(parseSupabaseAnonKey("sb_publishable_abcdefghijklmnopqrstuvwxyz")).toBe("sb_publishable_abcdefghijklmnopqrstuvwxyz");
  });

  it("REFUSES a service_role key, a secret key, a JWT with no readable role, and junk", () => {
    expect(parseSupabaseAnonKey(jwtWithRole("service_role"))).toBeNull();
    expect(parseSupabaseAnonKey(jwtWithRole("authenticated"))).toBeNull();
    expect(parseSupabaseAnonKey(jwtWithRole(undefined))).toBeNull();
    expect(parseSupabaseAnonKey(jwtWithRole(5))).toBeNull();
    expect(parseSupabaseAnonKey("sb_secret_abcdefghijklmnopqrstuvwxyz")).toBeNull();
    expect(parseSupabaseAnonKey("sb_publishable_has space_xxxxxxxxxxxxxx")).toBeNull();
    for (const bad of [undefined, null, "", "short", "a.b.c", "x".repeat(30), `${"e".repeat(30)}.${"f".repeat(30)}.${"g".repeat(30)}`, "x".repeat(3000)]) expect(parseSupabaseAnonKey(bad as string)).toBeNull();
  });
});

describe("no secrets in the repo or the bundle (rule: every key and URL comes from public EXPO_PUBLIC_* config)", () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const files = (dir: string): string[] => readdirSync(dir).flatMap((n) => (n === "node_modules" ? [] : statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : /\.(tsx?|json)$/.test(n) ? [join(dir, n)] : []));
  const shipped = [...files(join(root, "src")), ...files(join(root, "app")), join(root, "app.json")];
  const raw = (f: string): string => readFileSync(f, "utf8");
  /** Code only: comments may (and do) discuss service-role keys and AsyncStorage in order to say they are not used. */
  const text = (f: string): string => raw(f).replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|\s)\/\/.*$/gm, "$1");

  it("the scan sees the sources", () => {
    expect(shipped.length).toBeGreaterThan(60);
  });

  it("no JWT-shaped literal, no service-role or secret-key wording, anywhere that ships", () => {
    for (const f of shipped) {
      const src = text(f);
      expect(src, relative(root, f)).not.toMatch(/eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\./);
      expect(src, relative(root, f)).not.toMatch(/service_role|SERVICE_ROLE|sb_secret_(?!")/);
    }
  });

  it("the only environment variables read are the documented PUBLIC ones", () => {
    const names = new Set<string>();
    for (const f of shipped) for (const m of text(f).matchAll(/process\.env\.([A-Z0-9_]+)/g)) names.add(m[1]!);
    expect([...names].sort()).toEqual(["EXPO_PUBLIC_API_BASE_URL", "EXPO_PUBLIC_CATALOG_BASE_URL", "EXPO_PUBLIC_STORE_URL", "EXPO_PUBLIC_SUPABASE_ANON_KEY", "EXPO_PUBLIC_SUPABASE_URL"]);
    expect([...names].filter((n) => !n.startsWith("EXPO_PUBLIC_"))).toEqual([]);
  });

  it("the app never hands the session to anything but the secure store: no AsyncStorage / localStorage / SQLite writes of tokens", () => {
    for (const f of shipped.filter((x) => x.endsWith(".ts") || x.endsWith(".tsx"))) {
      const src = text(f);
      expect(src, relative(root, f)).not.toMatch(/\bAsyncStorage\b|\blocalStorage\b|\bsessionStorage\b/);
    }
    const sb = text(join(root, "src/auth/supabase-auth.ts"));
    expect(sb).toMatch(/storage:\s*sessionStorageAdapter\(opts\.storage\)/);
    expect(sb).toMatch(/storageKey:\s*SESSION_STORAGE_KEY/);
    const pkg = JSON.parse(text(join(root, "package.json"))) as { dependencies: Record<string, string> };
    expect(Object.keys(pkg.dependencies)).not.toContain("@react-native-async-storage/async-storage");
  });
});

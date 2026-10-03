/**
 * LOW-1: a SECRET key in an `EXPO_PUBLIC_*` variable would be inlined into the bundle by Metro. `scripts/check-public-env.mjs` runs the app's own
 * parser over the build environment before `expo export` / an EAS build and exits non-zero on one. Run here as a real child process.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findPublicEnvProblems, isSecretShapedKey, parseSupabaseAnonKey } from "../src/config-values";
import { b64url } from "./support/fakes";

const SCRIPT = fileURLToPath(new URL("../scripts/check-public-env.mjs", import.meta.url));
const jwt = (role: unknown) => `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify({ iss: "supabase", role }))}.${b64url("signature-signature")}`;
const ANON = jwt("anon");
const SERVICE_ROLE = jwt("service_role");
const SB_SECRET = "sb_secret_abcdefghijklmnopqrstuvwxyz0123456789";
const PUBLISHABLE = "sb_publishable_abcdefghijklmnopqrstuvwxyz";

/** Runs the guard with ONLY the given environment (plus PATH), in an empty project root holding the given `.env*` files. */
function run(env: Record<string, string>, files: Record<string, string> = {}) {
  const root = mkdtempSync(join(tmpdir(), "gr-public-env-"));
  try {
    for (const [name, text] of Object.entries(files)) writeFileSync(join(root, name), text);
    const r = spawnSync(process.execPath, [SCRIPT, "--root", root], { env: { PATH: process.env.PATH ?? "", ...env } as unknown as NodeJS.ProcessEnv, encoding: "utf8" });
    return { code: r.status, out: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("findPublicEnvProblems (the rule)", () => {
  it("accepts public keys and unset/empty values", () => {
    expect(findPublicEnvProblems({})).toEqual([]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: ANON, EXPO_PUBLIC_API_BASE_URL: "https://x.supabase.co/functions/v1" })).toEqual([]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: PUBLISHABLE })).toEqual([]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: "  " })).toEqual([]);
    expect(findPublicEnvProblems({ SUPABASE_SERVICE_ROLE_KEY: SERVICE_ROLE })).toEqual([]); // not a public variable: not Metro's business
  });

  it("flags a secret-shaped value in ANY EXPO_PUBLIC_ variable, by name, never by value", () => {
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: SERVICE_ROLE })).toEqual([{ name: "EXPO_PUBLIC_SUPABASE_ANON_KEY", problem: "secret_shaped" }]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: SB_SECRET })).toEqual([{ name: "EXPO_PUBLIC_SUPABASE_ANON_KEY", problem: "secret_shaped" }]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_OTHER: ` ${SB_SECRET}\n` })).toEqual([{ name: "EXPO_PUBLIC_OTHER", problem: "secret_shaped" }]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_X: jwt("authenticated") })).toEqual([{ name: "EXPO_PUBLIC_X", problem: "secret_shaped" }]);
  });

  it("flags a set anon key the app would refuse (junk, a JWT with no readable role)", () => {
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: "not-a-key-but-long-enough-xx" })).toEqual([{ name: "EXPO_PUBLIC_SUPABASE_ANON_KEY", problem: "unusable_anon_key" }]);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: jwt(undefined) })).toEqual([{ name: "EXPO_PUBLIC_SUPABASE_ANON_KEY", problem: "unusable_anon_key" }]);
  });

  it("is consistent with the runtime parser: whatever the parser refuses as a secret, the guard refuses", () => {
    for (const k of [SERVICE_ROLE, SB_SECRET]) {
      expect(parseSupabaseAnonKey(k)).toBeNull();
      expect(isSecretShapedKey(k)).toBe(true);
    }
    for (const k of [ANON, PUBLISHABLE]) {
      expect(parseSupabaseAnonKey(k)).toBe(k);
      expect(isSecretShapedKey(k)).toBe(false);
    }
  });
});

describe("scripts/check-public-env.mjs (a real child process)", () => {
  it("exits 0 with a clean or empty environment", () => {
    expect(run({}).code).toBe(0);
    expect(run({ EXPO_PUBLIC_SUPABASE_ANON_KEY: ANON, EXPO_PUBLIC_SUPABASE_URL: "https://x.supabase.co" }).code).toBe(0);
    expect(run({ EXPO_PUBLIC_SUPABASE_ANON_KEY: PUBLISHABLE }).code).toBe(0);
  });

  it("exits 1 on a service_role JWT or an sb_secret_ key in process.env, and prints the NAME but never the value", () => {
    for (const secret of [SERVICE_ROLE, SB_SECRET]) {
      const r = run({ EXPO_PUBLIC_SUPABASE_ANON_KEY: secret });
      expect(r.code).toBe(1);
      expect(r.out).toContain("EXPO_PUBLIC_SUPABASE_ANON_KEY");
      expect(r.out).not.toContain(secret);
      expect(r.out).not.toContain(secret.slice(10, 30));
    }
  });

  it("exits 1 for a secret in the wrong EXPO_PUBLIC_ variable, and for an unusable anon key", () => {
    expect(run({ EXPO_PUBLIC_SOMETHING: SB_SECRET }).code).toBe(1);
    expect(run({ EXPO_PUBLIC_SUPABASE_ANON_KEY: "junk-junk-junk-junk-junk-junk" }).code).toBe(1);
  });

  it("also reads the .env files Expo loads (a key pasted into .env.production is bundled just the same)", () => {
    expect(run({}, { ".env.production": `# comment\nEXPO_PUBLIC_SUPABASE_ANON_KEY="${SERVICE_ROLE}"\n` }).code).toBe(1);
    expect(run({}, { ".env": `export EXPO_PUBLIC_SUPABASE_ANON_KEY=${SB_SECRET} # oops\n` }).code).toBe(1);
    expect(run({}, { ".env.local": `EXPO_PUBLIC_SUPABASE_ANON_KEY='${ANON}'\nSOME_SERVER_ONLY=${SERVICE_ROLE}\n` }).code).toBe(0);
  });
});

describe("a checker that cannot run exits 2, never 1 (LOW-2: a broken checker must not read as a leaked secret)", () => {
  it("exits 2 with a 'could not run' message when the parser it imports cannot load (scratch copy with no src/)", () => {
    const dir = mkdtempSync(join(tmpdir(), "gr-public-env-broken-"));
    try {
      mkdirSync(join(dir, "scripts"));
      copyFileSync(SCRIPT, join(dir, "scripts", "check-public-env.mjs"));
      const r = spawnSync(process.execPath, [join(dir, "scripts", "check-public-env.mjs"), "--root", dir], { env: { PATH: process.env.PATH ?? "" } as unknown as NodeJS.ProcessEnv, encoding: "utf8" });
      expect(r.status).toBe(2);
      expect(r.stderr).toMatch(/guard could not run/);
      expect(r.stderr).not.toMatch(/SECRET key/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still exits 1 (not 2) for a real finding", () => {
    expect(run({ EXPO_PUBLIC_SUPABASE_ANON_KEY: SB_SECRET }).code).toBe(1);
  });
});

describe("the guard is wired in front of export and EAS builds (package.json)", () => {
  const scripts = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { scripts: Record<string, string> }).scripts;
  it("export:ios, export:android and the EAS pre-install hook run it first", () => {
    expect(scripts["export:ios"]).toMatch(/^node scripts\/check-public-env\.mjs && node scripts\/export-and-scan\.mjs --clear --platform ios$/);
    expect(scripts["export:android"]).toMatch(/^node scripts\/check-public-env\.mjs && node scripts\/export-and-scan\.mjs --clear --platform android$/);
    expect(scripts["eas-build-pre-install"]).toBe("node scripts/check-public-env.mjs");
    expect(scripts["check:public-env"]).toBe("node scripts/check-public-env.mjs");
  });
});

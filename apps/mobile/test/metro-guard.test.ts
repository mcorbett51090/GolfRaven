/**
 * LOW-3 (PR #37 gate): the public-env guard runs from `metro.config.js`, so EVERY path that bundles the app runs it (`expo start`, `expo export`,
 * `expo run:*`, `eas update`, Gradle / Xcode). Run here as real child processes.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { b64url } from "./support/fakes";

const APP = fileURLToPath(new URL("..", import.meta.url));
const CONFIG = join(APP, "metro.config.js");
const SECRET = `sb_secret_${"abcdefghijklmnopqrstuvwxyz0123456789"}`;
const serviceRole = `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify({ iss: "supabase", role: "service_role" }))}.${b64url("signature-signature")}`;

function load(configPath: string, env: Record<string, string>) {
  const r = spawnSync(process.execPath, ["-e", `const c = require(${JSON.stringify(configPath)}); console.log(JSON.stringify({ keys: Object.keys(c).length }))`], {
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", ...env } as unknown as NodeJS.ProcessEnv,
    encoding: "utf8",
    cwd: APP,
  });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

describe("metro.config.js runs the public-env guard", () => {
  it("normal local development, with NO EXPO_PUBLIC_* environment at all: Metro's config loads, silently, with Expo's defaults", () => {
    const r = load(CONFIG, {});
    expect(r.code).toBe(0);
    expect(r.err).toBe("");
    expect(JSON.parse(r.out).keys).toBeGreaterThan(5); // expo/metro-config's real default config
  });

  it("with only PUBLIC values set it loads", () => {
    expect(load(CONFIG, { EXPO_PUBLIC_API_BASE_URL: "https://x.supabase.co/functions/v1", EXPO_PUBLIC_SUPABASE_ANON_KEY: "sb_publishable_abcdefghijklmnopqrstuvwxyz" }).code).toBe(0);
  });

  it.each([
    ["an sb_secret_ key", SECRET],
    ["a service_role JWT", serviceRole],
  ])("%s in an EXPO_PUBLIC_* variable fails the bundle, naming the variable and NEVER printing the value", (_n, value) => {
    const r = load(CONFIG, { EXPO_PUBLIC_SUPABASE_ANON_KEY: value });
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/EXPO_PUBLIC_SUPABASE_ANON_KEY/);
    expect(r.err).toMatch(/refusing to bundle/);
    expect(r.out + r.err).not.toContain(value);
    expect(r.out + r.err).not.toContain(value.slice(0, 20));
  });

  it("exit code 1 is a FINDING ('secret-shaped value'); exit 2 or anything else is 'could not run'; BOTH block the bundle (fail closed) (script stubbed in a scratch copy)", () => {
    const dir = mkdtempSync(join(tmpdir(), "gr-metro-"));
    try {
      symlinkSync(join(APP, "node_modules"), join(dir, "node_modules"));
      copyFileSync(CONFIG, join(dir, "metro.config.js"));
      mkdirSync(join(dir, "scripts"));
      const stub = (body: string) => writeFileSync(join(dir, "scripts", "check-public-env.mjs"), body);
      stub("process.exit(0);");
      expect(load(join(dir, "metro.config.js"), {}).code).toBe(0);

      stub('console.error("check-public-env: EXPO_PUBLIC_X looks like a SECRET"); process.exit(1);');
      const found = load(join(dir, "metro.config.js"), {});
      expect(found.code).not.toBe(0);
      expect(found.err).toMatch(/EXPO_PUBLIC_X/);
      expect(found.err).toMatch(/secret-shaped value/);
      expect(found.err).not.toMatch(/could not run/);

      for (const exit of ["process.exit(2);", "process.exit(3);", 'process.kill(process.pid, "SIGKILL");']) {
        stub(exit);
        const broken = load(join(dir, "metro.config.js"), {});
        expect(broken.code, exit).not.toBe(0);
        expect(broken.err, exit).toMatch(/env guard could not run/);
        expect(broken.err, exit).not.toMatch(/secret-shaped value/);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("source: the config calls the guard script before exporting Expo's defaults, and the explicit scripts remain", () => {
    const src = readFileSync(CONFIG, "utf8");
    expect(src).toMatch(/check-public-env\.mjs/);
    expect(src.indexOf("runPublicEnvGuard();")).toBeLessThan(src.indexOf("module.exports"));
    expect(src).toMatch(/getDefaultConfig\(__dirname\)/);
    const pkg = JSON.parse(readFileSync(join(APP, "package.json"), "utf8")) as { scripts: Record<string, string> };
    expect(pkg.scripts["check:public-env"]).toBeTruthy();
    expect(pkg.scripts["export:ios"]).toMatch(/check-public-env/);
    expect(pkg.scripts["export:android"]).toMatch(/check-public-env/);
    expect(pkg.scripts["eas-build-pre-install"]).toMatch(/check-public-env/);
  });
});

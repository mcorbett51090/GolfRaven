/** P4.2b-2: `EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER`, the public Cloud project number Play Integrity requests are made for. Public, not a secret: the env guard must not flag it. */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findPublicEnvProblems, isSecretShapedKey, parsePlayCloudProjectNumber } from "../src/config-values";

const GUARD = fileURLToPath(new URL("../scripts/check-public-env.mjs", import.meta.url));

describe("parsePlayCloudProjectNumber", () => {
  it("accepts a plain number of 1 to 18 digits with no leading zero, trimmed", () => {
    for (const v of ["1", "123456789012", " 123456789012 ", "999999999999999999"]) expect(parsePlayCloudProjectNumber(v), v).toBe(v.trim());
  });
  it("refuses everything else: empty, unset, a leading zero, signs, separators, hex, a JWT, a URL, 19+ digits", () => {
    for (const v of [undefined, null, "", "  ", "0", "012345", "-1", "+1", "1e9", "12 34", "12,34", "0x10", "abc", "projects/123", "https://x.example", "1".repeat(19), "eyJhbGciOi.eyJyb2xlIjoiYW5vbiJ9.c2ln"]) {
      expect(parsePlayCloudProjectNumber(v as string | undefined), String(v)).toBeNull();
    }
  });
});

describe("the public-env guard and the Cloud project number", () => {
  it("a project number is not secret-shaped and is never reported, in any EXPO_PUBLIC_* variable", () => {
    expect(isSecretShapedKey("123456789012")).toBe(false);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER: "123456789012" })).toEqual([]);
  });

  it("the real guard script (a child process) exits 0 with it set, and still exits 1 for a secret next to it", () => {
    const run = (env: Record<string, string>) => spawnSync(process.execPath, [GUARD], { env: { PATH: process.env.PATH ?? "", ...env } as unknown as NodeJS.ProcessEnv, encoding: "utf8" });
    const ok = run({ EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER: "123456789012" });
    expect(ok.status).toBe(0);
    expect(ok.stderr).toBe("");
    const secret = `sb_secret_${"abcdefghijklmnopqrstuvwxyz0123456789"}`;
    const bad = run({ EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER: "123456789012", EXPO_PUBLIC_SUPABASE_ANON_KEY: secret });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("EXPO_PUBLIC_SUPABASE_ANON_KEY");
    expect(bad.stderr).not.toContain("EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER");
    expect(bad.stderr).not.toContain(secret);
  });
});

describe("the secret prefix is built from parts but still recognised (src/config-values.ts SB_SECRET_PREFIX)", () => {
  const SECRET = `sb_secret_${"abcdefghijklmnopqrstuvwxyz0123456789"}`;
  it("isSecretShapedKey and findPublicEnvProblems behave exactly as with the literal", () => {
    expect(isSecretShapedKey(SECRET)).toBe(true);
    expect(isSecretShapedKey("sb_publishable_abcdefghijklmnopqrstuvwxyz")).toBe(false);
    expect(findPublicEnvProblems({ EXPO_PUBLIC_SUPABASE_ANON_KEY: SECRET })).toEqual([{ name: "EXPO_PUBLIC_SUPABASE_ANON_KEY", problem: "secret_shaped" }]);
  });
});

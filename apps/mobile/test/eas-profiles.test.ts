/**
 * The EAS build profiles (`apps/mobile/eas.json`). The one thing a profile decides that this repository can check without an Expo account is the iOS App Attest
 * ENVIRONMENT: `modules/golfraven-attest/app.plugin.js` reads the build-time variable `GOLFRAVEN_APP_ATTEST_ENV` (`development` | `production`; unset means `production`) and writes it into
 * the entitlement `com.apple.developer.devicecheck.appattest-environment`. A key attested in one environment does not verify as the other at the server, so a profile that left the value unset,
 * misspelled it or put it in an `EXPO_PUBLIC_*` variable (which Metro inlines into the shipped bundle, and which the plugin does not read) would silently produce the wrong entitlement.
 *
 * What is checked here is the FILE. What EAS does with it (that `env` reaches the prebuild, what `distribution: "store"` signs with, `autoIncrement`, `appVersionSource`) is
 * `[unverified — training knowledge]`: it can only be exercised by a real `eas build`, which needs an Expo account and Apple credentials.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
const eas = JSON.parse(readFileSync(here("../eas.json"), "utf8")) as { build?: Record<string, { env?: Record<string, unknown>; distribution?: string; developmentClient?: boolean }> };
const { environmentFrom } = createRequire(import.meta.url)("../modules/golfraven-attest/app.plugin.js") as { environmentFrom: (env: Record<string, string | undefined>) => string };

const KEY = "GOLFRAVEN_APP_ATTEST_ENV";
const profiles = Object.entries(eas.build ?? {});

describe("eas.json build profiles", () => {
  it("declares exactly the three profiles the runbook names", () => {
    expect(profiles.map(([name]) => name).sort()).toEqual(["development", "preview", "production"]);
  });

  it.each(profiles)("%s sets GOLFRAVEN_APP_ATTEST_ENV to development or production (never unset, never anything else)", (_name, p) => {
    const value = p.env?.[KEY];
    expect(["development", "production"]).toContain(value);
    // and the plugin accepts it as written (the plugin throws on any other value)
    expect(environmentFrom({ [KEY]: value as string })).toBe(value);
  });

  it.each(profiles)("%s never carries GOLFRAVEN_APP_ATTEST_ENV in an EXPO_PUBLIC_* variable (those are inlined into the bundle)", (_name, p) => {
    const names = Object.keys(p.env ?? {});
    expect(names.filter((n) => n.startsWith("EXPO_PUBLIC_") && /ATTEST/i.test(n))).toEqual([]);
    expect(names).not.toContain(`EXPO_PUBLIC_${KEY}`);
    expect(JSON.stringify(p.env ?? {})).not.toMatch(/EXPO_PUBLIC_[A-Z_]*ATTEST/);
  });

  it.each(profiles)("%s carries no EXPO_PUBLIC_* variable at all, and no secret-shaped name (those values are set in EAS, not committed)", (_name, p) => {
    for (const n of Object.keys(p.env ?? {})) {
      expect(n.startsWith("EXPO_PUBLIC_"), `${n}: public values are set in the EAS environment, never in a committed file`).toBe(false);
      expect(n, `${n} looks like a secret`).not.toMatch(/SECRET|PRIVATE|SERVICE_ROLE|\.p8|PASSWORD|TOKEN/i);
    }
  });

  it("development is the dev client on the development attest environment; preview is internal on production; production is the store build on production", () => {
    const b = eas.build!;
    expect(b.development).toMatchObject({ developmentClient: true, distribution: "internal", env: { [KEY]: "development" } });
    expect(b.preview).toMatchObject({ distribution: "internal", env: { [KEY]: "production" } });
    expect(b.preview!.developmentClient).not.toBe(true);
    expect(b.production).toMatchObject({ distribution: "store", env: { [KEY]: "production" } });
    expect(b.production!.developmentClient).not.toBe(true);
  });

  it("holds no Apple or Expo identifier (the repository is public: those are placeholders in the README, set by the owner)", () => {
    const text = readFileSync(here("../eas.json"), "utf8");
    // Apple ids: a team id is 10 uppercase alphanumerics, an App Store Connect app id 9-10 digits; EAS project ids are uuids; submit.* blocks carry ascAppId / appleId / appleTeamId
    expect(text).not.toMatch(/\b[A-Z0-9]{10}\b/);
    expect(text).not.toMatch(/\b\d{9,10}\b/);
    expect(text).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    expect(text).not.toMatch(/ascAppId|appleId|appleTeamId|projectId|@/);
  });

  it("the check is not vacuous: a profile with the value missing, misspelled or public would be caught", () => {
    const bad = (env: Record<string, unknown> | undefined): boolean => {
      const v = env?.[KEY];
      const publicLeak = Object.keys(env ?? {}).some((n) => n.startsWith("EXPO_PUBLIC_") && /ATTEST/i.test(n));
      return !["development", "production"].includes(v as string) || publicLeak;
    };
    expect(bad(undefined)).toBe(true);
    expect(bad({})).toBe(true);
    expect(bad({ [KEY]: "Production" })).toBe(true);
    expect(bad({ [KEY]: "staging" })).toBe(true);
    expect(bad({ EXPO_PUBLIC_GOLFRAVEN_APP_ATTEST_ENV: "production" })).toBe(true);
    expect(bad({ [KEY]: "production", EXPO_PUBLIC_GOLFRAVEN_APP_ATTEST_ENV: "production" })).toBe(true);
    expect(bad({ [KEY]: "production" })).toBe(false);
  });
});

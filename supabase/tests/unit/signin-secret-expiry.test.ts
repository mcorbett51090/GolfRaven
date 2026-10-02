// §4.8's monthly check: fails when the Apple client secret expires within 30 days. The pure core and the runnable script agree.

import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { checkClientSecretExpiry } from "../../functions/_shared/signin/secret-expiry.ts";
import { NOW_MS, NOW_SEC, signRs256, makeRsaKey } from "./signin-test-helpers.ts";

const DAY = 86_400;
async function jwtExpiringIn(days: number, extra: Record<string, unknown> = {}): Promise<string> {
  const k = await makeRsaKey("k");
  return signRs256(k.privateKey, { alg: "RS256", kid: "k" }, { iss: "TEAM", iat: NOW_SEC - 100, exp: NOW_SEC + Math.round(days * DAY), ...extra });
}

describe("checkClientSecretExpiry", () => {
  it("ok with more than 30 days left", async () => {
    const v = checkClientSecretExpiry(await jwtExpiringIn(90), NOW_MS);
    expect(v).toMatchObject({ ok: true, reason: "ok" });
    expect(Math.round(v.daysLeft!)).toBe(90);
  });

  it("FAILS within 30 days, and exactly at the boundary side", async () => {
    expect(checkClientSecretExpiry(await jwtExpiringIn(29), NOW_MS)).toMatchObject({ ok: false, reason: "expires_soon" });
    expect(checkClientSecretExpiry(await jwtExpiringIn(29.99), NOW_MS).ok).toBe(false);
    expect(checkClientSecretExpiry(await jwtExpiringIn(30.01), NOW_MS).ok).toBe(true);
  });

  it("fails when already expired", async () => {
    expect(checkClientSecretExpiry(await jwtExpiringIn(-1), NOW_MS)).toMatchObject({ ok: false, reason: "expired" });
  });

  it("fails closed on a malformed JWT or one with no exp (never 'ok' by default)", async () => {
    expect(checkClientSecretExpiry("not-a-jwt", NOW_MS)).toMatchObject({ ok: false, reason: "malformed" });
    expect(checkClientSecretExpiry("a.!!!.c", NOW_MS)).toMatchObject({ ok: false, reason: "malformed" });
    expect(checkClientSecretExpiry(await jwtExpiringIn(90, { exp: "soon" }), NOW_MS)).toMatchObject({ ok: false, reason: "no_exp" });
  });

  it("the threshold is configurable", async () => {
    expect(checkClientSecretExpiry(await jwtExpiringIn(45), NOW_MS, 60).ok).toBe(false);
    expect(checkClientSecretExpiry(await jwtExpiringIn(45), NOW_MS, 30).ok).toBe(true);
  });
});

describe("tools/apple/check-siwa-secret-expiry.mjs (the scheduled form)", () => {
  const script = new URL("../../../tools/apple/check-siwa-secret-expiry.mjs", import.meta.url).pathname;
  // The script reads the real clock, so the fixtures are relative to Date.now(), not to the fixed test clock.
  async function real(days: number) {
    const k = await makeRsaKey("k");
    const now = Math.floor(Date.now() / 1000);
    return signRs256(k.privateKey, { alg: "RS256", kid: "k" }, { iss: "TEAM", iat: now - 100, exp: now + Math.round(days * DAY) });
  }
  const run = (jwt: string | null, args: string[] = [], env: Record<string, string> = {}) =>
    spawnSync(process.execPath, [script, ...args], { input: jwt ?? "", encoding: "utf8", env: { PATH: process.env.PATH ?? "", ...env } });

  it("exit 0 with more than 30 days left, reading the JWT from stdin", async () => {
    const r = run(await real(100));
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/ok/i);
  });

  it("exit 1 within 30 days, and the output says when it expires and never prints the secret", async () => {
    const jwt = await real(10);
    const r = run(jwt);
    expect(r.status).toBe(1);
    expect(r.stderr + r.stdout).toMatch(/expires/i);
    expect(r.stderr + r.stdout).not.toContain(jwt);
  });

  it("exit 1 when expired, exit 2 when no input or malformed, and the env var form works", async () => {
    expect(run(await real(-2)).status).toBe(1);
    expect(run("").status).toBe(2);
    expect(run("garbage").status).toBe(1);
    const jwt = await real(100);
    expect(run(null, [], { APPLE_SIWA_CLIENT_SECRET_JWT: jwt }).status).toBe(0);
  });

  it("--warn-days overrides the threshold", async () => {
    expect(run(await real(45), ["--warn-days", "60"]).status).toBe(1);
  });
});

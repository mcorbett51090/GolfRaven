// supabase/tests/unit/vendor-log.test.ts
//
// rewards/vendor-log.ts: the rate-limited warn line for a vendor outcome a caller can trigger (Google's ambiguous 403 on decodeIntegrityToken), and the
// handlers' use of it: the SAME 503 as before, never graded, and never an `error`-level "our credentials" line.

import { afterEach, describe, expect, it, vi } from "vitest";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.js";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { fromBase64UrlStrict, toHex } from "../../functions/_shared/rewards/binding.js";
import { createVendorFaultLogger, VENDOR_FAULT_LOG_INTERVAL_MS } from "../../functions/_shared/rewards/vendor-log.js";
import { VendorForbiddenError, VendorNotConfiguredError, type AndroidPort } from "../../functions/_shared/rewards/types.js";
import { handleActivation } from "../../functions/_shared/rewards/activate-handler.js";
import { HttpError } from "../../functions/_shared/http.js";
import { FAKE_DEVICE_ID, makeFakeRepo, makeFakeState } from "./fake-repo.js";
import { rewardsState, seedDevice, seedReward } from "./fake-rewards-repo.js";
import { sha256 } from "./rewards-test-crypto.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("createVendorFaultLogger: one line per (source, kind) per window, then a count of what was suppressed", () => {
  const make = (intervalMs = 1000) => {
    const lines: string[] = [];
    let now = 10_000;
    const log = createVendorFaultLogger({ warn: (m) => lines.push(m) }, () => now, intervalMs);
    return { lines, log, advance: (ms: number) => (now += ms) };
  };

  it("writes the first line, suppresses the rest of the window, and reports the count on the next line", () => {
    const { lines, log, advance } = make();
    expect(log("checkin-token", "decode_forbidden", "m")).toBe(true);
    for (let i = 0; i < 50; i++) expect(log("checkin-token", "decode_forbidden", "m")).toBe(false);
    expect(lines).toEqual(["checkin-token: m"]);
    advance(999);
    expect(log("checkin-token", "decode_forbidden", "m")).toBe(false);
    advance(1);
    expect(log("checkin-token", "decode_forbidden", "m")).toBe(true);
    expect(lines).toEqual(["checkin-token: m", "checkin-token: m (51 similar suppressed since the last line)"]);
  });

  it("windows are per (source, kind): another endpoint or another kind still logs", () => {
    const { lines, log } = make();
    expect(log("checkin-token", "decode_forbidden", "a")).toBe(true);
    expect(log("rewards-activate", "decode_forbidden", "b")).toBe(true);
    expect(log("checkin-token", "other", "c")).toBe(true);
    expect(lines).toHaveLength(3);
  });

  it("the default window is a minute", () => {
    expect(VENDOR_FAULT_LOG_INTERVAL_MS).toBe(60_000);
  });
});

describe("the handlers: Google's decode 403 is the SAME 503 as ever, never graded, logged at warn level (rate-limited), not as an error", () => {
  const forbiddenPort: AndroidPort = {
    async verifyIntegrity() {
      throw new VendorForbiddenError("Play Integrity decodeIntegrityToken answered 403: ...");
    },
  };
  const credentialsPort: AndroidPort = {
    async verifyIntegrity() {
      throw new VendorNotConfiguredError("Play Integrity is not configured: Google rejected our credentials (401)");
    },
  };
  const digestHex = async (b: Uint8Array) => toHex(await sha256(b));
  const statusOf = async (p: Promise<unknown>) => {
    try {
      await p;
      return null;
    } catch (e) {
      if (e instanceof HttpError) return { status: e.status, code: e.code };
      throw e;
    }
  };

  async function checkin(port: AndroidPort) {
    const state = makeFakeState();
    seedDevice(state, { id: FAKE_DEVICE_ID, userId: "user-a", platform: "android" });
    const [c] = await handleChallengeRequest({ deviceId: FAKE_DEVICE_ID }, makeFakeRepo(state, "user-a"), (n) => crypto.getRandomValues(new Uint8Array(n)), digestHex);
    const out = await statusOf(
      handleTokenRequest(
        { challengeId: c!.id, nonce: c!.nonce, hardwareSupportsAttestation: true, attestation: { platform: "android", integrityToken: "TOKEN.abc" } },
        makeFakeRepo(state, "user-a"),
        digestHex,
        { userId: "user-a", ports: { ios: null, android: port }, sha256 },
      ),
    );
    return { state, out };
  }

  it("checkin-token: 503 attestation_not_configured, nothing issued or signalled, a WARN line and no console.error", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00Z")); // a window no earlier test in this file has used
    const { state, out } = await checkin(forbiddenPort);
    expect(out).toEqual({ status: 503, code: "attestation_not_configured" });
    expect([...state.checkinTokens.values()]).toEqual([]);
    expect(state.fraudSignals).toEqual([]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]![0])).toMatch(/^checkin-token: Play Integrity decodeIntegrityToken answered 403/);
    expect(error).not.toHaveBeenCalled();
    // a flood from the same window writes nothing more
    for (let i = 0; i < 10; i++) expect((await checkin(forbiddenPort)).out).toEqual({ status: 503, code: "attestation_not_configured" });
    expect(warn).toHaveBeenCalledTimes(1);
    // the next window writes one more line, carrying the count
    vi.setSystemTime(new Date("2030-01-01T00:02:00Z"));
    await checkin(forbiddenPort);
    expect(warn).toHaveBeenCalledTimes(2);
    expect(String(warn.mock.calls[1]![0])).toMatch(/\(10 similar suppressed since the last line\)$/);
  });

  it("a genuine credentials failure (a plain NotConfigured) is unchanged: still console.error, every time, same 503", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    for (let i = 0; i < 3; i++) expect((await checkin(credentialsPort)).out).toEqual({ status: 503, code: "attestation_not_configured" });
    expect(error).toHaveBeenCalledTimes(3);
    expect(String(error.mock.calls[0]![0])).toMatch(/not configured/);
    expect(warn).not.toHaveBeenCalled();
  });

  it("rewards-activate: the same 503 and the same warn-level, rate-limited line (nothing written)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2031-01-01T00:00:00Z"));
    const state = makeFakeState();
    seedDevice(state, { id: FAKE_DEVICE_ID, userId: "user-a", platform: "android" });
    const R = "aaaaaaaa-0000-4000-8000-000000000001";
    seedReward(state, { id: R, userId: "user-a", kind: "offer_code" });
    const repo = makeFakeRepo(state, "user-a");
    const [c] = await handleChallengeRequest({ deviceId: FAKE_DEVICE_ID }, repo, (n) => crypto.getRandomValues(new Uint8Array(n)), digestHex);
    expect(fromBase64UrlStrict(c!.nonce)).not.toBeNull();
    const req = { deviceId: FAKE_DEVICE_ID, platform: "android" as const, challengeId: c!.id, nonce: c!.nonce, attestation: { kind: "android" as const, integrityToken: "TOKEN.abc" } };
    const out = await statusOf(handleActivation(R, req, repo, { ports: { ios: null, android: forbiddenPort }, sha256 }));
    expect(out).toEqual({ status: 503, code: "attestation_not_configured" });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]![0])).toMatch(/^rewards-activate: /);
    expect(error).not.toHaveBeenCalled();
    expect(rewardsState(state).signals).toEqual([]);
  });
});

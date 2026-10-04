// supabase/tests/unit/offline-seed-handler.test.ts
//
// POST /v1/me/offline-seed: the request's strictness, the exact response shape the mobile client implements, ownership (another account's device and a
// nonexistent one are the same 404), rotation, the missing-key 503, and the P5-shaped composition (provision as the player -> verify as staff -> atomic
// record -> replay refused). The fake Repo derives seeds with the independent reference (offline-seed-reference.ts); the REAL database function is proven
// by the pgTAP matrix 23_* and the Deno integration suite.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { HttpError } from "../../functions/_shared/http.ts";
import { handleOfflineSeedRequest, parseOfflineSeedRequest } from "../../functions/_shared/me/offline-seed-handler.ts";
import { OFFLINE_CODE_STEP_SECONDS } from "../../functions/_shared/offline-code/params.ts";
import { base32Decode, hotp, stepOf } from "../../functions/_shared/offline-code/totp.ts";
import { verifyOfflineCode } from "../../functions/_shared/offline-code/verify.ts";
import { makeFakeRepo, makeFakeState } from "./fake-repo.ts";
import { grantStaffScope, makeFakeStaffRecorder, offlineState } from "./fake-offline-code-repo.ts";
import { SHIM_OFFLINE_SEED_KEY, deriveSeedReference, toHex } from "./offline-seed-reference.ts";

const FUNCTIONS = join(import.meta.dirname, "..", "..", "functions");
const PLAYER = "11111111-aaaa-4aaa-8aaa-111111111111";
const OTHER = "22222222-bbbb-4bbb-8bbb-222222222222";
const STAFF = "33333333-cccc-4ccc-8ccc-333333333333";
const DEV_P1 = "aaaaaaaa-0000-4000-8000-000000000001";
const DEV_P2 = "aaaaaaaa-0000-4000-8000-000000000002";
const DEV_O1 = "bbbbbbbb-0000-4000-8000-000000000001";
const DEV_S1 = "cccccccc-0000-4000-8000-000000000001";

function world() {
  const state = makeFakeState();
  state.devices.set(DEV_P1, { id: DEV_P1, userId: PLAYER });
  state.devices.set(DEV_P2, { id: DEV_P2, userId: PLAYER });
  state.devices.set(DEV_O1, { id: DEV_O1, userId: OTHER });
  state.devices.set(DEV_S1, { id: DEV_S1, userId: STAFF });
  grantStaffScope(state, STAFF, "fac_x");
  return { state, repoOf: (uid: string) => makeFakeRepo(state, uid) };
}
const httpStatus = async (p: Promise<unknown>): Promise<{ status: number; code: string } | null> => {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, code: e.code };
    throw e;
  }
};

describe("request validation: strict", () => {
  const ok = (body: unknown) => parseOfflineSeedRequest(body);
  const bad = (body: unknown) => {
    try {
      parseOfflineSeedRequest(body);
    } catch (e) {
      expect(e).toBeInstanceOf(HttpError);
      expect((e as HttpError).status).toBe(400);
      return (e as HttpError).message;
    }
    throw new Error("expected a 400");
  };

  it("accepts {deviceId} and {deviceId, rotate: boolean}", () => {
    expect(ok({ deviceId: DEV_P1 })).toEqual({ deviceId: DEV_P1 });
    expect(ok({ deviceId: DEV_P1, rotate: true })).toEqual({ deviceId: DEV_P1, rotate: true });
    expect(ok({ deviceId: DEV_P1, rotate: false })).toEqual({ deviceId: DEV_P1, rotate: false });
  });
  it("rejects an unknown key (a typo such as `rotation` must not silently mean no rotation), naming it", () => {
    expect(bad({ deviceId: DEV_P1, rotation: true })).toMatch(/unknown field "rotation"/);
    expect(bad({ deviceId: DEV_P1, rotate: true, extra: 1 })).toMatch(/unknown field "extra"/);
    expect(bad({ deviceId: DEV_P1, userId: PLAYER })).toMatch(/unknown field "userId"/); // a user id is never client-supplied
    expect(bad({ deviceId: DEV_P1, platform: "ios" })).toMatch(/unknown field/);
    expect(bad({ deviceId: DEV_P1, seedVersion: 1 })).toMatch(/unknown field/); // a client cannot pick a version
    expect(bad({ deviceId: DEV_P1, __proto__x: 1 })).toMatch(/unknown field/);
  });
  it("rejects a non-UUID, missing or non-string deviceId", () => {
    for (const deviceId of [undefined, null, 5, "", "not-a-uuid", DEV_P1 + "0", "aaaaaaaa-0000-4000-8000-00000000000g", [DEV_P1], { toString: () => DEV_P1 }]) {
      bad({ deviceId });
    }
    bad({});
  });
  it("rejects a non-boolean rotate (including the strings 'true' / 'false' and 1 / 0)", () => {
    for (const rotate of ["true", "false", 1, 0, null, {}, []]) expect(bad({ deviceId: DEV_P1, rotate })).toMatch(/rotate must be a boolean/);
  });
  it("rejects a body that is not an object", () => {
    for (const body of [null, undefined, 5, "x", true, [], [{ deviceId: DEV_P1 }]]) bad(body);
  });
  it("a very long unknown key is truncated in the message (no reflected payload)", () => {
    expect(bad({ deviceId: DEV_P1, ["k".repeat(5000)]: 1 }).length).toBeLessThan(100);
  });
});

describe("the response: exactly what the mobile client implements", () => {
  it("has exactly the six keys, with the pinned parameters", async () => {
    const { repoOf } = world();
    const res = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    expect(Object.keys(res).sort()).toEqual(["algorithm", "digits", "issuedAt", "seed", "seedVersion", "stepSeconds"]);
    expect(res.stepSeconds).toBe(600);
    expect(res.digits).toBe(6);
    expect(res.algorithm).toBe("SHA256");
    expect(res.seedVersion).toBe(1);
    expect(res.issuedAt).toBe("2026-06-01T12:00:00.000Z");
    expect(res.seed).toMatch(/^[A-Z2-7]{52}$/); // base32, upper case, no padding, 32 bytes
  });
  it("the seed is the 32 bytes the database derived, base32-encoded", async () => {
    const { repoOf } = world();
    const res = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const expected = await deriveSeedReference(SHIM_OFFLINE_SEED_KEY, PLAYER, DEV_P1, 1);
    expect(toHex(base32Decode(res.seed))).toBe(toHex(expected));
  });
  it("is deterministic: re-provisioning returns the same seed and version (a reinstall that lost the secure store recovers)", async () => {
    const { repoOf } = world();
    const a = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const b = await handleOfflineSeedRequest({ deviceId: DEV_P1, rotate: false }, repoOf(PLAYER));
    expect(b).toEqual(a);
  });
  it("a different device of the same account, and another account's device, get different seeds", async () => {
    const { repoOf } = world();
    const a = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const b = await handleOfflineSeedRequest({ deviceId: DEV_P2 }, repoOf(PLAYER));
    const c = await handleOfflineSeedRequest({ deviceId: DEV_O1 }, repoOf(OTHER));
    expect(new Set([a.seed, b.seed, c.seed]).size).toBe(3);
  });
  it("the response never carries the key, a user id or a device id", async () => {
    const { repoOf } = world();
    const text = JSON.stringify(await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER)));
    expect(text).not.toContain(PLAYER);
    expect(text).not.toContain(DEV_P1);
    expect(text).not.toContain(SHIM_OFFLINE_SEED_KEY);
  });
});

describe("ownership: the device must be the caller's own", () => {
  it("another account's device is a 404, the same as a device that does not exist (no oracle on device ids)", async () => {
    const { repoOf } = world();
    const foreign = await httpStatus(handleOfflineSeedRequest({ deviceId: DEV_O1 }, repoOf(PLAYER)));
    const missing = await httpStatus(handleOfflineSeedRequest({ deviceId: "dddddddd-0000-4000-8000-00000000dead" }, repoOf(PLAYER)));
    expect(foreign).toEqual({ status: 404, code: "not_found" });
    expect(missing).toEqual(foreign);
  });
  it("a foreign device cannot be ROTATED either, and the owner's version is untouched", async () => {
    const { state, repoOf } = world();
    expect(await httpStatus(handleOfflineSeedRequest({ deviceId: DEV_O1, rotate: true }, repoOf(PLAYER)))).toEqual({ status: 404, code: "not_found" });
    expect(offlineState(state).versions.get(DEV_O1)).toBeUndefined();
    const owner = await handleOfflineSeedRequest({ deviceId: DEV_O1 }, repoOf(OTHER));
    expect(owner.seedVersion).toBe(1);
  });
  it("the endpoint never creates a device", async () => {
    const { state, repoOf } = world();
    const before = state.devices.size;
    await httpStatus(handleOfflineSeedRequest({ deviceId: "dddddddd-0000-4000-8000-00000000dead" }, repoOf(PLAYER)));
    expect(state.devices.size).toBe(before);
  });
});

describe("rotation", () => {
  it("increments the version and changes the seed; a plain call afterwards returns the NEW seed", async () => {
    const { repoOf } = world();
    const v1 = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const v2 = await handleOfflineSeedRequest({ deviceId: DEV_P1, rotate: true }, repoOf(PLAYER));
    expect(v2.seedVersion).toBe(2);
    expect(v2.seed).not.toBe(v1.seed);
    expect(await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER))).toEqual(v2);
    expect((await handleOfflineSeedRequest({ deviceId: DEV_P1, rotate: true }, repoOf(PLAYER))).seedVersion).toBe(3);
  });
  it("rotating one device does not change the account's other device", async () => {
    const { repoOf } = world();
    const before = await handleOfflineSeedRequest({ deviceId: DEV_P2 }, repoOf(PLAYER));
    await handleOfflineSeedRequest({ deviceId: DEV_P1, rotate: true }, repoOf(PLAYER));
    expect(await handleOfflineSeedRequest({ deviceId: DEV_P2 }, repoOf(PLAYER))).toEqual(before);
  });
});

describe("the derivation key is missing: 503, with nothing from the database", () => {
  it("answers 503 offline_seed_unavailable and the message names no key", async () => {
    const { state, repoOf } = world();
    offlineState(state).key = null;
    try {
      await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
      throw new Error("expected 503");
    } catch (e) {
      expect(e).toBeInstanceOf(HttpError);
      expect((e as HttpError).status).toBe(503);
      expect((e as HttpError).code).toBe("offline_seed_unavailable");
      expect((e as HttpError).message).not.toMatch(/vault|offline_seed_key|secret/i);
    }
  });
});

describe("the P5-shaped composition: provision -> verify -> record -> replay refused", () => {
  /** What the device does: derive the code from the base32 seed it was given, at its own clock. */
  async function deviceCode(seedB32: string, unixSeconds: number): Promise<string> {
    return hotp(base32Decode(seedB32), stepOf(unixSeconds));
  }
  async function staffVerify(state: ReturnType<typeof world>["state"], repoOf: (uid: string) => ReturnType<typeof makeFakeRepo>, deviceId: string, typed: string, facility = "fac_x") {
    // P5's step 1 (the staff-lane derivation of the player's seed by handle) is a database definer P5 adds; here the reference derivation stands in for it.
    const o = offlineState(state);
    const version = o.versions.get(deviceId) ?? 1;
    const ownerOf = state.devices.get(deviceId)!.userId;
    const seed = await deriveSeedReference(o.key!, ownerOf, deviceId, version);
    const verdict = await verifyOfflineCode({ seed, code: typed, now: state.now });
    if (!verdict.ok) return { ok: false as const, reason: verdict.reason };
    const recorded = await makeFakeStaffRecorder(state, STAFF).recordStep({ deviceId, seedVersion: version, step: verdict.step, facilityId: facility });
    return recorded === "recorded" ? { ok: true as const, step: verdict.step } : { ok: false as const, reason: recorded };
  }

  it("a code the device computed offline verifies once; the same code again is refused as a replay", async () => {
    const { state, repoOf } = world();
    const provisioned = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const typed = await deviceCode(provisioned.seed, state.now.getTime() / 1000);
    const first = await staffVerify(state, repoOf, DEV_P1, typed);
    expect(first).toEqual({ ok: true, step: stepOf(state.now.getTime() / 1000) });
    expect(await staffVerify(state, repoOf, DEV_P1, typed)).toEqual({ ok: false, reason: "replayed" });
  });
  it("a device clock one step behind or ahead still works, once each; two steps off does not", async () => {
    const { state, repoOf } = world();
    const { seed } = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const now = state.now.getTime() / 1000;
    expect((await staffVerify(state, repoOf, DEV_P1, await deviceCode(seed, now - OFFLINE_CODE_STEP_SECONDS))).ok).toBe(true);
    expect((await staffVerify(state, repoOf, DEV_P1, await deviceCode(seed, now + OFFLINE_CODE_STEP_SECONDS))).ok).toBe(true);
    expect(await staffVerify(state, repoOf, DEV_P1, await deviceCode(seed, now + 2 * OFFLINE_CODE_STEP_SECONDS))).toEqual({ ok: false, reason: "mismatch" });
  });
  it("a code from another device's seed (same account) is refused", async () => {
    const { state, repoOf } = world();
    const other = await handleOfflineSeedRequest({ deviceId: DEV_P2 }, repoOf(PLAYER));
    expect(await staffVerify(state, repoOf, DEV_P1, await deviceCode(other.seed, state.now.getTime() / 1000))).toEqual({ ok: false, reason: "mismatch" });
  });
  it("after a rotation the OLD seed's code is refused and the NEW seed's code is accepted (a stolen old seed is useless)", async () => {
    const { state, repoOf } = world();
    const old = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const rotated = await handleOfflineSeedRequest({ deviceId: DEV_P1, rotate: true }, repoOf(PLAYER));
    const now = state.now.getTime() / 1000;
    expect(await staffVerify(state, repoOf, DEV_P1, await deviceCode(old.seed, now))).toEqual({ ok: false, reason: "mismatch" });
    expect((await staffVerify(state, repoOf, DEV_P1, await deviceCode(rotated.seed, now))).ok).toBe(true);
  });
  it("a rotation that lands between the derive and the record is caught by the record (stale_seed_version)", async () => {
    const { state, repoOf } = world();
    const { seed } = await handleOfflineSeedRequest({ deviceId: DEV_P1 }, repoOf(PLAYER));
    const now = state.now.getTime() / 1000;
    const typed = await deviceCode(seed, now);
    const verdict = await verifyOfflineCode({ seed: base32Decode(seed), code: typed, now: state.now });
    expect(verdict.ok).toBe(true);
    await handleOfflineSeedRequest({ deviceId: DEV_P1, rotate: true }, repoOf(PLAYER)); // the player rotates while staff is mid-verification
    const recorded = await makeFakeStaffRecorder(state, STAFF).recordStep({ deviceId: DEV_P1, seedVersion: 1, step: stepOf(now), facilityId: "fac_x" });
    expect(recorded).toBe("stale_seed_version");
  });
  it("a staff member cannot attest their own account (422), and a user with no scope at the facility gets 403", async () => {
    const { state, repoOf } = world();
    const step = stepOf(state.now.getTime() / 1000);
    expect(await httpStatus(makeFakeStaffRecorder(state, STAFF).recordStep({ deviceId: DEV_S1, seedVersion: 1, step, facilityId: "fac_x" }))).toEqual({ status: 422, code: "self_attestation_refused" });
    expect(await httpStatus(makeFakeStaffRecorder(state, OTHER).recordStep({ deviceId: DEV_P1, seedVersion: 1, step, facilityId: "fac_x" }))).toEqual({ status: 403, code: "forbidden" });
    expect(await httpStatus(makeFakeStaffRecorder(state, STAFF).recordStep({ deviceId: DEV_P1, seedVersion: 1, step, facilityId: "fac_y" }))).toEqual({ status: 403, code: "forbidden" });
  });
  it("recordStep answers the other statuses", async () => {
    const { state, repoOf } = world();
    const step = stepOf(state.now.getTime() / 1000);
    const staff = makeFakeStaffRecorder(state, STAFF);
    expect(await staff.recordStep({ deviceId: "dddddddd-0000-4000-8000-00000000dead", seedVersion: 1, step, facilityId: "fac_x" })).toBe("no_such_device");
    expect(await staff.recordStep({ deviceId: DEV_P1, seedVersion: 1, step: step + 10, facilityId: "fac_x" })).toBe("step_out_of_window");
    expect(await staff.recordStep({ deviceId: DEV_P1, seedVersion: 7, step, facilityId: "fac_x" })).toBe("stale_seed_version");
    expect(await staff.recordStep({ deviceId: DEV_P1, seedVersion: 1, step, facilityId: "fac_x" })).toBe("recorded");
    expect(await staff.recordStep({ deviceId: DEV_P1, seedVersion: 1, step, facilityId: "fac_x" })).toBe("replayed");
  });
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------
// Source-level guards: the production tree must never be able to derive a seed, must never name the key, and the entrypoint keeps the ordering
// every other write endpoint keeps.
// ---------------------------------------------------------------------------------------------------------------------------------------------------
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "vendor") continue;
      out.push(...walk(p));
    } else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}
const stripComments = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

/** The lines of a source file that are CODE: a comment-only line (`//`, `/*`, `*`) is dropped, nothing else is. Deliberately a line filter, not a
 * comment-stripping regex: a stripper that pairs a stray `/*` inside a string with a later `*` + `/` would silently delete real code (the mutation that
 * put the derivation call on a code line next to a trailing block comment slipped through exactly that way). */
const codeLines = (text: string): string[] => text.split("\n").filter((l) => !/^\s*(?:\/\/|\/\*|\*)/.test(l));

describe("K never reaches the Edge runtime", () => {
  const files = walk(FUNCTIONS);
  it("no production file holds the derivation label, names the Vault secret, or reads the decrypted Vault, on any line of code", () => {
    for (const f of files) {
      const code = codeLines(readFileSync(f, "utf8")).join("\n");
      expect(code, f).not.toContain("golfraven/offline-seed/v1");
      expect(code, f).not.toMatch(/offline_seed_key|decrypted_secrets/);
    }
  });
  it("no line of production code names the derivation core (it has no EXECUTE for any role): privileged.ts only ever calls the two wrappers", () => {
    for (const f of files) expect(codeLines(readFileSync(f, "utf8")).join("\n"), f).not.toMatch(/offline_seed_derive/);
    const code = codeLines(readFileSync(join(FUNCTIONS, "_shared", "privileged.ts"), "utf8")).join("\n");
    expect(code).toMatch(/private\.offline_seed_for_actor\(/);
    // X9 (0047): the replay record is not an Edge capability, so the Edge's privileged.ts must not name it at all
    expect(code).not.toMatch(/offline_code_record_step_for_actor/);
  });
  it("no production file imports the test-only reference derivation", () => {
    for (const f of files) expect(readFileSync(f, "utf8"), f).not.toMatch(/offline-seed-reference/);
  });
  it("the seed is never logged: no console.* call in the offline-code modules, the handler or the entrypoint", () => {
    for (const f of [join(FUNCTIONS, "_shared", "me", "offline-seed-handler.ts"), join(FUNCTIONS, "me-offline-seed", "index.ts"), ...walk(join(FUNCTIONS, "_shared", "offline-code"))]) {
      expect(codeLines(readFileSync(f, "utf8")).join("\n"), f).not.toMatch(/console\./);
    }
  });
});

describe("me-offline-seed/index.ts", () => {
  const code = stripComments(readFileSync(join(FUNCTIONS, "me-offline-seed", "index.ts"), "utf8"));
  it("is POST-only", () => {
    expect(code).toMatch(/req\.method !== "POST"[\s\S]*405/);
  });
  it("authenticates the actor from the request before anything else", () => {
    const call = code.indexOf("await getActorFromRequest(req)");
    expect(call).toBeGreaterThan(-1);
    expect(call).toBeLessThan(code.indexOf("await readJsonBody(req)"));
    expect(code).toMatch(/Errors\.unauthorized\(\)/);
  });
  it("hits the rate limits BEFORE withOwnership opens (a hit inside the request transaction would hold a second pooled connection)", () => {
    const reveal = code.indexOf("hitRateLimitForActor(actor, OFFLINE_SEED_REVEAL_BUCKET");
    const rotate = code.indexOf("hitRateLimitForActor(actor, OFFLINE_SEED_ROTATE_BUCKET");
    const own = code.indexOf("withOwnership(");
    expect(reveal).toBeGreaterThan(-1);
    expect(rotate).toBeGreaterThan(reveal);
    expect(own).toBeGreaterThan(rotate);
  });
  it("limits the rotation separately and only when the request rotates", () => {
    expect(code).toMatch(/if \(body\.rotate === true\)[\s\S]*OFFLINE_SEED_ROTATE_BUCKET/);
  });
  it("answers with cache-control: no-store (the body is a secret)", () => {
    expect(code).toMatch(/okResponse\(200, result, \{ "cache-control": "no-store" \}\)/);
  });
  it("validates the body strictly before it spends a rate-limit hit", () => {
    const parse = code.indexOf("= parseOfflineSeedRequest(");
    expect(parse).toBeGreaterThan(-1);
    expect(parse).toBeLessThan(code.indexOf("await hitRateLimitForActor("));
  });
  it("takes no user id from the client: the actor comes from the verified token, and withOwnership is called with it", () => {
    expect(code).toMatch(/withOwnership\(actor,/);
  });
});

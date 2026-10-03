// supabase/tests/unit/offline-code-verify.test.ts
//
// The verification core (_shared/offline-code/verify.ts): given a seed, the typed code and the clock, accept a code of the current step +-1 and nothing
// else, refuse a replay the caller already knows of, never accept a code of an old seed after a rotation, and compare in constant time.

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { OFFLINE_CODE_STEP_SECONDS, OFFLINE_CODE_WINDOW_STEPS } from "../../functions/_shared/offline-code/params.ts";
import { hotp } from "../../functions/_shared/offline-code/totp.ts";
import { candidateSteps, constantTimeEqual, verifyOfflineCode } from "../../functions/_shared/offline-code/verify.ts";

const STEP = OFFLINE_CODE_STEP_SECONDS;
const seed = new Uint8Array(randomBytes(32));
/** A clock in the MIDDLE of step 3_000_000 (so +-1 s never crosses a boundary), and helpers around it. */
const T0 = 3_000_000;
const at = (step: number, offsetSeconds = 300) => new Date((step * STEP + offsetSeconds) * 1000);
const codeOf = (s: Uint8Array, step: number) => hotp(s, step);

describe("the window: the current step +-1, nothing else", () => {
  it("the window is one step (build plan §7.6: +-1 step)", () => {
    expect(OFFLINE_CODE_WINDOW_STEPS).toBe(1);
  });

  it("accepts the code of the CURRENT step, and reports that step", async () => {
    expect(await verifyOfflineCode({ seed, code: await codeOf(seed, T0), now: at(T0) })).toEqual({ ok: true, step: T0 });
  });
  it("accepts the code of the PREVIOUS step (a device clock a little behind) and of the NEXT (a little ahead), reporting the step that matched", async () => {
    expect(await verifyOfflineCode({ seed, code: await codeOf(seed, T0 - 1), now: at(T0) })).toEqual({ ok: true, step: T0 - 1 });
    expect(await verifyOfflineCode({ seed, code: await codeOf(seed, T0 + 1), now: at(T0) })).toEqual({ ok: true, step: T0 + 1 });
  });
  it("REFUSES two steps behind and two steps ahead (the window is exactly +-1)", async () => {
    expect(await verifyOfflineCode({ seed, code: await codeOf(seed, T0 - 2), now: at(T0) })).toEqual({ ok: false, reason: "mismatch" });
    expect(await verifyOfflineCode({ seed, code: await codeOf(seed, T0 + 2), now: at(T0) })).toEqual({ ok: false, reason: "mismatch" });
    expect(await verifyOfflineCode({ seed, code: await codeOf(seed, T0 - 50), now: at(T0) })).toEqual({ ok: false, reason: "mismatch" });
  });
  it("the window is judged at STEP boundaries: the last second of a step and the first of the next accept the same neighbours", async () => {
    const lastSecond = new Date((T0 * STEP + STEP - 1) * 1000);
    const firstSecond = new Date(((T0 + 1) * STEP) * 1000);
    expect((await verifyOfflineCode({ seed, code: await codeOf(seed, T0 + 1), now: lastSecond })).ok).toBe(true);
    expect((await verifyOfflineCode({ seed, code: await codeOf(seed, T0 - 1), now: lastSecond })).ok).toBe(true);
    expect((await verifyOfflineCode({ seed, code: await codeOf(seed, T0 - 1), now: firstSecond })).ok).toBe(false); // now step T0+1: T0-1 is two behind
    expect((await verifyOfflineCode({ seed, code: await codeOf(seed, T0), now: firstSecond })).ok).toBe(true);
  });
  it("candidateSteps is [t, t-1, t+1]; near the epoch it never offers a negative step", () => {
    expect(candidateSteps(at(T0))).toEqual([T0, T0 - 1, T0 + 1]);
    expect(candidateSteps(new Date(0))).toEqual([0, 1]);
  });
  it("a wrong code is a mismatch, and so is the code of ANOTHER seed (another device or account)", async () => {
    const other = new Uint8Array(randomBytes(32));
    expect(await verifyOfflineCode({ seed, code: await codeOf(other, T0), now: at(T0) })).toEqual({ ok: false, reason: "mismatch" });
    const real = await codeOf(seed, T0);
    const wrong = String((Number(real) + 1) % 1_000_000).padStart(6, "0");
    // (the neighbours could in principle collide with `wrong` at p = 1e-6 each; the seed is random, so check and nudge)
    const neighbours = [await codeOf(seed, T0 - 1), await codeOf(seed, T0 + 1)];
    const pick = [wrong, String((Number(real) + 2) % 1_000_000).padStart(6, "0")].find((c) => c !== real && !neighbours.includes(c))!;
    expect(await verifyOfflineCode({ seed, code: pick, now: at(T0) })).toEqual({ ok: false, reason: "mismatch" });
  });
});

describe("rotation: a code from an old seed is refused", () => {
  it("the same account and device at the next seed version has a different seed, so the OLD seed's code no longer verifies", async () => {
    const v1 = new Uint8Array(randomBytes(32));
    const v2 = new Uint8Array(randomBytes(32)); // stands for the rotated seed (the derivation changes with the version: 0045 vectors)
    const oldCode = await codeOf(v1, T0);
    expect((await verifyOfflineCode({ seed: v1, code: oldCode, now: at(T0) })).ok).toBe(true);
    expect(await verifyOfflineCode({ seed: v2, code: oldCode, now: at(T0) })).toEqual({ ok: false, reason: "mismatch" });
  });
});

describe("replay: an advisory pre-check on the steps the caller already knows are used", () => {
  it("a step in usedSteps is refused with the specific reason `replayed`", async () => {
    const code = await codeOf(seed, T0);
    expect(await verifyOfflineCode({ seed, code, now: at(T0), usedSteps: [T0] })).toEqual({ ok: false, reason: "replayed" });
    expect(await verifyOfflineCode({ seed, code, now: at(T0), usedSteps: new Set([T0]) })).toEqual({ ok: false, reason: "replayed" });
  });
  it("only the step that MATCHED matters: other used steps do not block a fresh code", async () => {
    const code = await codeOf(seed, T0);
    expect(await verifyOfflineCode({ seed, code, now: at(T0), usedSteps: [T0 - 1, T0 + 1, 5] })).toEqual({ ok: true, step: T0 });
  });
  it("a neighbour step's code is refused when ITS step was used, accepted when it was not", async () => {
    const code = await codeOf(seed, T0 + 1);
    expect(await verifyOfflineCode({ seed, code, now: at(T0), usedSteps: [T0 + 1] })).toEqual({ ok: false, reason: "replayed" });
    expect(await verifyOfflineCode({ seed, code, now: at(T0), usedSteps: [T0] })).toEqual({ ok: true, step: T0 + 1 });
  });
  it("usedSteps is optional (the atomic Repo#offlineCode.recordStep is the authority; the pre-check only sharpens the reason)", async () => {
    expect((await verifyOfflineCode({ seed, code: await codeOf(seed, T0), now: at(T0) })).ok).toBe(true);
  });
  // (Not tested: a code that equals the codes of TWO window steps, p = 1e-6 per pair, cannot be constructed on demand; the loop's rule is that an
  // UNUSED match wins over a used one, so a used step never hides an unused one: see `accepted` / `matchedButUsed` in verify.ts.)
});

describe("malformed codes are refused before any computation", () => {
  const bad = ["", " ", "12345", "1234567", "12 345", " 123456", "123456 ", "12345a", "١٢٣٤٥٦", "1e5555", "-12345", "+12345", "123.45", "123456\n", "００００００"];
  for (const code of bad) {
    it(`${JSON.stringify(code)} is malformed_code`, async () => {
      expect(await verifyOfflineCode({ seed, code, now: at(T0) })).toEqual({ ok: false, reason: "malformed_code" });
    });
  }
  it("a non-string code is malformed_code, not a throw", async () => {
    expect(await verifyOfflineCode({ seed, code: 123456 as unknown as string, now: at(T0) })).toEqual({ ok: false, reason: "malformed_code" });
    expect(await verifyOfflineCode({ seed, code: null as unknown as string, now: at(T0) })).toEqual({ ok: false, reason: "malformed_code" });
  });
  it("leading zeros are significant: '000123' is a code, and is not '123'", async () => {
    // find a step whose code has a leading zero so the zero-padded path is exercised end to end
    for (let s = T0; s < T0 + 400; s++) {
      const c = await codeOf(seed, s);
      if (c.startsWith("0")) {
        expect(await verifyOfflineCode({ seed, code: c, now: at(s) })).toEqual({ ok: true, step: s });
        expect((await verifyOfflineCode({ seed, code: String(Number(c)), now: at(s) })).ok).toBe(false);
        return;
      }
    }
    throw new Error("no leading-zero code in 400 steps (p of that = 0.9^400)");
  });
  it("a seed of the wrong length throws (a programming error: never a quiet 'mismatch')", async () => {
    await expect(verifyOfflineCode({ seed: new Uint8Array(20), code: "123456", now: at(T0) })).rejects.toThrow(/32 bytes/);
  });
});

describe("constant time", () => {
  it("constantTimeEqual: equal strings, different strings, different lengths, empty", () => {
    expect(constantTimeEqual("123456", "123456")).toBe(true);
    expect(constantTimeEqual("123456", "123457")).toBe(false);
    expect(constantTimeEqual("123456", "023456")).toBe(false);
    expect(constantTimeEqual("123456", "12345")).toBe(false);
    expect(constantTimeEqual("12345", "123456")).toBe(false);
    expect(constantTimeEqual("", "")).toBe(true);
    expect(constantTimeEqual("", "1")).toBe(false);
    expect(constantTimeEqual("123456", "123456\u0000")).toBe(false); // a NUL pad is not a way to equal a shorter string
  });

  // A source check: JavaScript offers no portable way to prove "constant time" by running it (a timing test is noise), but the property worth guarding is
  // structural: the comparison of the typed code with a candidate goes through constantTimeEqual, and nothing in the file compares codes with ===,
  // ==, !==, !=, localeCompare, includes, indexOf, startsWith or a regex built from the expected code.
  const source = readFileSync(join(import.meta.dirname, "..", "..", "functions", "_shared", "offline-code", "verify.ts"), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  it("verify.ts compares the typed code with each candidate through constantTimeEqual", () => {
    expect(code).toMatch(/constantTimeEqual\(\s*expected\s*,\s*code\s*\)/);
  });
  it("verify.ts never compares a code with an ordinary operator or string method", () => {
    expect(code).not.toMatch(/\b(?:expected|candidate|code)\b\s*[!=]==?\s*\b(?:expected|candidate|code|input\.code)\b/);
    expect(code).not.toMatch(/\b(?:expected|candidate)\b\s*[!=]==?/);
    expect(code).not.toMatch(/[!=]==?\s*\b(?:expected|candidate)\b/);
    expect(code).not.toMatch(/\.(?:localeCompare|includes|indexOf|startsWith|endsWith|match|test)\(\s*(?:expected|candidate)\b/);
    expect(code).not.toMatch(/\b(?:expected|candidate)\b\s*\.(?:localeCompare|includes|indexOf|startsWith|endsWith)\(/);
  });
  it("every candidate step is compared whether or not an earlier one matched (no `break` / early `return` inside the comparison loop)", () => {
    const loop = code.slice(code.indexOf("for (const step of candidateSteps"), code.indexOf("if (accepted !== null)"));
    expect(loop.length).toBeGreaterThan(50);
    expect(loop).not.toMatch(/\bbreak\b|\breturn\b|\bcontinue\b/);
  });
  it("constantTimeEqual itself has no early exit (no `return` before the final comparison, no `break`)", () => {
    const fn = code.slice(code.indexOf("export function constantTimeEqual"), code.indexOf("export function candidateSteps"));
    expect(fn.match(/\breturn\b/g)?.length).toBe(1);
    expect(fn).not.toMatch(/\bbreak\b/);
    expect(fn).toMatch(/\^/); // XOR accumulation
  });
});

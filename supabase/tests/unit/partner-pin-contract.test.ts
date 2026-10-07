// supabase/tests/unit/partner-pin-contract.test.ts
//
// The BROWSER-DERIVATION CONTRACT of the partner step-up PIN (supabase/functions/_shared/partner/pin-contract.ts, docs/security/partner-auth-design.md 6.3, D8 / N1) and the PIN rules and deny-list
// (pin-deny-list.ts). The vectors were computed OUTSIDE the code under test (Python hashlib.pbkdf2_hmac), so a green run here means Node's Web Crypto and the contract agree with an independent PBKDF2.
// The same vectors are asserted under Deno by supabase/tests/deno-unit/partner-pin-contract.deno.test.ts, and S7's PWA reuses them.

import { describe, expect, it } from "vitest";
import {
  DEFAULT_ITERATIONS,
  derivePinKey,
  derivePinKeyB64u,
  isWellFormedPin,
  MAX_ITERATIONS,
  MIN_ITERATIONS,
  newPinSalt,
  parseDerivedKey,
  parseIterations,
  parsePinSalt,
  PIN_DERIVATION,
} from "../../functions/_shared/partner/pin-contract.ts";
import { PIN_DERIVATION_VECTORS } from "../../functions/_shared/partner/pin-vectors.ts";
import { isAcceptablePin, PIN_DENY_LIST, pinRejection } from "../../functions/_shared/partner/pin-deny-list.ts";
import { fromB64u, toB64u, toHex } from "../../functions/_shared/partner/token.ts";

const fromHex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

describe("the derivation contract: PBKDF2-HMAC-SHA256(PIN as ASCII, 16-byte salt, iterations) -> 32 bytes", () => {
  it("states its constants (a change is a contract version bump, in step with migration 0052's label)", () => {
    expect(PIN_DERIVATION).toEqual({ version: 1, kdf: "PBKDF2-HMAC-SHA256", pinLength: 4, saltBytes: 16, derivedBytes: 32, minIterations: 210_000, maxIterations: 1_000_000, defaultIterations: 600_000 });
    expect([MIN_ITERATIONS, MAX_ITERATIONS, DEFAULT_ITERATIONS]).toEqual([210_000, 1_000_000, 600_000]);
  });

  it("the shared vectors: derivePinKey reproduces the bytes an independent PBKDF2 (Python hashlib) computed, in hex and in base64url", async () => {
    expect(PIN_DERIVATION_VECTORS.length).toBeGreaterThanOrEqual(4);
    for (const v of PIN_DERIVATION_VECTORS) {
      const derived = await derivePinKey(v.pin, fromHex(v.saltHex), v.iterations);
      expect(toHex(derived), `${v.iterations} iterations`).toBe(v.derivedHex);
      expect(await derivePinKeyB64u(v.pin, fromHex(v.saltHex), v.iterations)).toBe(v.derivedB64u);
      expect(derived.length).toBe(32);
    }
    // eight PBKDF2 runs, four of them at up to a million iterations: a loaded CI core needs more than vitest's 5 s default
  }, 120_000);

  it("the vectors cover the floor, the default and the ceiling, and use PINs a member could actually set", () => {
    const iters = PIN_DERIVATION_VECTORS.map((v) => v.iterations);
    expect(iters).toContain(MIN_ITERATIONS);
    expect(iters).toContain(DEFAULT_ITERATIONS);
    expect(iters).toContain(MAX_ITERATIONS);
    for (const v of PIN_DERIVATION_VECTORS) expect(isAcceptablePin(v.pin), v.pin).toBe(true);
  });

  it("the derived bytes depend on the PIN, the salt and the iteration count (each alone changes them)", async () => {
    const salt = fromHex("000102030405060708090a0b0c0d0e0f");
    const base = toHex(await derivePinKey("7391", salt, 210_000));
    expect(toHex(await derivePinKey("7392", salt, 210_000))).not.toBe(base);
    expect(toHex(await derivePinKey("7391", fromHex("100102030405060708090a0b0c0d0e0f"), 210_000))).not.toBe(base);
    expect(toHex(await derivePinKey("7391", salt, 210_001))).not.toBe(base);
    expect(toHex(await derivePinKey("7391", salt, 210_000))).toBe(base);
  });

  it("derivePinKey refuses what the contract does not allow (a programming error, never a user-facing answer)", async () => {
    const salt = new Uint8Array(16);
    for (const bad of ["123", "12345", "12a4", "", " 123", "１２３４", "12.4"]) await expect(derivePinKey(bad, salt, 600_000), JSON.stringify(bad)).rejects.toThrow(/four digits/);
    await expect(derivePinKey("7391", new Uint8Array(15), 600_000)).rejects.toThrow(/16 bytes/);
    await expect(derivePinKey("7391", new Uint8Array(17), 600_000)).rejects.toThrow(/16 bytes/);
    await expect(derivePinKey("7391", salt, MIN_ITERATIONS - 1)).rejects.toThrow(/iteration/);
    await expect(derivePinKey("7391", salt, MAX_ITERATIONS + 1)).rejects.toThrow(/iteration/);
    await expect(derivePinKey("7391", salt, 600_000.5)).rejects.toThrow(/iteration/);
  });

  it("newPinSalt is 16 CSPRNG bytes and differs between calls", () => {
    const a = newPinSalt();
    const b = newPinSalt();
    expect(a.length).toBe(16);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe("what the Edge validates: length and encoding of the DERIVED key, the salt and the iteration count (and nothing about the PIN)", () => {
  it("parseDerivedKey: canonical unpadded base64url of exactly 32 bytes (43 characters)", () => {
    const good = toB64u(new Uint8Array(32).fill(7));
    expect(good.length).toBe(43);
    expect(parseDerivedKey(good)).toEqual(new Uint8Array(32).fill(7));
    for (const bad of [toB64u(new Uint8Array(31)), toB64u(new Uint8Array(33)), good + "=", good.slice(0, 42), good.replace(/.$/, "!"), good.slice(0, 10) + "+" + good.slice(11), "", null, undefined, 1234, {}, ["x"]]) {
      expect(parseDerivedKey(bad), JSON.stringify(bad)).toBeNull();
    }
    // a non-canonical encoding of 32 bytes (stray trailing bits in the last character) is refused: re-encoding must give the same string
    const last = good[42]!;
    const alt = good.slice(0, 42) + (last === "w" ? "x" : last === "A" ? "B" : last === "Q" ? "R" : "w");
    expect(fromB64u(alt) === null || toB64u(fromB64u(alt)!) === alt).toBe(true);
    expect(parseDerivedKey(alt) === null || toB64u(parseDerivedKey(alt)!) === alt).toBe(true);
  });

  it("a PIN-shaped value is never a derived key (the body carries the key, not the PIN)", () => {
    for (const pin of ["1234", "7391", "0000"]) expect(parseDerivedKey(pin)).toBeNull();
  });

  it("parsePinSalt: canonical unpadded base64url of exactly 16 bytes (22 characters)", () => {
    const good = toB64u(new Uint8Array(16).fill(9));
    expect(good.length).toBe(22);
    expect(parsePinSalt(good)).toEqual(new Uint8Array(16).fill(9));
    for (const bad of [toB64u(new Uint8Array(15)), toB64u(new Uint8Array(17)), toB64u(new Uint8Array(32)), good + "=", "", null, 5]) expect(parsePinSalt(bad), JSON.stringify(bad)).toBeNull();
  });

  it("parseIterations: an integer from 210000 to 1000000", () => {
    for (const ok of [210_000, 600_000, 1_000_000]) expect(parseIterations(ok)).toBe(ok);
    for (const bad of [209_999, 1_000_001, 0, -1, 600_000.5, "600000", null, undefined, Number.NaN, Number.POSITIVE_INFINITY]) expect(parseIterations(bad), String(bad)).toBeNull();
  });

  it("isWellFormedPin: exactly four ASCII digits", () => {
    for (const ok of ["0000", "1234", "9999", "0482"]) expect(isWellFormedPin(ok)).toBe(true);
    for (const bad of ["", "123", "12345", "12a4", " 123", "123 ", "１２３４", null, 1234, undefined]) expect(isWellFormedPin(bad), JSON.stringify(bad)).toBe(false);
  });
});

describe("the PIN rules and the deny-list (enforced where the PIN is typed: the PIN never reaches the server)", () => {
  it("the list is sorted, unique, four digits each, and every entry is refused", () => {
    expect(PIN_DENY_LIST.length).toBeGreaterThanOrEqual(70);
    expect([...PIN_DENY_LIST]).toEqual([...PIN_DENY_LIST].sort());
    expect(new Set(PIN_DENY_LIST).size).toBe(PIN_DENY_LIST.length);
    for (const pin of PIN_DENY_LIST) {
      expect(pin, pin).toMatch(/^[0-9]{4}$/);
      expect(pinRejection(pin), pin).not.toBeNull();
      expect(isAcceptablePin(pin), pin).toBe(false);
    }
  });

  it("every entry the structural rules do NOT already refuse is refused as `common` (the list adds what the rules cannot see), and there are some", () => {
    const onlyList = PIN_DENY_LIST.filter((p) => pinRejection(p) === "common");
    expect(onlyList.length).toBeGreaterThanOrEqual(25);
    for (const p of ["2580", "1357", "1004", "6969", "1379", "2468", "0852", "0007"]) expect(PIN_DENY_LIST).toContain(p);
  });

  it("repeated: all four digits equal, a repeated pair, or two doubled digits", () => {
    for (let d = 0; d <= 9; d++) expect(pinRejection(String(d).repeat(4))).toBe("repeated");
    for (const p of ["1212", "6969", "4545", "2323", "0101"]) expect(pinRejection(p), p).toBe("repeated");
    for (const p of ["1122", "3344", "0011", "9988"]) expect(pinRejection(p), p).toBe("repeated");
  });

  it("run: four consecutive ascending or descending digits", () => {
    for (const p of ["0123", "1234", "2345", "3456", "4567", "5678", "6789", "3210", "4321", "5432", "6543", "7654", "8765", "9876"]) expect(pinRejection(p), p).toBe("run");
    for (const p of ["1235", "1324", "9867", "0124"]) expect(pinRejection(p), p).not.toBe("run");
  });

  it("year: 1900 to 2099, both edges", () => {
    for (const p of ["1900", "1950", "1984", "1999", "2000", "2024", "2026", "2099"]) expect(pinRejection(p), p).toBe("year");
    expect(pinRejection("1899")).not.toBe("year");
    expect(pinRejection("2100")).not.toBe("year");
  });

  it("date: a valid MMDD (February to the 29th), and not an invalid one", () => {
    for (const p of ["0105", "0229", "1231", "0430", "0630", "0731", "1015"]) expect(pinRejection(p), p).toBe("date");
    for (const p of ["0230", "0431", "0631", "0931", "1131", "1301", "0001", "0100", "1232"]) expect(pinRejection(p), p).not.toBe("date");
  });

  it("format: anything that is not four ASCII digits", () => {
    for (const p of ["", "123", "12345", "12a4", "１２３４", " 123", null, undefined, 1234]) expect(pinRejection(p), JSON.stringify(p)).toBe("format");
  });

  it("the first applicable reason wins (a run that is also a date reports `run`; a repeated pair that is also a date reports `repeated`)", () => {
    expect(pinRejection("0123")).toBe("run");
    expect(pinRejection("1212")).toBe("repeated");
    expect(pinRejection("2000")).toBe("year");
    expect(pinRejection("1004")).toBe("date");
  });

  it("most PINs remain available (the rules refuse the predictable, not the space): over 80 percent of the 10,000", () => {
    let acceptable = 0;
    for (let n = 0; n < 10_000; n++) if (isAcceptablePin(String(n).padStart(4, "0"))) acceptable += 1;
    expect(acceptable).toBeGreaterThan(8_000);
    expect(acceptable).toBeLessThan(9_500);
  });
});

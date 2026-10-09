/**
 * The browser half of the step-up PIN (src/auth/pin.ts): the derivation is held to the SHARED vectors (`_shared/partner/pin-vectors.ts`, computed outside
 * the code with Python's hashlib) and to an independent oracle (node's own PBKDF2), the rules and the deny-list are enforced BEFORE anything is derived,
 * and the work factor a server may ask for is bounded by the contract.
 */
import { pbkdf2Sync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { deriveForSet, deriveForVerify, PinError } from "../src/auth/pin";
import { DEFAULT_ITERATIONS, MAX_ITERATIONS, MIN_ITERATIONS, PIN_DERIVATION } from "../../../supabase/functions/_shared/partner/pin-contract.ts";
import { PIN_DENY_LIST, pinRejection } from "../../../supabase/functions/_shared/partner/pin-deny-list.ts";
import { PIN_DERIVATION_VECTORS } from "../../../supabase/functions/_shared/partner/pin-vectors.ts";
import { fromB64u, toB64u, toHex } from "../../../supabase/functions/_shared/partner/token.ts";

afterEach(() => vi.restoreAllMocks());

const saltFromHex = (hex: string): Uint8Array => Uint8Array.from(hex.match(/../g)!.map((h) => Number.parseInt(h, 16)));

describe("derivation: the shared vectors (computed outside this code)", () => {
  it("the vector file is the one the contract names: four vectors, at the floor, the default and the ceiling", () => {
    expect(PIN_DERIVATION_VECTORS).toHaveLength(4);
    const iterations = PIN_DERIVATION_VECTORS.map((v) => v.iterations);
    expect(iterations).toContain(MIN_ITERATIONS);
    expect(iterations).toContain(DEFAULT_ITERATIONS);
    expect(iterations).toContain(MAX_ITERATIONS);
  });

  it.each(PIN_DERIVATION_VECTORS.map((v) => [`${v.pin} @ ${v.iterations}`, v] as const))("%s: the page derives exactly the vector's bytes", async (_name, v) => {
    const derived = await deriveForVerify(v.pin, { salt: toB64u(saltFromHex(v.saltHex)), iterations: v.iterations });
    expect(derived).toBe(v.derivedB64u);
    expect(toHex(fromB64u(derived)!)).toBe(v.derivedHex);
    expect(derived).toHaveLength(43);
  });
});

describe("derivation at set time: a fresh salt, the contract's default work factor, and bytes an independent PBKDF2 agrees with", () => {
  it("is PBKDF2-HMAC-SHA256(PIN as ASCII, the page's own salt, 600000, 32 bytes), and sends salt and iterations in the canonical encodings", async () => {
    const m = await deriveForSet("7391");
    expect(m.iterations).toBe(DEFAULT_ITERATIONS);
    expect(m.iterations).toBe(PIN_DERIVATION.defaultIterations);
    expect(m.salt).toHaveLength(22);
    const salt = fromB64u(m.salt)!;
    expect(salt).toHaveLength(16);
    expect(m.derived).toBe(toB64u(new Uint8Array(pbkdf2Sync("7391", salt, m.iterations, 32, "sha256"))));
  });

  it("two derivations of the same PIN differ (a fresh CSPRNG salt each time), so two members' PINs cannot be compared", async () => {
    const [a, b] = await Promise.all([deriveForSet("7391"), deriveForSet("7391")]);
    expect(a.salt).not.toBe(b.salt);
    expect(a.derived).not.toBe(b.derived);
  });
});

describe("the rules and the deny-list are enforced before anything is derived", () => {
  it("every entry of the deny-list is refused, and no key is ever derived for it", async () => {
    const derive = vi.spyOn(crypto.subtle, "deriveBits");
    const imp = vi.spyOn(crypto.subtle, "importKey");
    for (const pin of PIN_DENY_LIST) {
      await expect(deriveForSet(pin), pin).rejects.toBeInstanceOf(PinError);
      await expect(deriveForVerify(pin, { salt: toB64u(new Uint8Array(16)), iterations: MIN_ITERATIONS }), pin).rejects.toBeInstanceOf(PinError);
    }
    expect(derive).not.toHaveBeenCalled();
    expect(imp).not.toHaveBeenCalled();
  });

  it.each([
    ["1234", "run"],
    ["4321", "run"],
    ["1111", "repeated"],
    ["1212", "repeated"],
    ["1990", "year"],
    ["0229", "date"],
    ["3112", "date"],
    ["123", "format"],
    ["12345", "format"],
    ["12a4", "format"],
    ["", "format"],
  ] as const)("%s is refused as %s, naming the reason", async (pin, reason) => {
    expect(pinRejection(pin)).toBe(reason);
    const e = await deriveForSet(pin).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(PinError);
    expect((e as PinError).kind).toBe("rejected");
    expect((e as PinError).reason).toBe(reason);
  });

  it("control: a PIN the rules accept is derived (the refusals above are not a blanket)", async () => {
    await expect(deriveForSet("7391")).resolves.toMatchObject({ iterations: DEFAULT_ITERATIONS });
  });
});

describe("the server cannot choose the work factor or the salt shape", () => {
  const goodSalt = toB64u(new Uint8Array(16));
  it.each([
    ["below the floor", MIN_ITERATIONS - 1],
    ["far below the floor", 1],
    ["above the ceiling (a denial of service on this page)", MAX_ITERATIONS + 1],
    ["not an integer", 600_000.5],
    ["NaN", Number.NaN],
    ["negative", -1],
  ])("iterations %s are refused without deriving", async (_name, iterations) => {
    const derive = vi.spyOn(crypto.subtle, "deriveBits");
    const e = await deriveForVerify("7391", { salt: goodSalt, iterations }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(PinError);
    expect((e as PinError).kind).toBe("params");
    expect(derive).not.toHaveBeenCalled();
  });

  it.each([
    ["too short", toB64u(new Uint8Array(15))],
    ["too long", toB64u(new Uint8Array(17))],
    ["not base64url", "!".repeat(22)],
    ["padded", `${goodSalt}==`],
    ["empty", ""],
  ])("a salt that is %s is refused without deriving", async (_name, salt) => {
    const derive = vi.spyOn(crypto.subtle, "deriveBits");
    await expect(deriveForVerify("7391", { salt, iterations: MIN_ITERATIONS })).rejects.toMatchObject({ kind: "params" });
    expect(derive).not.toHaveBeenCalled();
  });
});

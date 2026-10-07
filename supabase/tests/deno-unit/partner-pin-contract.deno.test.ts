// supabase/tests/deno-unit/partner-pin-contract.deno.test.ts
//
// The browser-derivation contract of the partner step-up PIN (supabase/functions/_shared/partner/pin-contract.ts, docs/security/partner-auth-design.md 6.3, D8 / N1), under DENO's Web Crypto: the shared
// vectors (pin-vectors.ts, computed OUTSIDE the code under test with Python's hashlib.pbkdf2_hmac) must derive to the same bytes here as under Node (supabase/tests/unit/partner-pin-contract.test.ts) and
// in the browser S7 builds. PURE: no network, no files, no environment (CI runs it with `--deny-net --cached-only`).

import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { DEFAULT_ITERATIONS, derivePinKey, derivePinKeyB64u, MAX_ITERATIONS, MIN_ITERATIONS, parseDerivedKey, parseIterations, parsePinSalt } from "../../functions/_shared/partner/pin-contract.ts";
import { PIN_DERIVATION_VECTORS } from "../../functions/_shared/partner/pin-vectors.ts";
import { isAcceptablePin } from "../../functions/_shared/partner/pin-deny-list.ts";
import { toB64u, toHex } from "../../functions/_shared/partner/token.ts";

const fromHex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

Deno.test("PIN contract: the shared vectors derive to the bytes an independent PBKDF2 computed (hex and base64url)", async () => {
  assert(PIN_DERIVATION_VECTORS.length >= 4);
  for (const v of PIN_DERIVATION_VECTORS) {
    const derived = await derivePinKey(v.pin, fromHex(v.saltHex), v.iterations);
    assertEquals(toHex(derived), v.derivedHex, `${v.iterations} iterations`);
    assertEquals(await derivePinKeyB64u(v.pin, fromHex(v.saltHex), v.iterations), v.derivedB64u);
    assert(isAcceptablePin(v.pin), `${v.pin} is a PIN a member could set`);
  }
  const iters = PIN_DERIVATION_VECTORS.map((v) => v.iterations);
  assert(iters.includes(MIN_ITERATIONS) && iters.includes(DEFAULT_ITERATIONS) && iters.includes(MAX_ITERATIONS), "the vectors cover the floor, the default and the ceiling");
});

Deno.test("PIN contract: a PIN that is not four digits, a salt that is not 16 bytes and an iteration count outside the range are refused", async () => {
  const salt = new Uint8Array(16);
  await assertRejects(() => derivePinKey("123", salt, 600_000), Error, "four digits");
  await assertRejects(() => derivePinKey("12a4", salt, 600_000), Error, "four digits");
  await assertRejects(() => derivePinKey("7391", new Uint8Array(15), 600_000), Error, "16 bytes");
  await assertRejects(() => derivePinKey("7391", salt, MIN_ITERATIONS - 1), Error, "iteration");
  await assertRejects(() => derivePinKey("7391", salt, MAX_ITERATIONS + 1), Error, "iteration");
});

Deno.test("PIN contract: the Edge's checks are length and encoding only", () => {
  assertEquals(parseDerivedKey(toB64u(new Uint8Array(32).fill(1)))?.length, 32);
  assertEquals(parseDerivedKey(toB64u(new Uint8Array(31))), null);
  assertEquals(parseDerivedKey("1234"), null);
  assertEquals(parsePinSalt(toB64u(new Uint8Array(16).fill(1)))?.length, 16);
  assertEquals(parsePinSalt(toB64u(new Uint8Array(17))), null);
  assertEquals(parseIterations(210_000), 210_000);
  assertEquals(parseIterations(209_999), null);
  assertEquals(parseIterations("600000"), null);
});

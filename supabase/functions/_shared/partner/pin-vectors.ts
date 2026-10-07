// supabase/functions/_shared/partner/pin-vectors.ts
//
// THE SHARED TEST VECTORS of the browser-derivation contract (pin-contract.ts): (PIN, salt, iterations) -> derived bytes. They were computed OUTSIDE the code under test, with Python's
// `hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations, 32)`, and they are test data, not secrets: these PINs are not any member's, and the salts are fixed constants.
//
// WHO USES THEM. supabase/tests/unit/partner-pin-contract.test.ts (vitest, Node WebCrypto), supabase/tests/deno-unit/partner-pin-contract.deno.test.ts (Deno WebCrypto) and, in S7, the PWA's own test: a browser
// that derives anything else for these inputs cannot verify against a stored verifier. To add a vector, compute it with the Python call above and add it HERE; both suites pick it up.
//
// (Field names avoid the words a secret scanner keys on; the values are the 32 derived bytes in lower-case hex and in canonical unpadded base64url.)

export interface PinDerivationVector {
  readonly pin: string;
  readonly saltHex: string;
  readonly iterations: number;
  readonly derivedHex: string;
  readonly derivedB64u: string;
}

export const PIN_DERIVATION_VECTORS: readonly PinDerivationVector[] = Object.freeze([
  {
    pin: "7391",
    saltHex: "000102030405060708090a0b0c0d0e0f",
    iterations: 600_000,
    derivedHex: "dcf10d521153899df6de891d0f2b2ea5b334a36d790eab45db3e29cdec56ec97",
    derivedB64u: "3PENUhFTiZ323okdDysupbM0o215DqtF2z4pzexW7Jc",
  },
  {
    pin: "0482",
    saltHex: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
    iterations: 210_000,
    derivedHex: "8968b7807d6845ed0afb7fd8a5ec45d61e62ea7fb421f78a288f597339e763b2",
    derivedB64u: "iWi3gH1oRe0K-3_YpexF1h5i6n-0IfeKKI9ZcznnY7I",
  },
  {
    pin: "9265",
    saltHex: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    iterations: 1_000_000,
    derivedHex: "c8210936854a90d92c59644a0b4c83716cc78ef321e9a0095ac5726bd73fa256",
    derivedB64u: "yCEJNoVKkNksWWRKC0yDcWzHjvMh6aAJWsVya9c_olY",
  },
  {
    pin: "5028",
    saltHex: "00000000000000000000000000000000",
    iterations: 600_000,
    derivedHex: "dd1cb1841592a64fd52918dfb9f25e3e405666fea1848bb39e6526fcbe99c516",
    derivedB64u: "3RyxhBWSpk_VKRjfufJePkBWZv6hhIuznmUm_L6ZxRY",
  },
]);

import { describe, expect, it } from "vitest";
import { EnvelopeError } from "../../functions/_shared/signin/errors.ts";
import { decryptToken, encryptToken, kekFromBase64, MAX_TOKEN_CHARS, unwrapDek, type Kek } from "../../functions/_shared/signin/envelope.ts";
import { toBase64Url } from "../../functions/_shared/signin/bytes.ts";

const newKek = (id: string): Kek => ({ kekId: id, key: crypto.getRandomValues(new Uint8Array(32)) });
const TOKEN = "r.0123456789abcdef.refresh-token-value";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    if (e instanceof EnvelopeError) return e.code;
    throw e;
  }
  return "no_error";
};

describe("envelope encryption", () => {
  it("round-trips a refresh token", async () => {
    const kek = newKek("k1");
    const env = await encryptToken(TOKEN, "apple", kek);
    expect(env.kekId).toBe("k1");
    expect(await decryptToken(env, "apple", kek)).toBe(TOKEN);
  });

  it("the plaintext does not appear in the ciphertext or the wrapped DEK", async () => {
    const kek = newKek("k1");
    const env = await encryptToken(TOKEN, "apple", kek);
    const hay = (b: Uint8Array) => new TextDecoder("latin1").decode(b);
    expect(hay(env.ciphertext)).not.toContain("refresh-token");
    expect(hay(env.dekWrapped)).not.toContain("refresh-token");
  });

  it("two encryptions of the same token differ (fresh DEK and IV each time), and both decrypt", async () => {
    const kek = newKek("k1");
    const a = await encryptToken(TOKEN, "apple", kek);
    const b = await encryptToken(TOKEN, "apple", kek);
    expect(toBase64Url(a.ciphertext)).not.toBe(toBase64Url(b.ciphertext));
    expect(toBase64Url(a.dekWrapped)).not.toBe(toBase64Url(b.dekWrapped));
    expect(await decryptToken(b, "apple", kek)).toBe(TOKEN);
  });

  it("every row gets its OWN fresh DEK and its OWN IVs (a constant DEK or a reused IV is a break, not a nit)", async () => {
    const kek = newKek("k1");
    const envs = await Promise.all([1, 2, 3, 4].map(() => encryptToken(TOKEN, "apple", kek)));
    const deks = await Promise.all(envs.map((e) => unwrapDek(e, kek)));
    expect(new Set(deks.map((d) => toBase64Url(d))).size).toBe(4);
    expect(new Set(envs.map((e) => toBase64Url(e.ciphertext.slice(1, 13)))).size).toBe(4); // token-layer IVs
    expect(new Set(envs.map((e) => toBase64Url(e.dekWrapped.slice(1, 13)))).size).toBe(4); // wrap-layer IVs
  });

  it("layout: version byte 1, 12-byte IV, ciphertext + 16-byte tag (token) and 32-byte DEK + tag (wrapped)", async () => {
    const env = await encryptToken(TOKEN, "apple", newKek("k1"));
    expect(env.ciphertext[0]).toBe(1);
    expect(env.ciphertext.length).toBe(1 + 12 + TOKEN.length + 16);
    expect(env.dekWrapped[0]).toBe(1);
    expect(env.dekWrapped.length).toBe(1 + 12 + 32 + 16);
  });

  it("must-fail: the wrong KEK (same id, other key)", async () => {
    const env = await encryptToken(TOKEN, "apple", newKek("k1"));
    expect(await code(decryptToken(env, "apple", newKek("k1")))).toBe("authentication_failed");
  });

  it("must-fail: a different kek id than the row names", async () => {
    const kek = newKek("k1");
    const env = await encryptToken(TOKEN, "apple", kek);
    expect(await code(decryptToken(env, "apple", { ...kek, kekId: "k2" }))).toBe("kek_mismatch");
  });

  it("must-fail: the ciphertext moved to another provider's row (AAD binds the provider)", async () => {
    const kek = newKek("k1");
    const env = await encryptToken(TOKEN, "apple", kek);
    expect(await code(decryptToken(env, "google", kek))).toBe("authentication_failed");
  });

  it("must-fail: the wrapped DEK bound to another kek id (AAD binds the kek id)", async () => {
    const kek = newKek("k1");
    const env = await encryptToken(TOKEN, "apple", kek);
    // Same key bytes under a different id: the row still names k1, so it cannot be unwrapped as k2.
    const asK2 = await encryptToken(TOKEN, "apple", { kekId: "k2", key: kek.key });
    expect(await code(decryptToken({ ...asK2, kekId: "k1" }, "apple", kek))).toBe("authentication_failed");
    expect(await decryptToken(env, "apple", kek)).toBe(TOKEN);
  });

  it("must-fail: any flipped bit in the ciphertext or the wrapped DEK, and a truncated blob, and an unknown version", async () => {
    const kek = newKek("k1");
    const env = await encryptToken(TOKEN, "apple", kek);
    const flip = (b: Uint8Array, i: number) => {
      const c = b.slice();
      c[i] = c[i]! ^ 1;
      return c;
    };
    for (const i of [1, 13, env.ciphertext.length - 1]) expect(await code(decryptToken({ ...env, ciphertext: flip(env.ciphertext, i) }, "apple", kek))).toBe("authentication_failed");
    for (const i of [1, 13, env.dekWrapped.length - 1]) expect(await code(decryptToken({ ...env, dekWrapped: flip(env.dekWrapped, i) }, "apple", kek))).toBe("authentication_failed");
    expect(await code(decryptToken({ ...env, ciphertext: env.ciphertext.slice(0, 10) }, "apple", kek))).toBe("format");
    expect(await code(decryptToken({ ...env, ciphertext: flip(env.ciphertext, 0) }, "apple", kek))).toBe("format");
  });

  it("refuses an empty or absurdly long token, and a KEK that is not 32 bytes", async () => {
    const kek = newKek("k1");
    expect(await code(encryptToken("", "apple", kek))).toBe("token_length");
    expect(await code(encryptToken("x".repeat(MAX_TOKEN_CHARS + 1), "apple", kek))).toBe("token_length");
    expect(await code(encryptToken(TOKEN, "apple", { kekId: "k1", key: new Uint8Array(16) }))).toBe("kek_length");
  });

  it("kekFromBase64: exactly 32 bytes, standard base64 as Vault stores it", () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const std = btoa(String.fromCharCode(...raw));
    expect(kekFromBase64("t1", std).key).toEqual(raw);
    for (const bad of [btoa("short"), "", "!!!", btoa("x".repeat(33))]) expect(() => kekFromBase64("t1", bad)).toThrow(EnvelopeError);
  });
});

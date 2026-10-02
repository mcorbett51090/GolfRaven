// supabase/functions/_shared/signin/envelope.ts
//
// Envelope encryption for the sign-in provider grants (build plan §4.8: "a per-row DEK wrapped by a KEK ... decrypted only
// inside connector functions"). The refresh token is the one thing in this feature that must never leak, so:
//
//   plaintext refresh token
//       --AES-256-GCM, a fresh random 32-byte DEK, a fresh 12-byte IV-->  ciphertext      (app.signin_provider_token
//   DEK  --AES-256-GCM, the KEK, a fresh 12-byte IV------------------>  dek_wrapped        .refresh_token_ciphertext
//                                                                                         .dek_wrapped, .kek_id)
//
// WHERE THE KEK LIVES: Supabase Vault (`siwa_token_kek_<id>`, read through private.get_signin_token_kek), the §4.8 "otherwise
// Vault" branch. A KMS outside Supabase would implement the same two-method `Kek` shape below; nothing else changes.
// WHERE THE CRYPTO RUNS: here, in the Edge runtime, never in the database. The plaintext token and the DEK therefore never
// travel as a query parameter (Postgres logs the parameters of a failing statement); only ciphertext and the wrapped DEK do,
// and the KEK comes back as a function RESULT.
//
// Both layers use AES-GCM with ASSOCIATED DATA, so a ciphertext cannot be moved to another provider's row or another KEK:
//   token layer  aad = "golfraven.signin_provider_token.v1|<provider>"
//   wrap layer   aad = "golfraven.signin_provider_token.dek.v1|<kek_id>"
// Layout of both blobs: 0x01 (format version) || 12-byte IV || ciphertext+tag. The IV is random per encryption; with a
// 96-bit random IV and one fresh DEK per row, the GCM random-nonce collision bound is irrelevant for the token layer, and
// the KEK only ever wraps one 32-byte DEK per token (a few thousand wraps over its lifetime).

import { EnvelopeError } from "./errors.ts";
import { fromBase64Url, utf8 } from "./bytes.ts";

const VERSION = 1;
const IV_BYTES = 12;
const KEY_BYTES = 32;
/** The longest refresh token this accepts. Apple's are ~100 characters; a response with something absurd is not a token. */
export const MAX_TOKEN_CHARS = 4096;

export interface Kek {
  kekId: string;
  /** Exactly 32 raw bytes. */
  key: Uint8Array;
}

export interface Envelope {
  ciphertext: Uint8Array;
  dekWrapped: Uint8Array;
  kekId: string;
}

const tokenAad = (provider: string) => utf8(`golfraven.signin_provider_token.v1|${provider}`);
const wrapAad = (kekId: string) => utf8(`golfraven.signin_provider_token.dek.v1|${kekId}`);

async function aesKey(raw: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw.slice().buffer, { name: "AES-GCM" }, false, [usage]);
}

async function seal(key: CryptoKey, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad.slice().buffer, tagLength: 128 }, key, plaintext.slice().buffer));
  const out = new Uint8Array(1 + IV_BYTES + ct.length);
  out[0] = VERSION;
  out.set(iv, 1);
  out.set(ct, 1 + IV_BYTES);
  return out;
}

async function open(key: CryptoKey, blob: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (blob.length < 1 + IV_BYTES + 16 || blob[0] !== VERSION) throw new EnvelopeError("format");
  const iv = blob.slice(1, 1 + IV_BYTES);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad.slice().buffer, tagLength: 128 }, key, blob.slice(1 + IV_BYTES).buffer));
  } catch {
    // Wrong key, wrong aad (another provider or KEK) and a tampered blob are indistinguishable by design.
    throw new EnvelopeError("authentication_failed");
  }
}

/** A KEK from the base64 string Vault returns. Exactly one 32-byte key, or a thrown EnvelopeError (never echoed). */
export function kekFromBase64(kekId: string, b64: string): Kek {
  const key = fromBase64Url(b64);
  if (key === null || key.length !== KEY_BYTES) throw new EnvelopeError("kek_length");
  return { kekId, key };
}

export async function encryptToken(plaintext: string, provider: string, kek: Kek): Promise<Envelope> {
  if (plaintext.length === 0 || plaintext.length > MAX_TOKEN_CHARS) throw new EnvelopeError("token_length");
  if (kek.key.length !== KEY_BYTES) throw new EnvelopeError("kek_length");
  const dek = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  try {
    const ciphertext = await seal(await aesKey(dek, "encrypt"), utf8(plaintext), tokenAad(provider));
    const dekWrapped = await seal(await aesKey(kek.key, "encrypt"), dek, wrapAad(kek.kekId));
    return { ciphertext, dekWrapped, kekId: kek.kekId };
  } finally {
    dek.fill(0);
  }
}

/** Unwraps the per-row DEK. Exported so the tests can prove each row really has its own fresh key; production code decrypts through
 * `decryptToken`, which zeroes the DEK as soon as it is used. */
export async function unwrapDek(env: Pick<Envelope, "dekWrapped" | "kekId">, kek: Kek): Promise<Uint8Array> {
  if (kek.kekId !== env.kekId) throw new EnvelopeError("kek_mismatch");
  if (kek.key.length !== KEY_BYTES) throw new EnvelopeError("kek_length");
  return open(await aesKey(kek.key, "decrypt"), env.dekWrapped, wrapAad(env.kekId));
}

export async function decryptToken(env: Envelope, provider: string, kek: Kek): Promise<string> {
  const dek = await unwrapDek(env, kek);
  try {
    if (dek.length !== KEY_BYTES) throw new EnvelopeError("dek_length");
    const plain = await open(await aesKey(dek, "decrypt"), env.ciphertext, tokenAad(provider));
    return new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch (e) {
    if (e instanceof EnvelopeError) throw e;
    throw new EnvelopeError("plaintext_encoding");
  } finally {
    dek.fill(0);
  }
}

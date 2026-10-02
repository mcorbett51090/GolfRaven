// supabase/tests/unit/rewards-test-crypto.ts
//
// TEST-ONLY helpers that build the byte formats rewards-activate verifies: an
// ECDSA P-256 key pair, an App Attest-shaped assertion (CBOR map +
// authenticatorData + DER signature) and the request binding. They encode the
// format as app-attest.ts's header documents it — which is exactly why a pass
// here proves self-consistency, NOT conformance with a real iOS device
// (`[unverified — no Apple device in this environment]`).

import { computeRequestBinding, concatBytes, type BoundBody } from "../../functions/_shared/rewards/binding.ts";

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
}

export interface TestKey {
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array; // 65-byte uncompressed point
}

export async function generateP256(): Promise<TestKey> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, publicKeyRaw };
}

/** Web Crypto's raw r‖s -> DER, as the Secure Enclave emits it. */
export function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  const enc = (half: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < half.length - 1 && half[i] === 0) i++;
    let body: Uint8Array = half.slice(i);
    if (body[0]! & 0x80) body = concatBytes(new Uint8Array([0]), body);
    return concatBytes(new Uint8Array([0x02, body.length]), body);
  };
  const r = enc(raw.slice(0, 32));
  const s = enc(raw.slice(32, 64));
  return concatBytes(new Uint8Array([0x30, r.length + s.length]), r, s);
}

function cborHead(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  return new Uint8Array([(major << 5) | 25, n >> 8, n & 0xff]);
}
export function cborBytes(b: Uint8Array): Uint8Array {
  return concatBytes(cborHead(2, b.length), b);
}
export function cborText(s: string): Uint8Array {
  const b = new TextEncoder().encode(s);
  return concatBytes(cborHead(3, b.length), b);
}
export function cborMap(entries: Array<[string, Uint8Array]>): Uint8Array {
  return concatBytes(cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [cborText(k), v]));
}

export function authenticatorData(rpIdHash: Uint8Array, counter: number, flags = 0x40): Uint8Array {
  const out = new Uint8Array(37);
  out.set(rpIdHash, 0);
  out[32] = flags;
  new DataView(out.buffer).setUint32(33, counter, false);
  return out;
}

export interface BuiltAssertion {
  assertionB64: string;
  authData: Uint8Array;
}

export function toB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Builds an assertion signed over SHA-256(authData ‖ clientDataHash). */
export async function buildAssertion(opts: {
  key: TestKey;
  appId: string;
  counter: number;
  clientDataHash: Uint8Array;
  rpIdHash?: Uint8Array;
  signWithHash?: Uint8Array; // sign a different clientDataHash than the one the server will compute
  mutateSignature?: (sig: Uint8Array) => Uint8Array;
}): Promise<BuiltAssertion> {
  const rpIdHash = opts.rpIdHash ?? (await sha256(new TextEncoder().encode(opts.appId)));
  const authData = authenticatorData(rpIdHash, opts.counter);
  const nonce = await sha256(concatBytes(authData, opts.signWithHash ?? opts.clientDataHash));
  const rawSig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, opts.key.privateKey, nonce.slice().buffer));
  const der = rawSignatureToDer(rawSig);
  const sig = opts.mutateSignature ? opts.mutateSignature(der) : der;
  const cbor = cborMap([
    ["signature", cborBytes(sig)],
    ["authenticatorData", cborBytes(authData)],
  ]);
  return { assertionB64: toB64(cbor), authData };
}

export async function bindingFor(body: BoundBody, challenge: Uint8Array): Promise<Uint8Array> {
  return computeRequestBinding(sha256, body, challenge);
}

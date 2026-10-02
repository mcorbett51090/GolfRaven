// supabase/tests/unit/attest-test-pki.ts
//
// TEST-ONLY. Builds synthetic App Attest ATTESTATION OBJECTS so the registration verifier
// (_shared/rewards/app-attest-registration.ts) can be exercised end to end with no Apple device:
//   - a throw-away three-level PKI: a P-384 "root" (the trust anchor the test verifier is given in
//     place of Apple's pinned one), a P-384 "intermediate", and a P-256 credential-certificate leaf
//     per attestation that carries the nonce extension 1.2.840.113635.100.8.2;
//   - the CBOR attestation object `{fmt, attStmt: {x5c, receipt}, authData}` with authenticatorData
//     laid out as the verifier's header documents (rpIdHash ‖ flags ‖ counter ‖ aaguid ‖ credIdLen ‖
//     credId ‖ COSE_Key).
// It encodes the format the way the verifier's own header describes it — which is exactly why a pass
// proves self-consistency, NOT conformance with a real iPhone
// (`[unverified — no Apple device in this environment]`). Every field a must-fail case needs to get
// wrong is an option here.

import { concatBytes } from "../../functions/_shared/rewards/binding.ts";

const ENC = new TextEncoder();

// ---------------------------------------------------------------------------
// DER encoders
// ---------------------------------------------------------------------------
function derLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  return new Uint8Array([0x82, n >> 8, n & 0xff]);
}
export function der(tag: number, ...content: Uint8Array[]): Uint8Array {
  const body = concatBytes(...content);
  return concatBytes(new Uint8Array([tag]), derLen(body.length), body);
}
export const derSeq = (...c: Uint8Array[]) => der(0x30, ...c);
export const derSet = (...c: Uint8Array[]) => der(0x31, ...c);
export const derOctet = (b: Uint8Array) => der(0x04, b);
export const derBool = (v: boolean) => der(0x01, new Uint8Array([v ? 0xff : 0x00]));
export const derUtf8 = (s: string) => der(0x0c, ENC.encode(s));
export function derInt(n: number | Uint8Array): Uint8Array {
  let bytes: Uint8Array;
  if (typeof n === "number") {
    const tmp: number[] = [];
    let v = n;
    do {
      tmp.unshift(v & 0xff);
      v = Math.floor(v / 256);
    } while (v > 0);
    bytes = new Uint8Array(tmp);
  } else {
    bytes = n;
  }
  if (bytes[0]! & 0x80) bytes = concatBytes(new Uint8Array([0]), bytes);
  return der(0x02, bytes);
}
export function derOid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map(Number);
  const out: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const a of arcs.slice(2)) {
    const tmp: number[] = [a & 0x7f];
    let v = Math.floor(a / 128);
    while (v > 0) {
      tmp.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...tmp);
  }
  return der(0x06, new Uint8Array(out));
}
export const derBitString = (b: Uint8Array) => der(0x03, new Uint8Array([0]), b);
export function derUtcTime(ms: number): Uint8Array {
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const yy = d.getUTCFullYear() % 100;
  return der(0x17, ENC.encode(`${p(yy)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`));
}

/** Web Crypto's raw r‖s -> DER ECDSA-Sig-Value (minimal INTEGERs). */
export function rawSigToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const enc = (h: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < h.length - 1 && h[i] === 0) i++;
    return derInt(h.slice(i));
  };
  return derSeq(enc(raw.slice(0, half)), enc(raw.slice(half)));
}

// ---------------------------------------------------------------------------
// CBOR encoders (general: ints incl. negative, bstr, tstr, arrays, maps with int OR text keys)
// ---------------------------------------------------------------------------
function cborHead(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 65536) return new Uint8Array([(major << 5) | 25, n >> 8, n & 0xff]);
  return new Uint8Array([(major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export const cbBytes = (b: Uint8Array) => concatBytes(cborHead(2, b.length), b);
export const cbText = (s: string) => {
  const b = ENC.encode(s);
  return concatBytes(cborHead(3, b.length), b);
};
export const cbInt = (n: number) => (n >= 0 ? cborHead(0, n) : cborHead(1, -1 - n));
export const cbArray = (...items: Uint8Array[]) => concatBytes(cborHead(4, items.length), ...items);
export const cbMap = (entries: Array<[Uint8Array, Uint8Array]>) => concatBytes(cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [k, v]));

// ---------------------------------------------------------------------------
// Keys and certificates
// ---------------------------------------------------------------------------
export type CurveName = "P-256" | "P-384";
export interface Pair {
  curve: CurveName;
  privateKey: CryptoKey;
  /** SubjectPublicKeyInfo DER. */
  spki: Uint8Array;
  /** Uncompressed point. */
  point: Uint8Array;
}

export async function genPair(curve: CurveName): Promise<Pair> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
  return {
    curve,
    privateKey: kp.privateKey,
    spki: new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)),
    point: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
  };
}

const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
export const NONCE_OID = "1.2.840.113635.100.8.2";

export interface Ext {
  oid: string;
  critical?: boolean;
  /** The extnValue CONTENT (DER). */
  value: Uint8Array;
}

export function nameOf(cn: string): Uint8Array {
  return derSeq(derSet(derSeq(derOid("2.5.4.3"), derUtf8(cn))));
}

export interface CertOptions {
  subjectCn: string;
  issuerCn: string;
  subject: Pair;
  issuer: Pair;
  hash: "SHA-256" | "SHA-384";
  notBeforeMs: number;
  notAfterMs: number;
  extensions: Ext[];
  serial?: number;
  /** Test knobs for malformed-DER cases. */
  version?: number;
  innerSigOid?: string;
  mutateTbs?: (tbs: Uint8Array) => Uint8Array;
  /** Applied AFTER signing: the certificate carries TBS bytes its signature does not cover. */
  tamperTbsAfterSigning?: (tbs: Uint8Array) => Uint8Array;
  mutateSignatureDer?: (sig: Uint8Array) => Uint8Array;
  /** Sign with this key instead of `issuer.privateKey` (a "wrong key" case). */
  signWith?: CryptoKey;
}

export async function buildCert(o: CertOptions): Promise<Uint8Array> {
  const sigOid = o.hash === "SHA-256" ? OID_ECDSA_SHA256 : OID_ECDSA_SHA384;
  const algId = derSeq(derOid(sigOid));
  const extBlock =
    o.extensions.length === 0
      ? new Uint8Array(0)
      : der(0xa3, derSeq(...o.extensions.map((e) => derSeq(derOid(e.oid), ...(e.critical ? [derBool(true)] : []), derOctet(e.value)))));
  let tbs = derSeq(
    der(0xa0, derInt(o.version ?? 2)),
    derInt(o.serial ?? 1),
    o.innerSigOid ? derSeq(derOid(o.innerSigOid)) : algId,
    nameOf(o.issuerCn),
    derSeq(derUtcTime(o.notBeforeMs), derUtcTime(o.notAfterMs)),
    nameOf(o.subjectCn),
    o.subject.spki,
    extBlock,
  );
  if (o.mutateTbs) tbs = o.mutateTbs(tbs);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: o.hash }, o.signWith ?? o.issuer.privateKey, tbs.slice().buffer));
  let sig = rawSigToDer(raw);
  if (o.mutateSignatureDer) sig = o.mutateSignatureDer(sig);
  return derSeq(o.tamperTbsAfterSigning ? o.tamperTbsAfterSigning(tbs) : tbs, algId, derBitString(sig));
}

// ---------------------------------------------------------------------------
// The PKI and the attestation object
// ---------------------------------------------------------------------------
export interface TestPki {
  root: Pair;
  rootDer: Uint8Array;
  intermediate: Pair;
  intermediateDer: Uint8Array;
  rootCn: string;
  intermediateCn: string;
  notBeforeMs: number;
  notAfterMs: number;
}

const HOUR = 3_600_000;

export async function buildTestPki(opts: { nowMs?: number; rootCn?: string } = {}): Promise<TestPki> {
  const now = opts.nowMs ?? Date.now();
  const notBeforeMs = now - 24 * HOUR;
  const notAfterMs = now + 24 * 365 * HOUR;
  const rootCn = opts.rootCn ?? "Test App Attestation Root CA";
  const intermediateCn = "Test App Attestation CA 1";
  const root = await genPair("P-384");
  const intermediate = await genPair("P-384");
  const caExt = (pathLen?: number): Ext => ({
    oid: "2.5.29.19",
    critical: true,
    value: derSeq(derBool(true), ...(pathLen !== undefined ? [derInt(pathLen)] : [])),
  });
  const rootDer = await buildCert({ subjectCn: rootCn, issuerCn: rootCn, subject: root, issuer: root, hash: "SHA-384", notBeforeMs, notAfterMs, extensions: [caExt()], serial: 0x0b0b });
  const intermediateDer = await buildCert({
    subjectCn: intermediateCn,
    issuerCn: rootCn,
    subject: intermediate,
    issuer: root,
    hash: "SHA-384",
    notBeforeMs,
    notAfterMs,
    extensions: [caExt(0)],
    serial: 2,
  });
  return { root, rootDer, intermediate, intermediateDer, rootCn, intermediateCn, notBeforeMs, notAfterMs };
}

const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer));

export function toB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export interface AttestationOptions {
  pki: TestPki;
  appId: string;
  environment: "production" | "development";
  clientDataHash: Uint8Array;
  /** Default: a fresh P-256 key; pass one to attest a specific key. */
  leaf?: Pair;
  counter?: number;
  aaguid?: Uint8Array;
  rpIdHash?: Uint8Array;
  flags?: number;
  /** The nonce hashed into the extension; default SHA-256(authData ‖ clientDataHash). */
  nonce?: Uint8Array;
  nonceShape?: "wrapped" | "bare";
  omitNonceExtension?: boolean;
  /** The credentialId inside authData; default the key id bytes. */
  credentialId?: Uint8Array;
  /** The COSE point; default the leaf's. */
  cosePoint?: Uint8Array;
  coseExtraKey?: boolean;
  fmt?: string;
  /** Replace the intermediate certificate in x5c. */
  intermediateDer?: Uint8Array;
  /** Replace the leaf certificate (built from `leaf`) wholesale. */
  leafDerOverride?: Uint8Array;
  leafNotBeforeMs?: number;
  leafNotAfterMs?: number;
  leafHash?: "SHA-256" | "SHA-384";
  leafExtraExtensions?: Ext[];
  /** Sign the leaf with this key instead of the intermediate's (broken chain). */
  leafSignWith?: CryptoKey;
  /** Issuer name written into the leaf; default the intermediate's subject. */
  leafIssuerCn?: string;
  mutateAuthData?: (ad: Uint8Array) => Uint8Array;
  /** Shape the object after the fact. */
  buildObject?: (parts: { authData: Uint8Array; x5c: Uint8Array[]; receipt: Uint8Array; fmt: string }) => Uint8Array;
  x5cCount?: number;
}

export interface BuiltAttestation {
  attestationB64: string;
  keyId: string;
  keyIdBytes: Uint8Array;
  leaf: Pair;
  authData: Uint8Array;
  leafDer: Uint8Array;
}

export async function buildAttestation(o: AttestationOptions): Promise<BuiltAttestation> {
  const leaf = o.leaf ?? (await genPair("P-256"));
  const keyIdBytes = await sha256(leaf.point);
  const keyId = toB64(keyIdBytes);

  const rpIdHash = o.rpIdHash ?? (await sha256(ENC.encode(o.appId)));
  const aaguid = o.aaguid ?? (o.environment === "production" ? concatBytes(ENC.encode("appattest"), new Uint8Array(7)) : ENC.encode("appattestdevelop"));
  const credId = o.credentialId ?? keyIdBytes;
  const cosePoint = o.cosePoint ?? leaf.point;
  const coseEntries: Array<[Uint8Array, Uint8Array]> = [
    [cbInt(1), cbInt(2)],
    [cbInt(3), cbInt(-7)],
    [cbInt(-1), cbInt(1)],
    [cbInt(-2), cbBytes(cosePoint.slice(1, 33))],
    [cbInt(-3), cbBytes(cosePoint.slice(33, 65))],
    ...(o.coseExtraKey ? ([[cbInt(9), cbInt(1)]] as Array<[Uint8Array, Uint8Array]>) : []),
  ];
  const head = new Uint8Array(37);
  head.set(rpIdHash, 0);
  head[32] = o.flags ?? 0x40;
  new DataView(head.buffer).setUint32(33, o.counter ?? 0, false);
  const credLen = new Uint8Array(2);
  new DataView(credLen.buffer).setUint16(0, credId.length, false);
  let authData = concatBytes(head, aaguid, credLen, credId, cbMap(coseEntries));
  if (o.mutateAuthData) authData = o.mutateAuthData(authData);

  const nonce = o.nonce ?? (await sha256(concatBytes(authData, o.clientDataHash)));
  const nonceValue = o.nonceShape === "bare" ? derSeq(derOctet(nonce)) : derSeq(der(0xa1, derOctet(nonce)));
  const extensions: Ext[] = [...(o.omitNonceExtension ? [] : [{ oid: NONCE_OID, value: nonceValue }]), ...(o.leafExtraExtensions ?? [])];

  const leafDer =
    o.leafDerOverride ??
    (await buildCert({
      subjectCn: "Test credential certificate",
      issuerCn: o.leafIssuerCn ?? o.pki.intermediateCn,
      subject: leaf,
      issuer: o.pki.intermediate,
      hash: o.leafHash ?? "SHA-256",
      notBeforeMs: o.leafNotBeforeMs ?? o.pki.notBeforeMs,
      notAfterMs: o.leafNotAfterMs ?? o.pki.notAfterMs,
      extensions,
      serial: 3,
      signWith: o.leafSignWith,
    }));

  const receipt = ENC.encode("test-receipt");
  const interDer = o.intermediateDer ?? o.pki.intermediateDer;
  const x5c = (o.x5cCount ?? 2) === 2 ? [leafDer, interDer] : (o.x5cCount ?? 2) === 1 ? [leafDer] : [leafDer, interDer, o.pki.rootDer];
  const fmt = o.fmt ?? "apple-appattest";
  const object = o.buildObject
    ? o.buildObject({ authData, x5c, receipt, fmt })
    : cbMap([
        [cbText("fmt"), cbText(fmt)],
        [cbText("attStmt"), cbMap([[cbText("x5c"), cbArray(...x5c.map(cbBytes))], [cbText("receipt"), cbBytes(receipt)]])],
        [cbText("authData"), cbBytes(authData)],
      ]);
  return { attestationB64: toB64(object), keyId, keyIdBytes, leaf, authData, leafDer };
}

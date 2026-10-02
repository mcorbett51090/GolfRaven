// supabase/functions/_shared/rewards/x509-lite.ts
//
// A minimal X.509 reader and chain checker for ONE job: verifying that an App Attest credential
// certificate chains to a PINNED trust anchor (Apple's App Attestation Root CA). It is not a general
// path validator and does not try to be one.
//
// What it does, for a chain `leaf (credCert) <- intermediate <- trust anchor`:
//   - parses each certificate with strict DER (der.ts): v3 only, unknown/unique-id fields refused,
//     the TBS `signature` algorithm must equal the outer one, extensions unique;
//   - names chain by byte equality (leaf.issuer == intermediate.subject, intermediate.issuer ==
//     anchor.subject);
//   - every certificate is within its validity window at `nowMs` (± `skewMs`);
//   - the intermediate is a CA (`basicConstraints` cA = TRUE; a pathLen, if present, is not enforced) and the
//     leaf is not;
//   - each signature verifies with Web Crypto: the leaf under the intermediate's key, the
//     intermediate under the anchor's key. ECDSA over P-256 or P-384 with SHA-256 or SHA-384 only
//     (the signature algorithm OID fixes the hash; the issuer's SPKI fixes the curve).
//
// What it deliberately does NOT do: revocation, name constraints, policy, key usage / extended key
// usage, and the criticality of extensions it does not recognise. The chain is rooted in a pinned
// Apple CA, so the value of those checks here is nil, and refusing on an Apple extension this code has
// never seen would turn an unknown into a false rejection of a real device `[unverified]`.
//
// ⚠ `[unverified — training knowledge of Apple's App Attest certificates]`: the intermediate
// ("Apple App Attestation CA 1") is believed to be a P-384 CA with basicConstraints cA=TRUE, and the
// credential certificate a P-256 leaf signed by it. Exercised here only against certificates this
// repo's tests build, and against the real root (parsed, not chained). A live conformance run on a
// physical iPhone is the check.

import {
  DerError,
  TAG,
  children,
  ecdsaSignatureDerToRaw,
  readBitStringBytes,
  readBoolean,
  readOid,
  readSmallInteger,
  readTime,
  readTlv,
  readUnsignedInteger,
  tlvBytes,
  tlvContent,
} from "./der.ts";

export type Curve = "P-256" | "P-384";

export interface CertExtension {
  oid: string;
  critical: boolean;
  /** The extnValue OCTET STRING's CONTENT (itself usually DER). */
  value: Uint8Array;
}

export interface ParsedCert {
  der: Uint8Array;
  /** The exact encoded tbsCertificate (header included): what the signature covers. */
  tbs: Uint8Array;
  sigAlgOid: string;
  /** The signature's DER `ECDSA-Sig-Value`. */
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  /** The exact encoded SubjectPublicKeyInfo. */
  spki: Uint8Array;
  curve: Curve;
  /** The uncompressed point, `0x04 ‖ X ‖ Y`. */
  publicKeyRaw: Uint8Array;
  notBeforeMs: number;
  notAfterMs: number;
  extensions: CertExtension[];
  /** basicConstraints: `null` when the extension is absent. */
  basicConstraints: { ca: boolean; pathLen: number | null } | null;
}

const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_PRIME256V1 = "1.2.840.10045.3.1.7";
const OID_SECP384R1 = "1.3.132.0.34";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";

const SIG_HASH: Record<string, "SHA-256" | "SHA-384"> = {
  [OID_ECDSA_SHA256]: "SHA-256",
  [OID_ECDSA_SHA384]: "SHA-384",
};
const CURVE_BYTES: Record<Curve, number> = { "P-256": 32, "P-384": 48 };

function parseAlgorithmIdentifier(buf: Uint8Array, seq: ReturnType<typeof readTlv>): string {
  if (seq.tag !== TAG.SEQUENCE) throw new DerError("AlgorithmIdentifier is not a SEQUENCE");
  const kids = children(buf, seq);
  // ECDSA-with-SHA2 AlgorithmIdentifiers carry NO parameters (RFC 5758 §3.2): exactly the OID.
  if (kids.length !== 1) throw new DerError("AlgorithmIdentifier must be exactly an OID");
  return readOid(buf, kids[0]!, "signature algorithm");
}

function parseSpki(buf: Uint8Array, seq: ReturnType<typeof readTlv>): { curve: Curve; point: Uint8Array } {
  if (seq.tag !== TAG.SEQUENCE) throw new DerError("SubjectPublicKeyInfo is not a SEQUENCE");
  const [alg, bits, ...rest] = children(buf, seq);
  if (!alg || !bits || rest.length > 0) throw new DerError("SubjectPublicKeyInfo shape");
  if (alg.tag !== TAG.SEQUENCE) throw new DerError("SPKI algorithm is not a SEQUENCE");
  const algKids = children(buf, alg);
  if (algKids.length !== 2) throw new DerError("SPKI algorithm must be { id-ecPublicKey, namedCurve }");
  if (readOid(buf, algKids[0]!, "SPKI algorithm") !== OID_EC_PUBLIC_KEY) throw new DerError("SPKI is not an EC key");
  const curveOid = readOid(buf, algKids[1]!, "SPKI curve");
  const curve: Curve | null = curveOid === OID_PRIME256V1 ? "P-256" : curveOid === OID_SECP384R1 ? "P-384" : null;
  if (!curve) throw new DerError(`unsupported curve ${curveOid}`);
  const point = readBitStringBytes(buf, bits, "SPKI public key");
  if (point.length !== 1 + 2 * CURVE_BYTES[curve] || point[0] !== 0x04) throw new DerError("public key is not an uncompressed point");
  return { curve, point: point.slice() };
}

function parseExtensions(buf: Uint8Array, wrapper: ReturnType<typeof readTlv>): CertExtension[] {
  // [3] EXPLICIT SEQUENCE OF Extension
  const inner = children(buf, wrapper);
  if (inner.length !== 1 || inner[0]!.tag !== TAG.SEQUENCE) throw new DerError("extensions must be one SEQUENCE");
  const out: CertExtension[] = [];
  const seen = new Set<string>();
  for (const ext of children(buf, inner[0]!)) {
    if (ext.tag !== TAG.SEQUENCE) throw new DerError("extension is not a SEQUENCE");
    const parts = children(buf, ext);
    if (parts.length < 2 || parts.length > 3) throw new DerError("extension shape");
    const oid = readOid(buf, parts[0]!, "extension id");
    let critical = false;
    let idx = 1;
    if (parts[1]!.tag === TAG.BOOLEAN) {
      critical = readBoolean(buf, parts[1]!);
      // DER omits a DEFAULT value: an explicit FALSE is not the canonical encoding.
      if (!critical) throw new DerError("explicit DEFAULT FALSE criticality is not DER");
      idx = 2;
    }
    const valueTlv = parts[idx];
    if (!valueTlv || valueTlv.tag !== TAG.OCTET_STRING || parts.length !== idx + 1) throw new DerError("extension value");
    if (seen.has(oid)) throw new DerError(`duplicate extension ${oid}`);
    seen.add(oid);
    out.push({ oid, critical, value: tlvContent(buf, valueTlv).slice() });
  }
  return out;
}

function parseBasicConstraints(value: Uint8Array): { ca: boolean; pathLen: number | null } {
  const seq = readTlv(value, 0, value.length);
  if (seq.tag !== TAG.SEQUENCE || seq.end !== value.length) throw new DerError("basicConstraints shape");
  const kids = children(value, seq);
  let ca = false;
  let pathLen: number | null = null;
  let i = 0;
  if (kids[i] && kids[i]!.tag === TAG.BOOLEAN) {
    ca = readBoolean(value, kids[i]!);
    if (!ca) throw new DerError("explicit DEFAULT FALSE cA is not DER");
    i++;
  }
  if (kids[i] && kids[i]!.tag === TAG.INTEGER) {
    pathLen = readSmallInteger(value, kids[i]!, "pathLenConstraint");
    i++;
  }
  if (i !== kids.length) throw new DerError("basicConstraints trailing content");
  return { ca, pathLen };
}

/** Parses one DER certificate. Throws `DerError` on anything unexpected. */
export function parseCertificate(der: Uint8Array): ParsedCert {
  const cert = readTlv(der, 0, der.length);
  if (cert.tag !== TAG.SEQUENCE || cert.end !== der.length) throw new DerError("certificate is not one SEQUENCE");
  const top = children(der, cert);
  if (top.length !== 3) throw new DerError("certificate must be { tbsCertificate, signatureAlgorithm, signatureValue }");
  const tbsTlv = top[0]!;
  const sigAlgTlv = top[1]!;
  const sigTlv = top[2]!;
  if (tbsTlv.tag !== TAG.SEQUENCE) throw new DerError("tbsCertificate is not a SEQUENCE");

  const sigAlgOid = parseAlgorithmIdentifier(der, sigAlgTlv);
  const signature = readBitStringBytes(der, sigTlv, "signatureValue").slice();

  const t = children(der, tbsTlv);
  let i = 0;
  const next = (what: string) => {
    const x = t[i++];
    if (!x) throw new DerError(`tbsCertificate: missing ${what}`);
    return x;
  };
  const versionWrap = next("version");
  if (versionWrap.tag !== 0xa0) throw new DerError("tbsCertificate: version must be present (v3)");
  const versionKids = children(der, versionWrap);
  if (versionKids.length !== 1 || readSmallInteger(der, versionKids[0]!, "version") !== 2) throw new DerError("only X.509 v3 is accepted");
  readUnsignedInteger(der, next("serialNumber"), 21, "serialNumber");
  const innerSigAlg = parseAlgorithmIdentifier(der, next("signature"));
  if (innerSigAlg !== sigAlgOid) throw new DerError("inner and outer signature algorithms differ");
  const issuerTlv = next("issuer");
  if (issuerTlv.tag !== TAG.SEQUENCE) throw new DerError("issuer is not a Name");
  const validityTlv = next("validity");
  if (validityTlv.tag !== TAG.SEQUENCE) throw new DerError("validity is not a SEQUENCE");
  const vKids = children(der, validityTlv);
  if (vKids.length !== 2) throw new DerError("validity must be { notBefore, notAfter }");
  const notBeforeMs = readTime(der, vKids[0]!);
  const notAfterMs = readTime(der, vKids[1]!);
  const subjectTlv = next("subject");
  if (subjectTlv.tag !== TAG.SEQUENCE) throw new DerError("subject is not a Name");
  const spkiTlv = next("subjectPublicKeyInfo");
  const { curve, point } = parseSpki(der, spkiTlv);

  let extensions: CertExtension[] = [];
  while (i < t.length) {
    const x = t[i++]!;
    if (x.tag === 0xa3) {
      if (i !== t.length) throw new DerError("extensions must be the last field");
      extensions = parseExtensions(der, x);
    } else {
      // [1]/[2] unique identifiers and anything else: not in an App Attest chain.
      throw new DerError(`unexpected tbsCertificate field with tag 0x${x.tag.toString(16)}`);
    }
  }

  const bc = extensions.find((e) => e.oid === OID_BASIC_CONSTRAINTS);
  return {
    der,
    tbs: tlvBytes(der, tbsTlv),
    sigAlgOid,
    signature,
    issuer: tlvBytes(der, issuerTlv),
    subject: tlvBytes(der, subjectTlv),
    spki: tlvBytes(der, spkiTlv),
    curve,
    publicKeyRaw: point,
    notBeforeMs,
    notAfterMs,
    extensions,
    basicConstraints: bc ? parseBasicConstraints(bc.value) : null,
  };
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** `cert` was signed by `issuer`'s key: ECDSA, hash from the signature algorithm OID, curve from the
 * issuer's SPKI. `false` for any malformed signature or unsupported algorithm. */
export async function certSignedBy(cert: ParsedCert, issuer: ParsedCert): Promise<boolean> {
  const hash = SIG_HASH[cert.sigAlgOid];
  if (!hash) return false;
  const raw = ecdsaSignatureDerToRaw(cert.signature, CURVE_BYTES[issuer.curve]);
  if (!raw) return false;
  try {
    const key = await crypto.subtle.importKey("spki", issuer.spki.slice().buffer, { name: "ECDSA", namedCurve: issuer.curve }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash }, key, raw.slice().buffer, cert.tbs.slice().buffer);
  } catch {
    return false;
  }
}

export type ChainFailure =
  | "chain_parse"
  | "chain_names"
  | "chain_validity"
  | "chain_not_a_ca"
  | "chain_leaf_is_ca"
  | "chain_leaf_key"
  | "chain_signature";

export interface ChainInput {
  leafDer: Uint8Array;
  intermediateDer: Uint8Array;
  /** The pinned trust anchor (a DER certificate). */
  anchorDer: Uint8Array;
  nowMs: number;
  /** Clock-skew tolerance applied to both ends of every validity window. */
  skewMs: number;
}

export type ChainResult = { ok: true; leaf: ParsedCert } | { ok: false; reason: ChainFailure };

/** Verifies `leaf <- intermediate <- anchor`. Returns the parsed leaf on success. */
export async function verifyChain(input: ChainInput): Promise<ChainResult> {
  let leaf: ParsedCert;
  let inter: ParsedCert;
  let anchor: ParsedCert;
  try {
    leaf = parseCertificate(input.leafDer);
    inter = parseCertificate(input.intermediateDer);
    anchor = parseCertificate(input.anchorDer);
  } catch {
    return { ok: false, reason: "chain_parse" };
  }
  if (!bytesEq(leaf.issuer, inter.subject) || !bytesEq(inter.issuer, anchor.subject)) return { ok: false, reason: "chain_names" };
  for (const c of [leaf, inter, anchor]) {
    if (input.nowMs + input.skewMs < c.notBeforeMs || input.nowMs - input.skewMs > c.notAfterMs) return { ok: false, reason: "chain_validity" };
  }
  if (!inter.basicConstraints || !inter.basicConstraints.ca) return { ok: false, reason: "chain_not_a_ca" };
  if (!anchor.basicConstraints || !anchor.basicConstraints.ca) return { ok: false, reason: "chain_not_a_ca" };
  if (leaf.basicConstraints?.ca) return { ok: false, reason: "chain_leaf_is_ca" };
  if (leaf.curve !== "P-256") return { ok: false, reason: "chain_leaf_key" };
  if (!(await certSignedBy(leaf, inter))) return { ok: false, reason: "chain_signature" };
  if (!(await certSignedBy(inter, anchor))) return { ok: false, reason: "chain_signature" };
  return { ok: true, leaf };
}

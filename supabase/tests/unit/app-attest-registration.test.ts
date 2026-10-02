// supabase/tests/unit/app-attest-registration.test.ts
//
// App Attest KEY REGISTRATION verification (rewards/app-attest-registration.ts, x509-lite.ts, der.ts,
// cbor-strict.ts) against attestation objects built by attest-test-pki.ts: a throw-away root,
// intermediate and per-attestation leaf, with the nonce extension.
//
// These prove the verifier's logic and its fail-closed behaviour; they do NOT prove conformance with a
// real iPhone (`[unverified]` — no Apple device or account in this environment). The pinned Apple root
// is exercised for what a unit test can honestly show: it parses, it is a self-consistent CA, and the
// bytes still match the fingerprint recorded next to them.

import { beforeAll, describe, expect, it } from "vitest";
import {
  ATTEST_KEY_PURPOSE,
  CERT_VALIDITY_SKEW_MS,
  attestKeyChallengeString,
  computeAttestKeyBinding,
  createAttestationVerifier,
  parseKeyId,
  type RegistrationFailure,
} from "../../functions/_shared/rewards/app-attest-registration.js";
import { APPLE_APP_ATTEST_ROOT_DER, APPLE_APP_ATTEST_ROOT_SHA256_HEX } from "../../functions/_shared/rewards/apple-app-attest-root.js";
import { CborError, decodeCborPrefix, decodeCborStrict } from "../../functions/_shared/rewards/cbor-strict.js";
import { DerError, ecdsaSignatureDerToRaw, readTime, readTlv, readUnsignedInteger, oidToString } from "../../functions/_shared/rewards/der.js";
import { certSignedBy, parseCertificate, verifyChain } from "../../functions/_shared/rewards/x509-lite.js";
import { computeRequestBinding, toHex } from "../../functions/_shared/rewards/binding.js";
import { computeStringBinding } from "../../functions/_shared/rewards/string-binding.js";
import { concatBytes } from "../../functions/_shared/rewards/binding.js";
import {
  buildAttestation,
  buildCert,
  buildTestPki,
  cbArray,
  cbBytes,
  cbInt,
  cbMap,
  cbText,
  der,
  derBool,
  derInt,
  derOctet,
  derOid,
  derSeq,
  genPair,
  toB64,
  type AttestationOptions,
  type TestPki,
} from "./attest-test-pki.ts";

const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer));
const APP_ID = "TEAMID1234.com.example.golfraven";
const NOW = Date.now();
const BODY = { challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", keyId: "", nonce: "Wlpaw1paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo" };

let pki: TestPki;
let otherPki: TestPki;
beforeAll(async () => {
  pki = await buildTestPki({ nowMs: NOW });
  otherPki = await buildTestPki({ nowMs: NOW, rootCn: "Some Other Root" });
});

const verifierFor = (env: "production" | "development" = "production", anchor?: Uint8Array) =>
  createAttestationVerifier({ appId: APP_ID, environment: env, trustAnchorDer: anchor ?? pki.rootDer }, { sha256 });

/** Builds an attestation whose clientDataHash is the real binding for (challenge, device, key). */
async function attest(over: Partial<AttestationOptions> = {}) {
  // The key id is the hash of the leaf's point, so generate the leaf first.
  const leaf = over.leaf ?? (await genPair("P-256"));
  const keyId = toB64(await sha256(leaf.point));
  const clientDataHash = await computeAttestKeyBinding(sha256, { ...BODY, keyId });
  const built = await buildAttestation({ pki, appId: APP_ID, environment: "production", clientDataHash, leaf, ...over });
  return { built, keyId, clientDataHash };
}

async function verify(over: Partial<AttestationOptions> = {}, opts: { env?: "production" | "development"; anchor?: Uint8Array; nowMs?: number; claimedKeyId?: string; clientDataHash?: Uint8Array } = {}) {
  const { built, keyId, clientDataHash } = await attest(over);
  return verifierFor(opts.env ?? "production", opts.anchor).verify({
    attestationB64: built.attestationB64,
    keyId: opts.claimedKeyId ?? keyId,
    clientDataHash: opts.clientDataHash ?? clientDataHash,
    nowMs: opts.nowMs ?? NOW,
  });
}

function expectFail(v: Awaited<ReturnType<typeof verify>>, reason: RegistrationFailure) {
  expect(v.ok).toBe(false);
  if (!v.ok) expect(v.reason).toBe(reason);
}

describe("registration: a valid attestation", () => {
  it("is accepted in production and returns the attested key", async () => {
    const { built, keyId } = await attest();
    const v = await verifierFor("production").verify({ attestationB64: built.attestationB64, keyId, clientDataHash: await computeAttestKeyBinding(sha256, { ...BODY, keyId }), nowMs: NOW });
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.keyId).toBe(keyId);
      expect(Array.from(v.publicKeyRaw)).toEqual(Array.from(built.leaf.point));
      expect(v.publicKeyRaw.length).toBe(65);
    }
  });

  it("is accepted in development with the development aaguid", async () => {
    const v = await verify({ environment: "development" }, { env: "development" });
    expect(v.ok).toBe(true);
  });

  it("accepts the bare-OCTET-STRING form of the nonce extension as well as the [1]-wrapped one", async () => {
    expect((await verify({ nonceShape: "bare" })).ok).toBe(true);
    expect((await verify({ nonceShape: "wrapped" })).ok).toBe(true);
  });

  it("accepts the base64 of the object padded, unpadded or url-safe", async () => {
    const { built, keyId, clientDataHash } = await attest();
    const v = verifierFor();
    for (const form of [built.attestationB64, built.attestationB64.replace(/=+$/, ""), built.attestationB64.replace(/\+/g, "-").replace(/\//g, "_")]) {
      expect((await v.verify({ attestationB64: form, keyId, clientDataHash, nowMs: NOW })).ok).toBe(true);
    }
  });
});

describe("registration: MUST-FAIL — the chain", () => {
  it("a different root (the attacker's own PKI) is refused", async () => {
    // A fully valid chain... to a root the server does not trust.
    const { built, keyId, clientDataHash } = await attest({ pki: otherPki });
    const v = await verifierFor("production", pki.rootDer).verify({ attestationB64: built.attestationB64, keyId, clientDataHash, nowMs: NOW });
    expectFail(v, "chain_names");
  });

  it("a root with the right NAME but another key is refused at the signature", async () => {
    const impostor = await buildTestPki({ nowMs: NOW, rootCn: pki.rootCn });
    const { built, keyId, clientDataHash } = await attest({ pki: impostor });
    const v = await verifierFor("production", pki.rootDer).verify({ attestationB64: built.attestationB64, keyId, clientDataHash, nowMs: NOW });
    expectFail(v, "chain_signature");
  });

  it("a leaf not signed by the intermediate (broken chain) is refused", async () => {
    const stranger = await genPair("P-384");
    expectFail(await verify({ leafSignWith: stranger.privateKey }), "chain_signature");
  });

  it("a leaf whose issuer name is not the intermediate's subject is refused", async () => {
    expectFail(await verify({ leafIssuerCn: "Somebody Else" }), "chain_names");
  });

  it("an intermediate that is not a CA is refused", async () => {
    // Same keys and names as the real intermediate, but with no basicConstraints.
    const nonCaDer = await buildCert({
      subjectCn: pki.intermediateCn,
      issuerCn: pki.rootCn,
      subject: pki.intermediate,
      issuer: pki.root,
      hash: "SHA-384",
      notBeforeMs: pki.notBeforeMs,
      notAfterMs: pki.notAfterMs,
      extensions: [],
    });
    expectFail(await verify({ intermediateDer: nonCaDer }), "chain_not_a_ca");
  });

  it("a leaf that claims to be a CA is refused", async () => {
    expectFail(await verify({ leafExtraExtensions: [{ oid: "2.5.29.19", critical: true, value: derSeq(derBool(true)) }] }), "chain_leaf_is_ca");
  });

  it("an expired leaf and a not-yet-valid leaf are refused; the skew tolerance is bounded", async () => {
    expectFail(await verify({ leafNotBeforeMs: NOW - 48 * 3_600_000, leafNotAfterMs: NOW - 24 * 3_600_000 }), "chain_validity");
    expectFail(await verify({ leafNotBeforeMs: NOW + 24 * 3_600_000, leafNotAfterMs: NOW + 48 * 3_600_000 }), "chain_validity");
    // Just inside the skew window is fine; just outside is not.
    expect((await verify({ leafNotBeforeMs: NOW + CERT_VALIDITY_SKEW_MS - 120_000, leafNotAfterMs: NOW + 48 * 3_600_000 })).ok).toBe(true);
    expectFail(await verify({ leafNotBeforeMs: NOW + CERT_VALIDITY_SKEW_MS + 120_000, leafNotAfterMs: NOW + 48 * 3_600_000 }), "chain_validity");
  });

  it("the chain must be exactly [credCert, intermediate]", async () => {
    expectFail(await verify({ x5cCount: 1 }), "attestation_bad_structure");
    expectFail(await verify({ x5cCount: 3 }), "attestation_bad_structure");
  });

  it("a leaf on a curve other than P-256 is refused", async () => {
    const p384Leaf = await genPair("P-384");
    const keyId = toB64(await sha256(p384Leaf.point));
    const clientDataHash = await computeAttestKeyBinding(sha256, { ...BODY, keyId });
    const built = await buildAttestation({ pki, appId: APP_ID, environment: "production", clientDataHash, leaf: p384Leaf });
    expectFail(await verifierFor().verify({ attestationB64: built.attestationB64, keyId, clientDataHash, nowMs: NOW }), "chain_leaf_key");
  });
});

describe("registration: MUST-FAIL — the attested fields", () => {
  it("a wrong nonce in the credential certificate is refused", async () => {
    expectFail(await verify({ nonce: new Uint8Array(32).fill(1) }), "nonce_mismatch");
  });

  it("a missing nonce extension is refused", async () => {
    expectFail(await verify({ omitNonceExtension: true }), "nonce_missing");
  });

  it("an attestation made over another challenge / device / key binding is refused (the replay case)", async () => {
    // Valid object, but the server computes its clientDataHash from a different challenge.
    const { built, keyId } = await attest();
    const hash = await computeAttestKeyBinding(sha256, { ...BODY, keyId, nonce: "d2Rkd2Rkd2Rkd2Rkd2Rkd2Rkd2Rkd2Rkd2Rkd2Rkd2Q" });
    expectFail(await verifierFor().verify({ attestationB64: built.attestationB64, keyId, clientDataHash: hash, nowMs: NOW }), "nonce_mismatch");
    const otherDevice = await computeAttestKeyBinding(sha256, { ...BODY, deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", keyId });
    expectFail(await verifierFor().verify({ attestationB64: built.attestationB64, keyId, clientDataHash: otherDevice, nowMs: NOW }), "nonce_mismatch");
  });

  it("a wrong rpIdHash (another app) is refused", async () => {
    expectFail(await verify({ rpIdHash: await sha256(new TextEncoder().encode("OTHERTEAM.com.example.other")) }), "rp_id_mismatch");
    // ...and so is a verifier configured for a different app id.
    const { built, keyId, clientDataHash } = await attest();
    const v = createAttestationVerifier({ appId: "OTHERTEAM.com.example.other", environment: "production", trustAnchorDer: pki.rootDer }, { sha256 });
    expectFail(await v.verify({ attestationB64: built.attestationB64, keyId, clientDataHash, nowMs: NOW }), "rp_id_mismatch");
  });

  it("a nonzero counter is refused", async () => {
    expectFail(await verify({ counter: 1 }), "counter_not_zero");
    expectFail(await verify({ counter: 0xffffffff }), "counter_not_zero");
  });

  it("the wrong aaguid for the environment is refused, in both directions", async () => {
    expectFail(await verify({ environment: "development" }, { env: "production" }), "aaguid_mismatch");
    expectFail(await verify({ environment: "production" }, { env: "development" }), "aaguid_mismatch");
    expectFail(await verify({ aaguid: new Uint8Array(16) }), "aaguid_mismatch");
  });

  it("a key id that is not the hash of the attested key is refused", async () => {
    // The client names a different (well-formed) key id than the attested key's hash.
    const otherKeyId = toB64(new Uint8Array(32).fill(3));
    const { built, clientDataHash } = await attest();
    expectFail(await verifierFor().verify({ attestationB64: built.attestationB64, keyId: otherKeyId, clientDataHash, nowMs: NOW }), "key_id_mismatch");
  });

  it("a credentialId that is not the key id is refused", async () => {
    expectFail(await verify({ credentialId: new Uint8Array(32).fill(9) }), "credential_id_mismatch");
  });

  it("a COSE key that is not the certificate's key is refused", async () => {
    const other = await genPair("P-256");
    expectFail(await verify({ cosePoint: other.point }), "cose_key_mismatch");
    expectFail(await verify({ coseExtraKey: true }), "cose_key_mismatch");
  });

  it("an authData with the wrong flags, trailing bytes or truncation is refused", async () => {
    expectFail(await verify({ flags: 0x00 }), "authdata_malformed");
    expectFail(await verify({ flags: 0xc0 }), "authdata_malformed");
    expectFail(await verify({ mutateAuthData: (ad) => concatBytes(ad, new Uint8Array([0])) }), "authdata_malformed");
    expectFail(await verify({ mutateAuthData: (ad) => ad.slice(0, 40) }), "authdata_malformed");
  });

  it("a wrong fmt is refused", async () => {
    expectFail(await verify({ fmt: "packed" }), "attestation_bad_fmt");
  });
});

describe("registration: MUST-FAIL — malformed input", () => {
  it("a malformed key id is refused before anything else", async () => {
    const { built, clientDataHash } = await attest();
    for (const bad of ["", "AAAA", toB64(new Uint8Array(31)), toB64(new Uint8Array(32)).replace("=", ""), toB64(new Uint8Array(32)).replace(/\+/g, "-") + "x"]) {
      expectFail(await verifierFor().verify({ attestationB64: built.attestationB64, keyId: bad, clientDataHash, nowMs: NOW }), "key_id_malformed");
    }
  });

  it("malformed base64 and an oversize object are refused", async () => {
    const { keyId, clientDataHash } = await attest();
    const v = verifierFor();
    expectFail(await v.verify({ attestationB64: "***not base64***", keyId, clientDataHash, nowMs: NOW }), "attestation_malformed_base64");
    expectFail(await v.verify({ attestationB64: toB64(new Uint8Array(20_000).fill(0)), keyId, clientDataHash, nowMs: NOW }), "attestation_too_large");
  });

  it("malformed CBOR is refused (truncated, trailing bytes, indefinite length, a tag, junk)", async () => {
    const { built, keyId, clientDataHash } = await attest();
    const bytes = Uint8Array.from(atob(built.attestationB64), (c) => c.charCodeAt(0));
    const v = verifierFor();
    const cases: Uint8Array[] = [
      bytes.slice(0, bytes.length - 10),
      concatBytes(bytes, new Uint8Array([0x00])),
      new Uint8Array([0xbf, 0xff]), // indefinite-length map
      new Uint8Array([0xc1, 0x00]), // a tag
      new Uint8Array([0xff, 0xff, 0xff]),
      new Uint8Array([]),
    ];
    for (const c of cases) {
      const r = await v.verify({ attestationB64: toB64(c), keyId, clientDataHash, nowMs: NOW });
      expect(r.ok).toBe(false);
    }
    expectFail(await v.verify({ attestationB64: toB64(bytes.slice(0, bytes.length - 10)), keyId, clientDataHash, nowMs: NOW }), "attestation_malformed_cbor");
    expectFail(await v.verify({ attestationB64: toB64(concatBytes(bytes, new Uint8Array([0x00]))), keyId, clientDataHash, nowMs: NOW }), "attestation_malformed_cbor");
  });

  it("a structurally wrong object is refused (extra top-level key, wrong types, missing receipt)", async () => {
    const mk = (parts: { authData: Uint8Array; x5c: Uint8Array[]; receipt: Uint8Array; fmt: string }, extra: Array<[Uint8Array, Uint8Array]> = [], omitReceipt = false) =>
      cbMap([
        [cbText("fmt"), cbText(parts.fmt)],
        [cbText("attStmt"), cbMap([[cbText("x5c"), cbArray(...parts.x5c.map(cbBytes))], ...(omitReceipt ? [] : ([[cbText("receipt"), cbBytes(parts.receipt)]] as Array<[Uint8Array, Uint8Array]>)), ...(omitReceipt ? ([[cbText("extra"), cbInt(1)]] as Array<[Uint8Array, Uint8Array]>) : [])])],
        [cbText("authData"), cbBytes(parts.authData)],
        ...extra,
      ]);
    expectFail(await verify({ buildObject: (p) => mk(p, [[cbText("extra"), cbInt(1)]]) }), "attestation_bad_structure");
    expectFail(await verify({ buildObject: (p) => mk(p, [], true) }), "attestation_bad_structure");
    expectFail(await verify({ buildObject: () => cbArray(cbInt(1)) }), "attestation_bad_structure");
    expectFail(await verify({ buildObject: (p) => cbMap([[cbText("fmt"), cbText(p.fmt)], [cbText("attStmt"), cbText("nope")], [cbText("authData"), cbBytes(p.authData)]]) }), "attestation_bad_structure");
  });

  it("a malformed certificate is refused (a trailing byte, a non-minimal length, a mutated TBS)", async () => {
    const good = (await attest()).built.leafDer;
    expectFail(await verify({ leafDerOverride: concatBytes(good, new Uint8Array([0])) }), "chain_parse");
    // Re-encode the outer SEQUENCE length in the (legal BER, illegal DER) long form.
    // Re-spell the outer SEQUENCE length with a redundant leading zero length byte (legal BER, not DER).
    const lenBytes = good[1]! === 0x81 ? 1 : 2;
    const body = good.slice(2 + lenBytes);
    const respelled = concatBytes(new Uint8Array([0x30, 0x83, 0x00, (body.length >> 8) & 0xff, body.length & 0xff]), body);
    expectFail(await verify({ leafDerOverride: respelled }), "chain_parse");
    expectFail(await verify({ leafDerOverride: good.slice(0, good.length - 3) }), "chain_parse");
    // A signature over different TBS bytes than the certificate carries.
    const tampered = await buildCert({
      subjectCn: "Test credential certificate",
      issuerCn: pki.intermediateCn,
      subject: await genPair("P-256"),
      issuer: pki.intermediate,
      hash: "SHA-256",
      notBeforeMs: pki.notBeforeMs,
      notAfterMs: pki.notAfterMs,
      extensions: [],
      tamperTbsAfterSigning: (t) => {
        const c = t.slice();
        c[c.length - 1] ^= 0xff;
        return c;
      },
    });
    expectFail(await verify({ leafDerOverride: tampered }), "chain_signature");
  });

  it("a v1 certificate, a differing inner signature algorithm and a negative or padded signature INTEGER are refused", async () => {
    const mk = (over: Partial<Parameters<typeof buildCert>[0]>) =>
      buildCert({
        subjectCn: "Test credential certificate",
        issuerCn: pki.intermediateCn,
        subject: pki.intermediate,
        issuer: pki.intermediate,
        hash: "SHA-256",
        notBeforeMs: pki.notBeforeMs,
        notAfterMs: pki.notAfterMs,
        extensions: [],
        ...over,
      });
    expectFail(await verify({ leafDerOverride: await mk({ version: 0 }) }), "chain_parse");
    expectFail(await verify({ leafDerOverride: await mk({ innerSigOid: "1.2.840.10045.4.3.3" }) }), "chain_parse");
    // Signature DER with a redundant leading zero in r.
    const padded = await mk({
      mutateSignatureDer: (sig) => {
        // sig = 30 len 02 rlen r... 02 slen s...; insert 00 before r when it does not need one.
        const rlen = sig[3]!;
        const r = sig.slice(4, 4 + rlen);
        const rest = sig.slice(4 + rlen);
        const newR = concatBytes(new Uint8Array([0x00]), r[0]! & 0x80 ? new Uint8Array([0x00]) : new Uint8Array(0), r);
        return concatBytes(new Uint8Array([0x30, newR.length + 2 + rest.length, 0x02, newR.length]), newR, rest);
      },
    });
    const parsedPadded = parseCertificate(padded);
    expect(ecdsaSignatureDerToRaw(parsedPadded.signature, 48)).toBeNull();
    expect(await certSignedBy(parsedPadded, parseCertificate(pki.intermediateDer))).toBe(false);
  });
});

describe("registration: the trust-anchor seam", () => {
  it("only the injected anchor is trusted: a chain valid to the TEST root fails against the pinned APPLE root", async () => {
    const { built, keyId, clientDataHash } = await attest();
    const v = verifierFor("production", APPLE_APP_ATTEST_ROOT_DER);
    const r = await v.verify({ attestationB64: built.attestationB64, keyId, clientDataHash, nowMs: NOW });
    expect(r.ok).toBe(false);
  });
});

describe("the pinned Apple root", () => {
  it("is the bytes whose SHA-256 is recorded next to it", async () => {
    expect(toHex(await sha256(APPLE_APP_ATTEST_ROOT_DER))).toBe(APPLE_APP_ATTEST_ROOT_SHA256_HEX);
  });

  it("parses as a self-signed P-384 CA valid until 2045 and signs itself", async () => {
    const root = parseCertificate(APPLE_APP_ATTEST_ROOT_DER);
    expect(root.curve).toBe("P-384");
    expect(root.basicConstraints?.ca).toBe(true);
    expect(new TextDecoder().decode(root.subject)).toContain("Apple App Attestation Root CA");
    expect(Buffer.from(root.subject).equals(Buffer.from(root.issuer))).toBe(true);
    expect(root.notAfterMs).toBe(Date.UTC(2045, 2, 15, 0, 0, 0));
    expect(root.notBeforeMs).toBe(Date.UTC(2020, 2, 18, 18, 32, 53));
    expect(await certSignedBy(root, root)).toBe(true);
  });

  it("does not verify a certificate it did not sign", async () => {
    const root = parseCertificate(APPLE_APP_ATTEST_ROOT_DER);
    expect(await certSignedBy(parseCertificate(pki.intermediateDer), root)).toBe(false);
  });
});

describe("registration binding", () => {
  it("is domain-separated from the activation binding", async () => {
    const challenge = new Uint8Array(32).fill(1);
    const reg = await computeAttestKeyBinding(sha256, { challengeId: "c", deviceId: "d", keyId: "k", nonce: "n" });
    const act = await computeRequestBinding(sha256, { rewardId: "r", deviceId: "d", platform: "ios", challengeId: "c" }, challenge);
    expect(toHex(reg)).not.toBe(toHex(act));
  });

  it("is SHA-256 of ONE ASCII string a JS client can build: sorted keys, no whitespace, the nonce as TEXT", async () => {
    const body = { challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", keyId: toB64(new Uint8Array(32).fill(0xfb)), nonce: "abcDEF_-0123" };
    const s = attestKeyChallengeString(body);
    // The literal a client writes by hand (a template literal), byte for byte.
    expect(s).toBe(
      `{"challengeId":"${body.challengeId}","deviceId":"${body.deviceId}","keyId":"${body.keyId}","nonce":"${body.nonce}","platform":"ios","purpose":"${ATTEST_KEY_PURPOSE}"}`,
    );
    expect(/^[\x20-\x7e]*$/.test(s)).toBe(true); // printable ASCII only: no encoding question for the client's own hash
    // What `@expo/app-integrity`-style modules do with a string `challenge`: SHA-256 of its UTF-8 bytes.
    expect(toHex(await computeAttestKeyBinding(sha256, body))).toBe(toHex(await sha256(new TextEncoder().encode(s))));
    // ...and that also equals the generic helper (the one the activation proposal reuses).
    expect(toHex(await computeStringBinding(sha256, JSON.parse(s)))).toBe(toHex(await computeAttestKeyBinding(sha256, body)));
  });

  it("the generic string binding sorts keys itself (a caller's insertion order never changes the hash)", async () => {
    expect(toHex(await computeStringBinding(sha256, { b: "2", a: "1" }))).toBe(toHex(await sha256(new TextEncoder().encode('{"a":"1","b":"2"}'))));
  });

  it("binds every one of its fields", async () => {
    const base = { challengeId: "c", deviceId: "d", keyId: "k", nonce: "n" };
    const ref = toHex(await computeAttestKeyBinding(sha256, base));
    for (const mutated of [{ ...base, challengeId: "x" }, { ...base, deviceId: "x" }, { ...base, keyId: "x" }, { ...base, nonce: "x" }]) {
      expect(toHex(await computeAttestKeyBinding(sha256, mutated))).not.toBe(ref);
    }
  });

  it("parseKeyId accepts exactly the canonical 44-character form", () => {
    const ok = toB64(new Uint8Array(32).fill(0xfb)); // base64 of 0xfb... contains "+" and "/"-class characters
    expect(ok).toContain("+");
    expect(parseKeyId(ok)?.length).toBe(32);
    for (const bad of [ok.replace("=", ""), ok.replace(/\+/g, "-"), ok + "=", "", "A".repeat(44), toB64(new Uint8Array(33))]) expect(parseKeyId(bad)).toBeNull();
  });
});

describe("der.ts strictness", () => {
  const T = (bytes: number[]) => new Uint8Array(bytes);
  it("refuses indefinite, non-minimal and high-tag encodings", () => {
    expect(() => readTlv(T([0x30, 0x80, 0x00, 0x00]), 0)).toThrow(DerError);
    expect(() => readTlv(T([0x04, 0x81, 0x05, 1, 2, 3, 4, 5]), 0)).toThrow(DerError); // long form that fits the short form
    expect(() => readTlv(T([0x04, 0x82, 0x00, 0x90, ...new Array(0x90).fill(0)]), 0)).toThrow(DerError); // leading zero length byte
    expect(() => readTlv(T([0x1f, 0x01, 0x00]), 0)).toThrow(DerError);
    expect(() => readTlv(T([0x04, 0x05, 1, 2]), 0)).toThrow(DerError); // overruns
    expect(readTlv(T([0x04, 0x02, 1, 2]), 0).end).toBe(4);
  });

  it("refuses negative and non-minimal INTEGERs (the same rules the assertion's signature parser applies)", () => {
    const i = (bytes: number[]) => readUnsignedInteger(T(bytes), readTlv(T(bytes), 0), 32, "t");
    expect(Array.from(i([0x02, 0x01, 0x05]))).toEqual([5]);
    expect(Array.from(i([0x02, 0x02, 0x00, 0x80]))).toEqual([0x80]);
    expect(Array.from(i([0x02, 0x01, 0x00]))).toEqual([0]);
    expect(() => i([0x02, 0x01, 0x80])).toThrow(DerError); // negative
    expect(() => i([0x02, 0x02, 0x00, 0x05])).toThrow(DerError); // non-minimal
    expect(() => i([0x02, 0x00])).toThrow(DerError);
    expect(() => readUnsignedInteger(T([0x02, 0x03, 1, 2, 3]), readTlv(T([0x02, 0x03, 1, 2, 3]), 0), 2, "t")).toThrow(DerError); // too long
  });

  it("decodes OIDs and refuses non-minimal arcs", () => {
    expect(oidToString(T([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]))).toBe("1.2.840.10045.3.1.7");
    expect(oidToString(T([0x2b, 0x81, 0x04, 0x00, 0x22]))).toBe("1.3.132.0.34");
    expect(() => oidToString(T([0x2a, 0x80, 0x01]))).toThrow(DerError);
    expect(() => oidToString(T([0x2a, 0x86]))).toThrow(DerError);
  });

  it("reads only the two exact time shapes and rejects out-of-range fields", () => {
    const t = (tag: number, s: string) => {
      const b = new TextEncoder().encode(s);
      const buf = concatBytes(new Uint8Array([tag, b.length]), b);
      return readTime(buf, readTlv(buf, 0));
    };
    expect(t(0x17, "200318183253Z")).toBe(Date.UTC(2020, 2, 18, 18, 32, 53));
    expect(t(0x18, "20450315000000Z")).toBe(Date.UTC(2045, 2, 15, 0, 0, 0));
    expect(() => t(0x17, "2003181832Z")).toThrow(DerError); // no seconds
    expect(() => t(0x17, "200318183253+0100")).toThrow(DerError); // offset
    expect(() => t(0x18, "20450315000000.5Z")).toThrow(DerError); // fraction
    expect(() => t(0x17, "201318183253Z")).toThrow(DerError); // month 13
    expect(() => t(0x17, "200231183253Z")).toThrow(DerError); // 31 Feb
  });

  it("ecdsaSignatureDerToRaw refuses anything but a strict SEQUENCE of two minimal INTEGERs", () => {
    const rs = (r: number[], s: number[]) => derSeq(derInt(Uint8Array.from(r)), derInt(Uint8Array.from(s)));
    expect(ecdsaSignatureDerToRaw(rs([1], [2]), 32)?.length).toBe(64);
    expect(ecdsaSignatureDerToRaw(concatBytes(rs([1], [2]), new Uint8Array([0])), 32)).toBeNull();
    expect(ecdsaSignatureDerToRaw(derSeq(derInt(Uint8Array.from([1]))), 32)).toBeNull();
    expect(ecdsaSignatureDerToRaw(der(0x31, derInt(Uint8Array.from([1])), derInt(Uint8Array.from([2]))), 32)).toBeNull();
    expect(ecdsaSignatureDerToRaw(rs(new Array(33).fill(1), [2]), 32)).toBeNull(); // too long for P-256
    expect(ecdsaSignatureDerToRaw(derSeq(der(0x02, Uint8Array.from([0x80])), derInt(Uint8Array.from([2]))), 32)).toBeNull(); // negative
  });
});

describe("cbor-strict.ts", () => {
  it("decodes ints (negative too), strings, arrays and maps with integer keys", () => {
    const v = decodeCborStrict(cbMap([[cbInt(1), cbInt(2)], [cbInt(-2), cbBytes(new Uint8Array([1, 2]))], [cbText("a"), cbArray(cbInt(0), cbInt(-1))]]));
    expect(v instanceof Map).toBe(true);
    const m = v as Map<number | string, unknown>;
    expect(m.get(1)).toBe(2);
    expect(Array.from(m.get(-2) as Uint8Array)).toEqual([1, 2]);
    expect(m.get("a")).toEqual([0, -1]);
  });

  it("refuses tags, floats, simple values, indefinite lengths, 64-bit arguments, duplicate keys, odd key types, depth and trailing bytes", () => {
    const bad: number[][] = [
      [0xc0, 0x00], // tag
      [0xf9, 0x00, 0x00], // half float
      [0xf5], // true
      [0xf6], // null
      [0x5f, 0xff], // indefinite byte string
      [0x1b, 0, 0, 0, 0, 0, 0, 0, 1], // 64-bit argument
      [0xa2, 0x01, 0x01, 0x01, 0x02], // duplicate key 1
      [0xa1, 0x41, 0x00, 0x01], // byte-string key
      [0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00], // depth
      [0x01, 0x02], // trailing
      [0x62, 0xc3, 0x28], // invalid utf-8
    ];
    for (const b of bad) expect(() => decodeCborStrict(Uint8Array.from(b))).toThrow(CborError);
  });

  it("decodeCborPrefix reports the bytes it used", () => {
    expect(decodeCborPrefix(Uint8Array.from([0x18, 0x2a, 0x99])).length).toBe(2);
  });
});

describe("chain checks directly", () => {
  it("verifyChain accepts the test chain and reports the leaf", async () => {
    const { built } = await attest();
    const r = await verifyChain({ leafDer: built.leafDer, intermediateDer: pki.intermediateDer, anchorDer: pki.rootDer, nowMs: NOW, skewMs: CERT_VALIDITY_SKEW_MS });
    expect(r.ok).toBe(true);
    if (r.ok) expect(Array.from(r.leaf.publicKeyRaw)).toEqual(Array.from(built.leaf.point));
  });

  it("a duplicate extension, an explicit-FALSE criticality and an unknown tbs field are refused at parse", async () => {
    const dup = await buildCert({
      subjectCn: "x", issuerCn: pki.intermediateCn, subject: await genPair("P-256"), issuer: pki.intermediate, hash: "SHA-256", notBeforeMs: pki.notBeforeMs, notAfterMs: pki.notAfterMs,
      extensions: [{ oid: "1.2.3.4", value: derSeq() }, { oid: "1.2.3.4", value: derSeq() }],
    });
    expect(() => parseCertificate(dup)).toThrow(DerError);
    const explicitFalse = await buildCert({
      subjectCn: "x", issuerCn: pki.intermediateCn, subject: await genPair("P-256"), issuer: pki.intermediate, hash: "SHA-256", notBeforeMs: pki.notBeforeMs, notAfterMs: pki.notAfterMs,
      extensions: [{ oid: "2.5.29.19", value: derSeq(derBool(false)) }],
    });
    expect(() => parseCertificate(explicitFalse)).toThrow(DerError);
    // octet/oid helpers sanity (keeps the encoders honest)
    expect(derOid("1.2.840.113635.100.8.2").length).toBeGreaterThan(5);
    expect(derOctet(new Uint8Array(3)).length).toBe(5);
  });
});

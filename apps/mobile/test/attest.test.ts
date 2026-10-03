/**
 * P4.2b-1: the attestation SEAM. The byte layouts are compared with what the SERVER's own functions produced for fixed inputs
 * (`fixtures/edge-contract.json` `vectors.binding`, recorded from `_shared/rewards/binding.ts`, `string-binding.ts`, `app-attest-registration.ts`),
 * and with an independent implementation on `node:crypto`.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createHttpApiClient } from "../src/api";
import {
  UnattestableAttestor,
  androidBoundBodyBytes,
  androidRequestBinding,
  attestKeyBinding,
  attestKeyChallengeString,
  bytesToBase64Url,
  bytesToHex,
  canonicalJson,
  concatBytes,
  iosActivationBinding,
  iosActivationChallengeString,
  nonceBytesStrict,
  type Attestor,
} from "../src/attest";
import { createItem, type OutboxItem } from "../src/outbox";
import { VECTORS, scriptedFetch } from "./support/edge-fixtures";
import { T0, itemFor, wireOf } from "./support/evidence";

const sha = (b: Uint8Array | string): string => createHash("sha256").update(b).digest("hex");
const V = VECTORS.binding;

describe("Android requestHash = SHA-256(canonical_body || raw challenge bytes) (the server's binding.ts)", () => {
  const a = V.androidRequestBinding;
  const body = { rewardId: a.body.rewardId, deviceId: a.body.deviceId, challengeId: a.body.challengeId, installLinkId: a.body.installLinkId };

  it("the canonical body bytes equal the server's", () => {
    expect(new TextDecoder().decode(androidBoundBodyBytes(body))).toBe(a.canonicalBodyUtf8);
    expect(bytesToHex(androidBoundBodyBytes(body))).toBe(a.canonicalBodyHex);
  });

  it("the hash equals the server's, with and without installLinkId", () => {
    expect(bytesToHex(androidRequestBinding(body, a.challengeBase64Url))).toBe(a.hashHex);
    const { installLinkId: _drop, ...noLink } = body;
    expect(bytesToHex(androidRequestBinding(noLink, V.androidRequestBindingNoInstallLink.challengeBase64Url))).toBe(V.androidRequestBindingNoInstallLink.hashHex);
    expect(a.hashHex).not.toBe(V.androidRequestBindingNoInstallLink.hashHex);
  });

  it("the layout is exactly body-bytes THEN raw challenge bytes (independent check)", () => {
    const challenge = nonceBytesStrict(a.challengeBase64Url)!;
    expect(challenge).toHaveLength(32);
    expect(sha(concatBytes(androidBoundBodyBytes(body), challenge))).toBe(a.hashHex);
    expect(sha(concatBytes(challenge, androidBoundBodyBytes(body)))).not.toBe(a.hashHex); // order matters
    expect(sha(Buffer.from(a.canonicalBodyUtf8 + a.challengeBase64Url))).not.toBe(a.hashHex); // the nonce is bound as BYTES for Android
  });

  it("an absent optional field is ABSENT (never null); uppercase UUIDs are lowercased before binding; a different body or challenge changes the hash", () => {
    expect(a.canonicalBodyUtf8).not.toContain("null");
    const up = { ...body, rewardId: body.rewardId.toUpperCase(), deviceId: body.deviceId.toUpperCase(), challengeId: body.challengeId.toUpperCase() };
    expect(bytesToHex(androidRequestBinding(up, a.challengeBase64Url))).toBe(a.hashHex);
    expect(bytesToHex(androidRequestBinding({ ...body, installLinkId: "other-link-id-0000" }, a.challengeBase64Url))).not.toBe(a.hashHex);
    expect(bytesToHex(androidRequestBinding(body, bytesToBase64Url(new Uint8Array(32).fill(1))))).not.toBe(a.hashHex);
  });

  it("a non-canonical nonce spelling is refused, as on the server (several spellings of one challenge would be several bindings)", () => {
    expect(nonceBytesStrict("AA")).toEqual(new Uint8Array([0])); // the canonical spelling of byte 0 ...
    expect(nonceBytesStrict("AB")).toBeNull(); // ... AB and AP decode to the same byte but are not canonical
    expect(nonceBytesStrict("AP")).toBeNull();
    expect(nonceBytesStrict("AAAA=")).toBeNull(); // padded
    expect(nonceBytesStrict("a+b/")).toBeNull(); // standard alphabet
    expect(nonceBytesStrict("A")).toBeNull();
    expect(nonceBytesStrict("AAAA")).toEqual(new Uint8Array([0, 0, 0]));
    expect(() => androidRequestBinding(body, "AB")).toThrow(/canonical/);
  });
});

describe("iOS clientDataHash = SHA-256(UTF-8(S)), S a canonical string carrying the nonce as TEXT (string-binding.ts): NOT body||raw bytes", () => {
  it("activation: the string and the hash equal the server's", () => {
    const i = V.iosActivation;
    expect(iosActivationChallengeString(i.body)).toBe(i.challengeString);
    expect(bytesToHex(iosActivationBinding(i.body))).toBe(i.hashHex);
    expect(sha(i.challengeString)).toBe(i.hashHex);
    expect(i.challengeString).toContain(`"nonce":"${i.body.nonce}"`);
    expect(i.challengeString).toContain('"platform":"ios","purpose":"reward_activation"');
  });

  it("key registration (attestKey): the string and the hash equal the server's, with a different purpose from activation (domain separation)", () => {
    const r = V.iosAttestKey;
    expect(attestKeyChallengeString(r.body)).toBe(r.challengeString);
    expect(bytesToHex(attestKeyBinding(r.body))).toBe(r.hashHex);
    expect(r.challengeString).toContain('"purpose":"attest_key_registration"');
    expect(r.challengeString).toContain(`"keyId":"${r.body.keyId}"`);
    expect(r.hashHex).not.toBe(V.iosActivation.hashHex);
  });

  it("plan vs server, pinned: the plan's raw-bytes form (body || challenge) would be a DIFFERENT hash on iOS", () => {
    const i = V.iosActivation;
    expect(sha(concatBytes(new TextEncoder().encode(i.challengeString), nonceBytesStrict(i.body.nonce) ?? new Uint8Array()))).not.toBe(i.hashHex);
  });

  it("uppercase UUIDs (Swift's uuidString) are lowercased before they enter S", () => {
    const i = V.iosActivation.body;
    const up = { ...i, rewardId: i.rewardId.toUpperCase(), deviceId: i.deviceId.toUpperCase(), challengeId: i.challengeId.toUpperCase() };
    expect(iosActivationChallengeString(up)).toBe(V.iosActivation.challengeString);
    const r = V.iosAttestKey.body;
    expect(attestKeyChallengeString({ ...r, deviceId: r.deviceId.toUpperCase(), challengeId: r.challengeId.toUpperCase() })).toBe(V.iosAttestKey.challengeString);
  });
});

describe("canonical JSON", () => {
  it("equals the server's output (sorted keys, no whitespace); undefined and non-finite numbers are errors", () => {
    expect(canonicalJson(V.canonicalJsonSample.input)).toBe(V.canonicalJsonSample.output);
    expect(() => canonicalJson({ a: undefined })).toThrow(/undefined/);
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(/non-finite/);
    expect(() => canonicalJson({ a: () => 1 })).toThrow(/unsupported/);
  });
});

describe("UnattestableAttestor: the only attestor this build ships", () => {
  it("says 'unattestable / not_implemented' for every operation, never 'failed', never an invented token", async () => {
    const a: Attestor = new UnattestableAttestor();
    const hash = new Uint8Array(32);
    for (const r of [await a.generateKey(), await a.attestKey("k", hash), await a.assert("k", hash), await a.integrityToken(hash)]) {
      expect(r).toEqual({ kind: "unattestable", reason: "not_implemented" });
    }
  });

  it("reports that this build does not claim hardware attestation, so the server grades a token-less request `unattestable`, not `failed` (G3-08)", () => {
    expect(new UnattestableAttestor().capability).toEqual({ platform: "none", hardwareSupportsAttestation: false });
  });

  it("the evidence flow carries exactly that: redemption sends hardwareSupportsAttestation:false; an attestor that claims support sends true (the seam P4.2b-2 plugs into)", async () => {
    const held = (): OutboxItem => {
      const base = itemFor(wireOf("evidence_accepted_no_challenge"), 1);
      const p = JSON.parse(JSON.stringify(base.payload)) as { challenges: Record<string, unknown> };
      const k = Object.keys(p.challenges)[0]!;
      p.challenges[k] = { state: "held", challengeId: "chal_9", nonce: "bm9uY2U", kind: "prefetched", expiresAt: T0 + 10 * 3600_000 };
      return { ...createItem({ id: "ev1", sourceRef: "r", ownerUserId: "user-a", courseId: base.courseId, catalogVersion: base.catalogVersion, payload: p as never }, T0), status: "sent" };
    };
    for (const [attestor, expected] of [[undefined, false], [{ capability: { platform: "ios", hardwareSupportsAttestation: true } } as unknown as Attestor, true]] as const) {
      const f = scriptedFetch({ respond: "token_201_unattestable" }, { respond: "evidence_accepted_with_challenge" });
      const api = createHttpApiClient({ baseUrl: "https://p.supabase.co/functions/v1", fetch: f.fetch, getAccessToken: () => Promise.reject(new Error("no")), now: () => T0, ...(attestor ? { attestor } : {}) });
      await api.submitEvidence(held(), { userId: "user-a", accessToken: "tok" });
      expect((f.seen[0]!.body as { hardwareSupportsAttestation: boolean }).hardwareSupportsAttestation).toBe(expected);
    }
  });
});

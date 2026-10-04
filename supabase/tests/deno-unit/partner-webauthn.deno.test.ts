// supabase/tests/deno-unit/partner-webauthn.deno.test.ts
//
// docs/security/partner-auth-design.md, slice S0, acceptance PA-0a: the software authenticator (software-authenticator.ts) registers and signs in
// against the partner-lane WebAuthn wrapper (supabase/functions/_shared/partner/webauthn.ts); wrong origin, wrong RP ID, missing UV, an equal or lower
// non-zero counter and a wrong challenge are each refused; 0 against 0 passes; and the L7 rules hold: `crossOrigin: true`, a non-`none` attestation
// `fmt`, an algorithm outside [-7, -257] and a `response.id` that is not the looked-up credential are each refused.
//
// HOW EACH REFUSAL IS MADE NON-VACUOUS. Every refusal case differs from a passing case by exactly ONE mutation of the fixture, and the passing case
// is asserted in the same file (the register / sign-in tests), so "it was refused" cannot be an artefact of a broken fixture. Where the rule is one
// the LIBRARY does not enforce (the four L7 findings, design section 14), a CONTROL calls the library directly with the same bytes and asserts that it
// ACCEPTS them: that is what makes the wrapper's refusal evidence about the wrapper, and it will fail loudly if a library bump ever changes the behaviour
// the wrapper was written around (re-read the source then, as the design's quarterly bump discipline says).
//
// PURE: no database, no network, no files. CI runs it with `--deny-net --cached-only` (see the "Run supabase/tests/deno-unit" step in
// .github/workflows/ci.yml); the last test here asserts that this run was not granted network access.
//
// Run locally:
//   deno test --config supabase/functions/deno.json --lock=supabase/tests/deno.lock --frozen --deny-net supabase/tests/deno-unit/

import { assert, assertEquals, assertInstanceOf, assertMatch, assertNotEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { decodeAttestationObject, decodeCredentialPublicKey, isoBase64URL } from "@simplewebauthn/server/helpers";
import {
  assertRpConfig,
  authenticationOptions,
  PARTNER_ALGORITHM_IDS,
  registrationOptions,
  RpConfigError,
  type RpConfig,
  type StoredCredential,
  verifyAssertion,
  verifyRegistration,
  WebAuthnRefusal,
  type WebAuthnRefusalCode,
} from "../../functions/_shared/partner/webauthn.ts";
import { type AssertOptions, b64u, cbor, concat, FLAG_UP, FLAG_UV, SoftwareAuthenticator } from "./software-authenticator.ts";

const RP: RpConfig = { rpId: "partners.example.test", origin: "https://partners.example.test" };
const OTHER_RP_ID = "other.example.test";
const challenge = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));

/** Asserts the promise rejects with a WebAuthnRefusal of exactly `code`; when `cause` is given, the library's own message must match it too. */
async function refused(p: Promise<unknown>, code: WebAuthnRefusalCode, cause?: RegExp): Promise<WebAuthnRefusal> {
  const err = await assertRejects(() => p, WebAuthnRefusal);
  assertInstanceOf(err, WebAuthnRefusal);
  assertEquals(err.code, code);
  assertEquals(err.message, code, "the message is the closed code and nothing else (no library text on the wire)");
  if (cause !== undefined) assertMatch(String((err.cause as Error | undefined)?.message), cause);
  return err;
}

/** Registers `auth` through the wrapper and returns the stored shape `partner_credential_lookup` would give back. */
async function enrol(auth: SoftwareAuthenticator, counter = 0): Promise<StoredCredential> {
  const ch = challenge();
  const reg = await verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, counter }), expectedChallenge: ch });
  return { id: reg.credentialId, publicKey: reg.publicKey, signCount: reg.signCount };
}

// ===== registration =====================================================================================================================

for (const alg of ["ES256", "RS256"] as const) {
  Deno.test(`register: a ${alg} credential verifies and comes back in the shape the database stores`, async () => {
    const auth = await SoftwareAuthenticator.create(alg);
    const ch = challenge();
    const reg = await verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch }), expectedChallenge: ch });
    assertEquals(reg.credentialId, auth.id);
    assertEquals(reg.alg, alg === "ES256" ? -7 : -257);
    assertEquals(reg.signCount, 0);
    assertEquals(reg.userVerified, true);
    assertEquals(reg.backupEligible, false);
    assertEquals(reg.backupState, false);
    assertEquals(Array.from(reg.publicKey), Array.from(auth.cosePublicKey));
  });
}

Deno.test("register: backup-eligible and backed-up flags are reported (a synced passkey, R-P3) and nothing is enforced on them", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  const reg = await verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, flags: { be: true, bs: true } }), expectedChallenge: ch });
  assertEquals(reg.backupEligible, true);
  assertEquals(reg.backupState, true);
});

Deno.test("register: missing UV is refused (and the same call with UV passes)", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  await refused(verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, flags: { uv: false } }), expectedChallenge: ch }), "verification_failed", /User verification was required/);
});

Deno.test("register: missing UP is refused", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  await refused(verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, flags: { up: false } }), expectedChallenge: ch }), "verification_failed", /User presence was required/);
});

Deno.test("register: wrong origin is refused", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  await refused(
    verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: "https://evil.example.test", challenge: ch }), expectedChallenge: ch }),
    "verification_failed",
    /Unexpected registration response origin/,
  );
});

Deno.test("register: wrong RP ID (authenticator data hashes another RP ID) is refused", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  await refused(
    verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, rpIdHashOf: OTHER_RP_ID }), expectedChallenge: ch }),
    "verification_failed",
    /Unexpected RP ID hash/,
  );
});

Deno.test("register: wrong challenge is refused", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  await refused(
    verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: challenge() }), expectedChallenge: challenge() }),
    "verification_failed",
    /Unexpected registration response challenge/,
  );
});

Deno.test("register: a get-type clientDataJSON is refused", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  await refused(
    verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, client: { type: "webauthn.get" } }), expectedChallenge: ch }),
    "verification_failed",
    /Unexpected registration response type/,
  );
});

// ----- L7 (a): crossOrigin ---------------------------------------------------------------------------------------------------------------

Deno.test("L7a register: crossOrigin true is refused, and a CONTROL shows the library alone accepts it", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, client: { crossOrigin: true } });
  const control = await verifyRegistrationResponse({ response: response as never, expectedChallenge: b64u(ch), expectedOrigin: RP.origin, expectedRPID: RP.rpId, supportedAlgorithmIDs: [-7, -257] });
  assertEquals(control.verified, true, "CONTROL: SimpleWebAuthn 14.0.3 registration never looks at crossOrigin");
  await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "cross_origin");
});

Deno.test("L7a: every crossOrigin value other than absent or false is refused, and absent passes", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  for (const value of [true, "true", "false", 1, 0, null, {}]) {
    const ch = challenge();
    await refused(verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, client: { crossOrigin: value } }), expectedChallenge: ch }), "cross_origin");
  }
  const ch = challenge();
  const absent = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, client: { crossOrigin: undefined } });
  assertEquals((await verifyRegistration({ rp: RP, response: absent, expectedChallenge: ch })).credentialId, auth.id);
});

Deno.test("L7a: any topOrigin is refused, even with crossOrigin false", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  await refused(verifyRegistration({ rp: RP, response: await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, client: { topOrigin: "https://evil.example.test" } }), expectedChallenge: ch }), "top_origin");
});

Deno.test("L7a: a clientDataJSON that is not an object is refused as malformed", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  for (const junk of ["null", "[]", "42", '"x"', "not json"]) {
    const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
    response.response.clientDataJSON = b64u(new TextEncoder().encode(junk));
    await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "malformed");
  }
});

// ----- L7 (b): attestation format --------------------------------------------------------------------------------------------------------

Deno.test("L7b register: fmt packed is refused, and a CONTROL shows the library alone would VERIFY it (it parses the format the authenticator chose)", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, fmt: "packed" });
  const control = await verifyRegistrationResponse({ response: response as never, expectedChallenge: b64u(ch), expectedOrigin: RP.origin, expectedRPID: RP.rpId, supportedAlgorithmIDs: [-7, -257] });
  assertEquals(control.verified, true);
  assertEquals(control.registrationInfo?.fmt, "packed", "CONTROL: the library ran its packed-attestation verifier on authenticator-chosen bytes");
  await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "attestation_format");
});

Deno.test("L7b: every other format name is refused BEFORE the library (garbage statement; a library call would have failed with a different code)", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  for (const fmt of ["fido-u2f", "packed", "android-safetynet", "android-key", "tpm", "apple", "made-up", ""]) {
    const ch = challenge();
    // an x5c full of junk: if the library's X.509/ASN.1 parsers were reached, the failure would be `verification_failed`, not `attestation_format`
    const response = await auth.register({
      rpId: RP.rpId,
      origin: RP.origin,
      challenge: ch,
      fmt,
      attStmt: new Map<number | string, number | string | Uint8Array>([["x5c", cbor("junk")], ["sig", new Uint8Array(8)]]) as never,
    });
    await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "attestation_format");
  }
});

Deno.test("L7b: fmt none with a non-empty attestation statement is refused (by the library; the wrapper lets exactly none through)", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, attStmt: new Map([["sig", new Uint8Array(4)]]) as never });
  await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "verification_failed", /None attestation had unexpected attestation statement/);
});

Deno.test("L7b: an attestation object that is not CBOR is refused as malformed", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
  response.response.attestationObject = b64u(Uint8Array.of(0xff, 0xff, 0xff));
  await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "malformed");
});

// ----- L7 (d): algorithms ----------------------------------------------------------------------------------------------------------------

Deno.test("L7d register: an Ed25519 (-8) credential is refused, and a CONTROL shows the library's default list accepts it", async () => {
  const auth = await SoftwareAuthenticator.create("EdDSA");
  const ch = challenge();
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
  const control = await verifyRegistrationResponse({ response: response as never, expectedChallenge: b64u(ch), expectedOrigin: RP.origin, expectedRPID: RP.rpId });
  assertEquals(control.verified, true, "CONTROL: EdDSA is in the library's default algorithm list");
  await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "verification_failed", /Unexpected public key alg "-8"/);
});

Deno.test("L7d: the registration options offer exactly -7 and -257, attestation none, a required discoverable credential and required UV", async () => {
  const ch = challenge();
  const opts = await registrationOptions({
    rp: RP,
    rpName: "Example partners",
    userHandle: Uint8Array.of(1, 2, 3, 4),
    userName: "member",
    userDisplayName: "Member",
    challenge: ch,
    excludeCredentialIds: ["AAEC"],
  });
  assertEquals(
    opts.pubKeyCredParams.map((p) => p.alg),
    [-7, -257],
  );
  assertEquals([...PARTNER_ALGORITHM_IDS], [-7, -257]);
  assertEquals(opts.attestation, "none");
  assertEquals(opts.authenticatorSelection?.residentKey, "required");
  assertEquals(opts.authenticatorSelection?.requireResidentKey, true);
  assertEquals(opts.authenticatorSelection?.userVerification, "required");
  assertEquals(opts.timeout, 120_000);
  assertEquals(opts.rp.id, RP.rpId);
  assertEquals(opts.challenge, b64u(ch), "the challenge bytes are emitted as given (no UTF-8 re-encoding)");
  assertEquals(opts.user.id, b64u(Uint8Array.of(1, 2, 3, 4)));
  assertEquals(
    opts.excludeCredentials?.map((c) => c.id),
    ["AAEC"],
  );
});

Deno.test("options: sign-in options require UV, carry an empty allowCredentials and the issued challenge, and bad inputs fail closed", async () => {
  const ch = challenge();
  const opts = await authenticationOptions({ rp: RP, challenge: ch });
  assertEquals(opts.userVerification, "required");
  assertEquals(opts.allowCredentials ?? [], []);
  assertEquals(opts.timeout, 120_000);
  assertEquals(opts.rpId, RP.rpId);
  assertEquals(opts.challenge, b64u(ch));
  await assertRejects(async () => await authenticationOptions({ rp: RP, challenge: new Uint8Array(31) }), RpConfigError);
  await assertRejects(async () => await authenticationOptions({ rp: { rpId: "partners.example.test", origin: "http://partners.example.test" }, challenge: ch }), RpConfigError);
});

Deno.test("RP config: only an exact https origin whose host is the RP ID or a subdomain passes", () => {
  assertRpConfig(RP);
  assertRpConfig({ rpId: "example.test", origin: "https://partners.example.test" });
  assertRpConfig({ rpId: "partners.example.test", origin: "https://partners.example.test:8443" });
  for (const bad of [
    { rpId: "partners.example.test", origin: "https://partners.example.test/" },
    { rpId: "partners.example.test", origin: "https://partners.example.test/x" },
    { rpId: "partners.example.test", origin: "http://partners.example.test" },
    { rpId: "partners.example.test", origin: "https://evilpartners.example.test" },
    { rpId: "partners.example.test", origin: "https://example.test" },
    { rpId: "Partners.example.test", origin: "https://partners.example.test" },
    { rpId: "https://partners.example.test", origin: "https://partners.example.test" },
    { rpId: "", origin: "https://partners.example.test" },
    { rpId: "partners.example.test", origin: "not a url" },
  ]) {
    assertEquals(
      (() => {
        try {
          assertRpConfig(bad);
          return "accepted";
        } catch (e) {
          return e instanceof RpConfigError ? "refused" : "wrong error";
        }
      })(),
      "refused",
      JSON.stringify(bad),
    );
  }
});

// ----- L7 (c) at registration -------------------------------------------------------------------------------------------------------------

Deno.test("L7c register: a response.id that is not the credential id inside the authenticator data is refused, and a CONTROL shows the library accepts it", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const ch = challenge();
  const other = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, reportedId: other });
  const control = await verifyRegistrationResponse({ response: response as never, expectedChallenge: b64u(ch), expectedOrigin: RP.origin, expectedRPID: RP.rpId, supportedAlgorithmIDs: [-7, -257] });
  assertEquals(control.verified, true, "CONTROL: the library does not compare response.id with the id in the authenticator data");
  assertEquals(control.registrationInfo?.credential.id, auth.id);
  await refused(verifyRegistration({ rp: RP, response, expectedChallenge: ch }), "credential_id_mismatch");
});

Deno.test("register: a key whose shape is not the lane's is refused (RSA with e != 65537; RSA under 2048 bits; EC key labelled -7 but RSA-typed)", async () => {
  const auth = await SoftwareAuthenticator.create("RS256");
  // edit a genuine key (decoded with the library's own decoder), not a hand-made one
  const real = new Map((decodeCredentialPublicKey(auth.cosePublicKey as Uint8Array<ArrayBuffer>) as unknown as Map<number, number | Uint8Array>).entries());
  const variants: Array<[string, Map<number, number | Uint8Array>]> = [
    ["e = 3", new Map([...real, [-2, Uint8Array.of(3)]])],
    ["512-bit modulus", new Map([...real, [-1, (real.get(-1) as Uint8Array).slice(0, 64)]])],
    ["kty EC2 with alg -257", new Map([...real, [1, 2]])],
  ];
  for (const [name, key] of variants) {
    const ch = challenge();
    const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: ch, coseKeyOverride: cbor(key as never) });
    const e = await assertRejects(() => verifyRegistration({ rp: RP, response, expectedChallenge: ch }), WebAuthnRefusal, undefined, name);
    assertEquals((e as WebAuthnRefusal).code, "key_shape", name);
  }
});

// ===== sign-in ==========================================================================================================================

for (const alg of ["ES256", "RS256"] as const) {
  Deno.test(`sign in: a ${alg} assertion verifies, the counter advances, and the response carries the stored user handle`, async () => {
    const auth = await SoftwareAuthenticator.create(alg);
    const cred = await enrol(auth);
    for (const expected of [1, 2, 3]) {
      const ch = challenge();
      const out = await verifyAssertion({
        rp: RP,
        response: await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch }),
        expectedChallenge: ch,
        credential: cred,
        expectedUserHandle: auth.userHandle,
      });
      assertEquals(out.credentialId, auth.id);
      assertEquals(out.newSignCount, expected);
      assertEquals(out.userVerified, true);
      cred.signCount = out.newSignCount;
    }
  });
}

/** One assertion with an arbitrary stored counter, for the counter-policy cells. */
async function assertWithCounter(stored: number, reported: number): Promise<number> {
  const auth = await SoftwareAuthenticator.create("ES256");
  const cred = await enrol(auth);
  cred.signCount = stored;
  const ch = challenge();
  const out = await verifyAssertion({
    rp: RP,
    response: await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch, counter: reported }),
    expectedChallenge: ch,
    credential: cred,
    expectedUserHandle: auth.userHandle,
  });
  return out.newSignCount;
}

Deno.test("counter: 0 against a stored 0 PASSES (a synced passkey never counts)", async () => {
  assertEquals(await assertWithCounter(0, 0), 0);
});

Deno.test("counter: a higher counter passes (1 against 0; 6 against 5; a large jump)", async () => {
  assertEquals(await assertWithCounter(0, 1), 1);
  assertEquals(await assertWithCounter(5, 6), 6);
  assertEquals(await assertWithCounter(5, 4_000_000_000), 4_000_000_000);
});

Deno.test("counter: an EQUAL non-zero counter is refused (replay of the last value)", async () => {
  await assertRejects(() => assertWithCounter(5, 5), WebAuthnRefusal);
  const e = await assertRejects(() => assertWithCounter(5, 5), WebAuthnRefusal);
  assertEquals((e as WebAuthnRefusal).code, "verification_failed");
  assertMatch(String(((e as WebAuthnRefusal).cause as Error).message), /Response counter value 5 was lower than expected 5/);
});

Deno.test("counter: a LOWER counter is refused, including 0 against a stored non-zero (clone indicator)", async () => {
  for (const [stored, reported] of [
    [5, 3],
    [5, 4],
    [1, 0],
    [5, 0],
  ] as const) {
    const e = await assertRejects(() => assertWithCounter(stored, reported), WebAuthnRefusal, undefined, `stored ${stored}, reported ${reported}`);
    assertEquals((e as WebAuthnRefusal).code, "verification_failed");
    assertMatch(String(((e as WebAuthnRefusal).cause as Error).message), /Response counter value/);
  }
});

Deno.test("counter: a malformed stored counter is a configuration error, not a client refusal", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const cred = await enrol(auth);
  const ch = challenge();
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
  for (const bad of [-1, 1.5, 2 ** 32, Number.NaN]) {
    await assertRejects(() => verifyAssertion({ rp: RP, response, expectedChallenge: ch, credential: { ...cred, signCount: bad }, expectedUserHandle: auth.userHandle }), RpConfigError);
  }
});

/** A sign-in with one mutation; returns the promise so each case says what it expects. */
async function signIn(
  mutate: { assert?: Partial<AssertOptions>; verifyChallenge?: Uint8Array; userHandle?: Uint8Array },
  alg: "ES256" | "RS256" = "ES256",
): Promise<unknown> {
  const auth = await SoftwareAuthenticator.create(alg);
  const cred = await enrol(auth);
  const ch = challenge();
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch, ...mutate.assert });
  return verifyAssertion({ rp: RP, response, expectedChallenge: mutate.verifyChallenge ?? ch, credential: cred, expectedUserHandle: mutate.userHandle ?? auth.userHandle });
}

Deno.test("sign in: wrong origin is refused", async () => {
  await refused(signIn({ assert: { client: { origin: "https://evil.example.test" } } }) as Promise<unknown>, "verification_failed", /Unexpected authentication response origin/);
});

Deno.test("sign in: wrong RP ID (authenticator data hashes another RP ID) is refused", async () => {
  await refused(signIn({ assert: { rpIdHashOf: OTHER_RP_ID } }) as Promise<unknown>, "verification_failed", /Unexpected RP ID hash/);
});

Deno.test("sign in: missing UV is refused", async () => {
  await refused(signIn({ assert: { flags: { uv: false } } }) as Promise<unknown>, "verification_failed", /User verification required/);
});

Deno.test("sign in: missing UP (and UV) is refused", async () => {
  await refused(signIn({ assert: { flags: { up: false, uv: false } } }) as Promise<unknown>, "verification_failed", /User verification required|User not present/);
});

Deno.test("sign in: a wrong challenge is refused", async () => {
  await refused(signIn({ verifyChallenge: challenge() }) as Promise<unknown>, "verification_failed", /Unexpected authentication response challenge/);
});

Deno.test("sign in: a create-type clientDataJSON is refused", async () => {
  await refused(signIn({ assert: { client: { type: "webauthn.create" } } }) as Promise<unknown>, "verification_failed", /Unexpected authentication response type/);
});

Deno.test("sign in: a tampered signature, a signature by another key, and signed-over-different-authenticator-data are each refused (ES256 and RS256)", async () => {
  for (const alg of ["ES256", "RS256"] as const) {
    const other = await SoftwareAuthenticator.create(alg);
    for (const m of [{ tamperSignature: true }, { signWith: other }, { tamperAuthenticatorData: true }]) {
      await refused(signIn({ assert: m }, alg) as Promise<unknown>, "not_verified");
    }
  }
});

// ----- L7 (a) at sign-in -----------------------------------------------------------------------------------------------------------------

Deno.test("L7a sign in: crossOrigin true is refused, and a CONTROL shows the library alone accepts it (no topOrigin to trip over)", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const cred = await enrol(auth);
  const ch = challenge();
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch, client: { crossOrigin: true } });
  const control = await verifyAuthenticationResponse({
    response: response as never,
    expectedChallenge: b64u(ch),
    expectedOrigin: RP.origin,
    expectedRPID: RP.rpId,
    credential: { id: cred.id, publicKey: cred.publicKey as Uint8Array<ArrayBuffer>, counter: 0 },
  });
  assertEquals(control.verified, true, "CONTROL: SimpleWebAuthn 14.0.3 accepts crossOrigin true when topOrigin is absent");
  await refused(verifyAssertion({ rp: RP, response, expectedChallenge: ch, credential: cred, expectedUserHandle: auth.userHandle }), "cross_origin");
});

Deno.test("L7a sign in: topOrigin is refused whatever crossOrigin says", async () => {
  await refused(signIn({ assert: { client: { crossOrigin: true, topOrigin: "https://evil.example.test" } } }) as Promise<unknown>, "cross_origin");
  await refused(signIn({ assert: { client: { topOrigin: "https://evil.example.test" } } }) as Promise<unknown>, "top_origin");
});

// ----- L7 (c) at sign-in -----------------------------------------------------------------------------------------------------------------

Deno.test("L7c sign in: a response.id that is not the looked-up credential is refused, and a CONTROL shows the library accepts it", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const cred = await enrol(auth);
  const ch = challenge();
  const otherId = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch, reportedId: otherId });
  const control = await verifyAuthenticationResponse({
    response: response as never,
    expectedChallenge: b64u(ch),
    expectedOrigin: RP.origin,
    expectedRPID: RP.rpId,
    credential: { id: cred.id, publicKey: cred.publicKey as Uint8Array<ArrayBuffer>, counter: 0 },
  });
  assertEquals(control.verified, true, "CONTROL: the library verifies against the credential it was GIVEN and never compares response.id");
  assertNotEquals(response.id, cred.id);
  await refused(verifyAssertion({ rp: RP, response, expectedChallenge: ch, credential: cred, expectedUserHandle: auth.userHandle }), "credential_id_mismatch");
});

Deno.test("L7c sign in: a rawId that differs from the looked-up id is refused too", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const cred = await enrol(auth);
  const ch = challenge();
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
  response.rawId = b64u(crypto.getRandomValues(new Uint8Array(32)));
  await refused(verifyAssertion({ rp: RP, response, expectedChallenge: ch, credential: cred, expectedUserHandle: auth.userHandle }), "credential_id_mismatch");
});

// ----- L7 (d) at sign-in -----------------------------------------------------------------------------------------------------------------

Deno.test("L7d sign in: a STORED Ed25519 key is refused, and a CONTROL shows the library alone verifies it", async () => {
  const auth = await SoftwareAuthenticator.create("EdDSA");
  const ch = challenge();
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
  const stored: StoredCredential = { id: auth.id, publicKey: auth.cosePublicKey, signCount: 0 };
  const control = await verifyAuthenticationResponse({
    response: response as never,
    expectedChallenge: b64u(ch),
    expectedOrigin: RP.origin,
    expectedRPID: RP.rpId,
    credential: { id: stored.id, publicKey: stored.publicKey as Uint8Array<ArrayBuffer>, counter: 0 },
  });
  assertEquals(control.verified, true, "CONTROL: verifyAuthenticationResponse has no algorithm option");
  await refused(verifyAssertion({ rp: RP, response, expectedChallenge: ch, credential: stored, expectedUserHandle: auth.userHandle }), "algorithm_not_allowed");
});

Deno.test("L7d sign in: a stored key that is not a COSE key is refused", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const cred = await enrol(auth);
  const ch = challenge();
  const response = await auth.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch });
  await refused(verifyAssertion({ rp: RP, response, expectedChallenge: ch, credential: { ...cred, publicKey: Uint8Array.of(1, 2, 3) }, expectedUserHandle: auth.userHandle }), "key_shape");
});

// ----- user handle -----------------------------------------------------------------------------------------------------------------------

Deno.test("sign in: a userHandle that differs from the stored one, or is absent, is refused", async () => {
  await refused(signIn({ assert: { userHandle: crypto.getRandomValues(new Uint8Array(16)) } }) as Promise<unknown>, "user_handle_mismatch");
  await refused(signIn({ assert: { userHandle: null } }) as Promise<unknown>, "user_handle_mismatch");
  await refused(signIn({ userHandle: crypto.getRandomValues(new Uint8Array(16)) }) as Promise<unknown>, "user_handle_mismatch");
});

// ----- the whole path with the L7 refusals in a different order ---------------------------------------------------------------------------

Deno.test("end to end: enrol two credentials for one person (ES256 and RS256), sign in with each, and the other credential's assertion is refused for the first", async () => {
  const handle = crypto.getRandomValues(new Uint8Array(16));
  const a = await SoftwareAuthenticator.create("ES256", handle);
  const b = await SoftwareAuthenticator.create("RS256", handle);
  const ca = await enrol(a);
  const cb = await enrol(b);
  const ch = challenge();
  assertEquals((await verifyAssertion({ rp: RP, response: await a.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch }), expectedChallenge: ch, credential: ca, expectedUserHandle: handle })).newSignCount, 1);
  assertEquals((await verifyAssertion({ rp: RP, response: await b.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch }), expectedChallenge: ch, credential: cb, expectedUserHandle: handle })).newSignCount, 1);
  // b's assertion presented against a's looked-up record: id mismatch first
  await refused(verifyAssertion({ rp: RP, response: await b.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch }), expectedChallenge: ch, credential: ca, expectedUserHandle: handle }), "credential_id_mismatch");
  // and with b relabelled as a (an attacker who rewrites the id): the signature no longer verifies under a's key
  await refused(
    verifyAssertion({ rp: RP, response: await b.assert({ rpId: RP.rpId, origin: RP.origin, challenge: ch, reportedId: a.id }), expectedChallenge: ch, credential: ca, expectedUserHandle: handle }),
    "verification_failed",
  );
});

// ----- fixture self-checks -----------------------------------------------------------------------------------------------------------------

Deno.test("fixture: the attestation object round-trips through the library's own decoder, and the flag bits are the ones the spec names", async () => {
  const auth = await SoftwareAuthenticator.create("ES256");
  const response = await auth.register({ rpId: RP.rpId, origin: RP.origin, challenge: challenge() });
  const decoded = decodeAttestationObject(isoBase64URL.toBuffer(response.response.attestationObject));
  assertEquals(decoded.get("fmt"), "none");
  assertEquals(decoded.get("attStmt").size, 0);
  const authData = decoded.get("authData");
  assertEquals(authData[32], FLAG_UP | FLAG_UV | 0x40);
  assertEquals(concat(Uint8Array.of(1), Uint8Array.of(2)).length, 2);
});

Deno.test("this run was not granted network access (CI passes --deny-net; the suite needs none, the packages having been cached first)", () => {
  assertNotEquals(Deno.permissions.querySync({ name: "net" }).state, "granted");
  assert(true);
});

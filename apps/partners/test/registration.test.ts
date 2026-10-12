/**
 * The browser half of a passkey registration (src/webauthn/registration.ts): the server's creation options are passed through only if they keep the
 * ceremony strong, and the browser's result is serialised into exactly the shape the server's STRICT registration parser accepts (run here for real).
 */
import { describe, expect, it } from "vitest";
import { WebAuthnFailure } from "../src/webauthn/assertion";
import { encodeBase64Url } from "../src/webauthn/base64url";
import { createCredential, parseCreationOptions, registrationToJson } from "../src/webauthn/registration";
import { parseEnrolCredentialBody } from "../../../supabase/functions/_shared/partner/invites-shape.ts";
import { createSoftAuthenticator } from "./support/soft-authenticator";

const b64 = (n: number, fill = 1) => encodeBase64Url(new Uint8Array(n).fill(fill));
/** What `@simplewebauthn/server` `generateRegistrationOptions` emits for the S0 wrapper's settings. */
const serverOptions = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  rp: { name: "GolfRaven Partners", id: "partners.example.test" },
  user: { id: b64(16, 7), name: "staff@partners.example.test", displayName: "staff@partners.example.test" },
  challenge: b64(32, 9),
  pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
  timeout: 60000,
  attestation: "none",
  excludeCredentials: [],
  authenticatorSelection: { residentKey: "required", userVerification: "required", requireResidentKey: true },
  ...over,
});
const bad = (over: Record<string, unknown>) => () => parseCreationOptions(serverOptions(over));
const refused = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(WebAuthnFailure);
    expect((e as WebAuthnFailure).kind).toBe("bad_options");
    return;
  }
  throw new Error("expected bad_options");
};

describe("parseCreationOptions", () => {
  it("passes the server's options through as binary, and fixes the strong settings itself", () => {
    const o = parseCreationOptions(serverOptions());
    expect(new Uint8Array(o.challenge as ArrayBuffer)).toEqual(new Uint8Array(32).fill(9));
    expect(new Uint8Array(o.user.id as ArrayBuffer)).toEqual(new Uint8Array(16).fill(7));
    expect(o.rp).toEqual({ name: "GolfRaven Partners", id: "partners.example.test" });
    expect(o.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }]);
    expect(o.authenticatorSelection).toEqual({ residentKey: "required", requireResidentKey: true, userVerification: "required" });
    expect(o.attestation).toBe("none");
    expect(o.excludeCredentials).toEqual([]);
    expect(o.timeout).toBe(60000);
  });

  it("excluded credential ids become binary descriptors", () => {
    const o = parseCreationOptions(serverOptions({ excludeCredentials: [{ id: b64(32, 3), type: "public-key", transports: ["internal"] }] }));
    expect(o.excludeCredentials).toHaveLength(1);
    expect(new Uint8Array(o.excludeCredentials![0]!.id as ArrayBuffer)).toEqual(new Uint8Array(32).fill(3));
  });

  it.each([
    ["not an object", () => parseCreationOptions("x")],
    ["user verification only preferred", bad({ authenticatorSelection: { residentKey: "required", userVerification: "preferred" } })],
    ["user verification missing", bad({ authenticatorSelection: { residentKey: "required" } })],
    ["resident key only preferred (a non-discoverable credential cannot sign in usernameless)", bad({ authenticatorSelection: { residentKey: "preferred", userVerification: "required" } })],
    ["no authenticator selection", bad({ authenticatorSelection: undefined })],
    ["attestation that identifies the device", bad({ attestation: "direct" })],
    ["an algorithm the server will not verify (EdDSA)", bad({ pubKeyCredParams: [{ alg: -8, type: "public-key" }] })],
    ["one good and one weak algorithm", bad({ pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -65535, type: "public-key" }] })],
    ["no algorithms", bad({ pubKeyCredParams: [] })],
    ["a challenge of 31 bytes", bad({ challenge: b64(31) })],
    ["a non-canonical challenge", bad({ challenge: `${b64(32)}=` })],
    ["no user", bad({ user: undefined })],
    ["an empty user handle", bad({ user: { id: "", name: "n", displayName: "d" } })],
    ["an oversized user handle (65 bytes)", bad({ user: { id: b64(65), name: "n", displayName: "d" } })],
    ["an excluded credential that is not an object", bad({ excludeCredentials: ["x"] })],
    ["a negative timeout", bad({ timeout: -1 })],
    ["an empty relying-party id", bad({ rp: { name: "n", id: "" } })],
  ])("refuses %s", (_name, f) => refused(f));
});

describe("registrationToJson: exactly the strict shape the server's parser accepts", () => {
  const credential = (over: Record<string, unknown> = {}, response: Record<string, unknown> = {}) => ({
    id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    type: "public-key",
    rawId: new Uint8Array(32).buffer,
    response: { clientDataJSON: new Uint8Array(40).fill(1).buffer, attestationObject: new Uint8Array(60).fill(2).buffer, getTransports: () => ["internal", "hybrid"], ...response },
    ...over,
  });

  it("encodes every binary field as canonical base64url and sends only what the server reads", () => {
    const j = registrationToJson(credential());
    expect(Object.keys(j).sort()).toEqual(["id", "rawId", "response", "type"]);
    expect(Object.keys(j.response).sort()).toEqual(["attestationObject", "clientDataJSON", "transports"]);
    expect(j.rawId).toBe(encodeBase64Url(new Uint8Array(32)));
    expect(j.response.transports).toEqual(["internal", "hybrid"]);
  });

  it("sends no transports when the browser cannot say, or says nonsense", () => {
    expect(registrationToJson(credential({}, { getTransports: undefined })).response).not.toHaveProperty("transports");
    expect(registrationToJson(credential({}, { getTransports: () => { throw new Error("x"); } })).response).not.toHaveProperty("transports");
    expect(registrationToJson(credential({}, { getTransports: () => [1, "", "x".repeat(17)] })).response).not.toHaveProperty("transports");
    expect(registrationToJson(credential({}, { getTransports: () => Array.from({ length: 40 }, () => "usb") })).response.transports).toHaveLength(16);
  });

  it.each([
    ["not an object", null],
    ["wrong type", credential({ type: "password" })],
    ["no raw id", credential({ rawId: "x" })],
    ["no attestation object", credential({}, { attestationObject: "x" })],
    ["no client data", credential({}, { clientDataJSON: undefined })],
  ])("refuses a result that is %s", (_name, value) => {
    expect(() => registrationToJson(value)).toThrow(WebAuthnFailure);
  });
});

describe("createCredential against a software authenticator and the server's REAL registration parser", () => {
  const auth = () => createSoftAuthenticator({ origin: "https://partners.example.test", rpId: "partners.example.test" });

  it("the serialised ceremony is accepted by parseEnrolCredentialBody (unknown keys are refused there, so this is the contract)", async () => {
    const a = auth();
    const json = await createCredential({ credentials: a.credentials, supported: true }, serverOptions());
    const body = { userId: "00000000-0000-4000-8000-0000000000a1", refKind: "invite", refId: "00000000-0000-4000-8000-0000000000b1", challengeToken: `${b64(32)}.${Math.floor(Date.now() / 1000) + 100}.${b64(32)}`, credential: json };
    const parsed = parseEnrolCredentialBody(body);
    expect(parsed.ok, JSON.stringify(parsed)).toBe(true);
    expect(a.created).toHaveLength(1);
    // the authenticator was asked for what the server asked for, with binary challenge and user handle
    const pk = a.createRequests[0]!.publicKey!;
    expect(pk.authenticatorSelection).toMatchObject({ residentKey: "required", userVerification: "required" });
    expect(pk.attestation).toBe("none");
  });

  it("no WebAuthn: 'unsupported'; no create(): 'unsupported'; the person cancelling: 'cancelled'; a null result: 'cancelled'; another refusal: 'failed'", async () => {
    const a = auth();
    const kind = async (deps: Parameters<typeof createCredential>[0]) => ((await createCredential(deps, serverOptions()).catch((e: unknown) => e)) as WebAuthnFailure).kind;
    expect(await kind({ credentials: undefined, supported: true })).toBe("unsupported");
    expect(await kind({ credentials: a.credentials, supported: false })).toBe("unsupported");
    a.failNextCreateWith = "NotAllowedError";
    expect(await kind({ credentials: a.credentials, supported: true })).toBe("cancelled");
    a.failNextCreateWith = "InvalidStateError";
    expect(await kind({ credentials: a.credentials, supported: true })).toBe("failed");
    expect(await kind({ credentials: { create: async () => null }, supported: true })).toBe("cancelled");
  });

  it("bad options never reach the browser", async () => {
    const a = auth();
    await expect(createCredential({ credentials: a.credentials, supported: true }, serverOptions({ attestation: "direct" }))).rejects.toMatchObject({ kind: "bad_options" });
    expect(a.createRequests).toHaveLength(0);
  });
});

import { describe, expect, it } from "vitest";
import { assertionToJson, getAssertion, parseRequestOptions, WebAuthnFailure } from "../src/webauthn/assertion";
import { encodeBase64Url } from "../src/webauthn/base64url";
import { createSoftAuthenticator } from "./support/soft-authenticator";

const CHALLENGE_BYTES = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const CHALLENGE = encodeBase64Url(CHALLENGE_BYTES);
// the shape @simplewebauthn/server@14.0.3 generateAuthenticationOptions returns (`extensions` is undefined and so absent from JSON)
const SERVER_OPTIONS = { rpId: "partners.example.test", challenge: CHALLENGE, allowCredentials: [], timeout: 60000, userVerification: "required" };

const kind = (fn: () => unknown): string => {
  try {
    fn();
    return "ok";
  } catch (e) {
    return e instanceof WebAuthnFailure ? e.kind : "other";
  }
};

describe("parseRequestOptions", () => {
  it("passes the server's options through: challenge bytes, rpId, timeout, UV required, empty allowCredentials", () => {
    const o = parseRequestOptions(JSON.parse(JSON.stringify(SERVER_OPTIONS)));
    expect(new Uint8Array(o.challenge as ArrayBuffer)).toEqual(CHALLENGE_BYTES);
    expect(o.rpId).toBe("partners.example.test");
    expect(o.timeout).toBe(60000);
    expect(o.userVerification).toBe("required");
    expect(o.allowCredentials).toEqual([]);
  });

  it("accepts options with no allowCredentials, rpId or timeout, and still forces an empty list and required UV", () => {
    const o = parseRequestOptions({ challenge: CHALLENGE, userVerification: "required" });
    expect(o.allowCredentials).toEqual([]);
    expect(o.userVerification).toBe("required");
    expect(o.rpId).toBeUndefined();
    expect(o.timeout).toBeUndefined();
  });

  it("REFUSES anything that weakens user verification", () => {
    for (const uv of ["preferred", "discouraged", undefined, "REQUIRED", true, null]) {
      expect(kind(() => parseRequestOptions({ ...SERVER_OPTIONS, userVerification: uv })), String(uv)).toBe("bad_options");
    }
  });

  it("REFUSES a pinned credential list (the chooser must stay usernameless)", () => {
    expect(kind(() => parseRequestOptions({ ...SERVER_OPTIONS, allowCredentials: [{ type: "public-key", id: "AAAA" }] }))).toBe("bad_options");
    expect(kind(() => parseRequestOptions({ ...SERVER_OPTIONS, allowCredentials: "none" }))).toBe("bad_options");
    expect(kind(() => parseRequestOptions({ ...SERVER_OPTIONS, allowCredentials: null }))).toBe("bad_options");
  });

  it("REFUSES a challenge that is not 32 canonical base64url bytes", () => {
    for (const challenge of [undefined, 42, "", "AQ", encodeBase64Url(new Uint8Array(31)), encodeBase64Url(new Uint8Array(33)), CHALLENGE + "=", CHALLENGE.replace("A", "+")]) {
      expect(kind(() => parseRequestOptions({ ...SERVER_OPTIONS, challenge })), String(challenge)).toBe("bad_options");
    }
  });

  it("REFUSES non-object options and malformed rpId or timeout", () => {
    for (const bad of [null, undefined, "x", 3, [], { ...SERVER_OPTIONS, rpId: "" }, { ...SERVER_OPTIONS, rpId: 3 }, { ...SERVER_OPTIONS, timeout: -1 }, { ...SERVER_OPTIONS, timeout: "60000" }, { ...SERVER_OPTIONS, timeout: Number.NaN }]) {
      expect(kind(() => parseRequestOptions(bad)), JSON.stringify(bad)).toBe("bad_options");
    }
  });
});

describe("assertionToJson", () => {
  async function assertion(knobs: object = {}) {
    const a = createSoftAuthenticator({ origin: "https://partners.example.test", rpId: "partners.example.test" });
    Object.assign(a.knobs, knobs);
    const cred = await a.credentials.get({ publicKey: parseRequestOptions(SERVER_OPTIONS) });
    return { a, cred };
  }

  it("produces exactly the fields the server's strict parser accepts, all canonical base64url", async () => {
    const { a, cred } = await assertion();
    const json = assertionToJson(cred);
    expect(Object.keys(json).sort()).toEqual(["id", "rawId", "response", "type"]);
    expect(Object.keys(json.response).sort()).toEqual(["authenticatorData", "clientDataJSON", "signature", "userHandle"]);
    expect(json.type).toBe("public-key");
    expect(json.id).toBe(encodeBase64Url(a.credential.credentialId));
    expect(json.rawId).toBe(json.id);
    for (const v of [json.id, json.rawId, json.response.clientDataJSON, json.response.authenticatorData, json.response.signature, json.response.userHandle!]) expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(json.response.userHandle).toBe(encodeBase64Url(a.credential.userHandle));
    expect(JSON.parse(Buffer.from(json.response.clientDataJSON, "base64url").toString())).toMatchObject({ type: "webauthn.get", challenge: CHALLENGE });
  });

  it("omits userHandle when the authenticator returns none or an empty one", async () => {
    for (const userHandle of [null, new Uint8Array(0)]) {
      const { cred } = await assertion({ userHandle });
      expect("userHandle" in assertionToJson(cred).response).toBe(false);
    }
  });

  it("serialises a view onto a larger buffer by its own bytes only", () => {
    const big = new Uint8Array([9, 9, 1, 2, 3, 9, 9]);
    const json = assertionToJson({ id: "AQID", type: "public-key", rawId: big.subarray(2, 5), response: { clientDataJSON: big.subarray(2, 5), authenticatorData: big.subarray(2, 5), signature: big.subarray(2, 5) } });
    expect(json.rawId).toBe("AQID");
    expect(json.response.signature).toBe("AQID");
  });

  it("refuses a credential that is not a complete assertion", () => {
    const ab = new ArrayBuffer(4);
    const good = { id: "x", type: "public-key", rawId: ab, response: { clientDataJSON: ab, authenticatorData: ab, signature: ab } };
    expect(kind(() => assertionToJson(good))).toBe("ok");
    for (const bad of [null, "x", { ...good, type: "password" }, { ...good, id: 3 }, { ...good, rawId: "AAAA" }, { ...good, response: null }, { ...good, response: { clientDataJSON: ab, authenticatorData: ab } }, { ...good, response: { ...good.response, signature: "sig" } }]) {
      expect(kind(() => assertionToJson(bad)), JSON.stringify(bad, (_k, v) => (v instanceof ArrayBuffer ? "AB" : v))).toBe("failed");
    }
  });
});

describe("getAssertion", () => {
  const soft = () => createSoftAuthenticator({ origin: "https://partners.example.test", rpId: "partners.example.test" });

  it("asks the browser for exactly the server's parameters: UV required, empty allowCredentials, the server's challenge, nothing else", async () => {
    const a = soft();
    const json = await getAssertion({ credentials: a.credentials, supported: true }, SERVER_OPTIONS);
    expect(a.requests).toHaveLength(1);
    const pk = a.requests[0]!.publicKey!;
    expect(Object.keys(pk).sort()).toEqual(["allowCredentials", "challenge", "rpId", "timeout", "userVerification"]);
    expect(pk.userVerification).toBe("required");
    expect(pk.allowCredentials).toEqual([]);
    expect(new Uint8Array(pk.challenge as ArrayBuffer)).toEqual(CHALLENGE_BYTES);
    expect(Object.keys(a.requests[0]!)).toEqual(["publicKey"]); // no mediation, no signal unless given
    expect(json.type).toBe("public-key");
  });

  it("passes an abort signal through", async () => {
    const a = soft();
    const c = new AbortController();
    await getAssertion({ credentials: a.credentials, supported: true }, SERVER_OPTIONS, c.signal);
    expect(a.requests[0]!.signal).toBe(c.signal);
  });

  it("maps the browser's refusals: NotAllowedError and AbortError are 'cancelled', others 'failed', a null result is 'cancelled'", async () => {
    const run = async (setup: (a: ReturnType<typeof soft>) => void) => {
      const a = soft();
      setup(a);
      try {
        await getAssertion({ credentials: a.credentials, supported: true }, SERVER_OPTIONS);
        return "ok";
      } catch (e) {
        return (e as WebAuthnFailure).kind;
      }
    };
    expect(await run((a) => (a.failNextWith = "NotAllowedError"))).toBe("cancelled");
    expect(await run((a) => (a.failNextWith = "AbortError"))).toBe("cancelled");
    expect(await run((a) => (a.failNextWith = "SecurityError"))).toBe("failed");
    expect(await run((a) => (a.failNextWith = "InvalidStateError"))).toBe("failed");
    expect(await run((a) => (a.returnNullNext = true))).toBe("cancelled");
  });

  it("is 'unsupported' with no credentials container or no PublicKeyCredential, and never calls the browser then", async () => {
    const a = soft();
    for (const deps of [{ credentials: undefined, supported: true }, { credentials: a.credentials, supported: false }]) {
      await expect(getAssertion(deps, SERVER_OPTIONS)).rejects.toMatchObject({ kind: "unsupported" });
    }
    expect(a.requests).toEqual([]);
  });

  it("never calls the browser for options it refuses", async () => {
    const a = soft();
    await expect(getAssertion({ credentials: a.credentials, supported: true }, { ...SERVER_OPTIONS, userVerification: "preferred" })).rejects.toMatchObject({ kind: "bad_options" });
    expect(a.requests).toEqual([]);
  });

  it("refuses a result that is not an assertion", async () => {
    await expect(getAssertion({ credentials: { get: async () => ({ id: "x", type: "public-key", rawId: new ArrayBuffer(1), response: { attestationObject: new ArrayBuffer(1) } }) as unknown as Credential }, supported: true }, SERVER_OPTIONS)).rejects.toMatchObject({ kind: "failed" });
  });
});

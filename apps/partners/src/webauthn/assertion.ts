/**
 * The browser half of a passkey assertion (docs/security/partner-auth-design.md 6.2, 18.1).
 *
 * The server owns the ceremony's parameters: the challenge, the relying-party id, `userVerification: "required"` and an
 * EMPTY `allowCredentials` (usernameless sign-in: the operating system's chooser lists the discoverable credentials).
 * `parseRequestOptions` passes them through and REFUSES options that weaken any of those, so a server bug or a hostile
 * proxy cannot quietly turn user verification off or pin the chooser to one credential.
 *
 * `getAssertion` calls `navigator.credentials.get` and serialises the result by hand, field by field, into exactly the
 * shape the server's strict parser accepts (every binary field canonical unpadded base64url). It does not use
 * `PublicKeyCredential.toJSON()`: that method is newer than the browsers a shop iPad may run `[unverified - training
 * knowledge on Safari's toJSON support]`, and a hand serialiser is the contract the unit tests pin.
 */

import type { AssertionJson } from "../api/types";
import { decodeBase64Url, encodeBase64Url } from "./base64url";

export type WebAuthnFailureKind =
  /** The browser has no WebAuthn (`navigator.credentials` / `PublicKeyCredential` missing). */
  | "unsupported"
  /** The server's options are not the documented, strong shape. */
  | "bad_options"
  /** The person cancelled, the prompt timed out, or no credential was chosen (`NotAllowedError`, a null result). */
  | "cancelled"
  /** The browser refused for another reason (security error, an invalid state ...). */
  | "failed";

export class WebAuthnFailure extends Error {
  readonly kind: WebAuthnFailureKind;
  constructor(kind: WebAuthnFailureKind) {
    super(`webauthn: ${kind}`);
    this.name = "WebAuthnFailure";
    this.kind = kind;
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Server JSON options -> the object `navigator.credentials.get` takes. Throws `WebAuthnFailure("bad_options")`. */
export function parseRequestOptions(json: unknown): PublicKeyCredentialRequestOptions {
  if (!isObject(json)) throw new WebAuthnFailure("bad_options");
  const { challenge, rpId, timeout, userVerification, allowCredentials } = json;
  if (typeof challenge !== "string") throw new WebAuthnFailure("bad_options");
  let challengeBytes: ArrayBuffer;
  try {
    challengeBytes = decodeBase64Url(challenge);
  } catch {
    throw new WebAuthnFailure("bad_options");
  }
  if (challengeBytes.byteLength !== 32) throw new WebAuthnFailure("bad_options");
  if (userVerification !== "required") throw new WebAuthnFailure("bad_options");
  if (allowCredentials !== undefined && !(Array.isArray(allowCredentials) && allowCredentials.length === 0)) throw new WebAuthnFailure("bad_options");
  if (rpId !== undefined && (typeof rpId !== "string" || rpId.length === 0)) throw new WebAuthnFailure("bad_options");
  if (timeout !== undefined && (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout < 0)) throw new WebAuthnFailure("bad_options");
  const options: PublicKeyCredentialRequestOptions = { challenge: challengeBytes, userVerification: "required", allowCredentials: [] };
  if (typeof rpId === "string") options.rpId = rpId;
  if (typeof timeout === "number") options.timeout = timeout;
  return options;
}

function isBuffer(v: unknown): v is ArrayBuffer {
  return v instanceof ArrayBuffer || ArrayBuffer.isView(v);
}

/**
 * The server's wire shape of a `PublicKeyCredential` assertion. Checked structurally (the fields must be there and be binary), not with
 * `instanceof`, so the serialiser runs identically in a browser and under a test double.
 */
export function assertionToJson(credential: unknown): AssertionJson {
  if (!isObject(credential) || credential["type"] !== "public-key" || typeof credential["id"] !== "string" || !isBuffer(credential["rawId"])) throw new WebAuthnFailure("failed");
  const response = credential["response"];
  if (!isObject(response) || !isBuffer(response["clientDataJSON"]) || !isBuffer(response["authenticatorData"]) || !isBuffer(response["signature"])) throw new WebAuthnFailure("failed");
  const out: AssertionJson = {
    id: credential["id"],
    rawId: encodeBase64Url(credential["rawId"]),
    type: "public-key",
    response: {
      clientDataJSON: encodeBase64Url(response["clientDataJSON"]),
      authenticatorData: encodeBase64Url(response["authenticatorData"]),
      signature: encodeBase64Url(response["signature"]),
    },
  };
  // a discoverable credential returns the user handle; an absent or empty one is simply not sent
  const handle = response["userHandle"];
  if (isBuffer(handle) && handle.byteLength > 0) out.response.userHandle = encodeBase64Url(handle);
  return out;
}

export interface GetAssertionDeps {
  /** `navigator.credentials`. Injected so tests and the harness never touch a global. */
  readonly credentials: Pick<CredentialsContainer, "get"> | undefined;
  /** Whether WebAuthn exists in this browser; defaults to `typeof PublicKeyCredential !== "undefined"`. */
  readonly supported?: boolean;
}

/** Runs the ceremony for the server's options and returns the serialised assertion. */
export async function getAssertion(deps: GetAssertionDeps, optionsJson: unknown, signal?: AbortSignal): Promise<AssertionJson> {
  const credentials = deps.credentials;
  const supported = deps.supported ?? typeof PublicKeyCredential !== "undefined";
  if (credentials === undefined || !supported) throw new WebAuthnFailure("unsupported");
  const publicKey = parseRequestOptions(optionsJson);
  let result: Credential | null;
  try {
    const request: CredentialRequestOptions = { publicKey };
    if (signal !== undefined) request.signal = signal;
    result = await credentials.get(request);
  } catch (e) {
    const name = typeof e === "object" && e !== null && "name" in e ? String((e as { name: unknown }).name) : "";
    throw new WebAuthnFailure(name === "NotAllowedError" || name === "AbortError" ? "cancelled" : "failed");
  }
  if (result === null) throw new WebAuthnFailure("cancelled");
  return assertionToJson(result);
}

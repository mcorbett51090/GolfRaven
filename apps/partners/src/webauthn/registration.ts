/**
 * The browser half of a passkey REGISTRATION (docs/security/partner-auth-design.md 6.1 step 4, 18): `navigator.credentials.create` for the options
 * the server returned from `accept/verify`.
 *
 * The server owns the ceremony: the 32-byte challenge, the relying party, the person's user handle, `attestation: "none"`, a discoverable credential
 * (`residentKey: "required"`) and `userVerification: "required"`, and only ES256 / RS256. `parseCreationOptions` passes those through and REFUSES any
 * options that weaken them (a hostile proxy or a server bug must not quietly turn user verification off, ask for a non-resident credential, request
 * attestation that identifies the device, or offer an algorithm the server will not verify).
 *
 * `createCredential` serialises the result by hand into exactly the shape the server's strict registration parser accepts (every binary field canonical
 * unpadded base64url; no extension results, no convenience copies the server would drop), the same discipline as `assertion.ts`.
 */

import type { RegistrationJson } from "../api/types";
import { WebAuthnFailure } from "./assertion";
import { decodeBase64Url, encodeBase64Url } from "./base64url";

/** The two algorithms the server verifies (design 6.1 L7 d): ES256 and RS256. */
const ALLOWED_ALGORITHMS: readonly number[] = [-7, -257];
const MAX_TRANSPORTS = 16;
const MAX_TRANSPORT_LENGTH = 16;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function bytesOf(v: unknown, min: number, max: number): ArrayBuffer {
  if (typeof v !== "string") throw new WebAuthnFailure("bad_options");
  let b: ArrayBuffer;
  try {
    b = decodeBase64Url(v);
  } catch {
    throw new WebAuthnFailure("bad_options");
  }
  if (b.byteLength < min || b.byteLength > max) throw new WebAuthnFailure("bad_options");
  return b;
}

/** Server JSON creation options -> the object `navigator.credentials.create` takes. Throws `WebAuthnFailure("bad_options")`. */
export function parseCreationOptions(json: unknown): PublicKeyCredentialCreationOptions {
  if (!isObject(json)) throw new WebAuthnFailure("bad_options");
  const { rp, user, challenge, pubKeyCredParams, timeout, attestation, excludeCredentials, authenticatorSelection } = json;
  if (!isObject(rp) || typeof rp["name"] !== "string" || (rp["id"] !== undefined && (typeof rp["id"] !== "string" || rp["id"].length === 0))) throw new WebAuthnFailure("bad_options");
  if (!isObject(user) || typeof user["name"] !== "string" || typeof user["displayName"] !== "string") throw new WebAuthnFailure("bad_options");
  const userId = bytesOf(user["id"], 1, 64);
  const challengeBytes = bytesOf(challenge, 32, 32);
  if (!Array.isArray(pubKeyCredParams) || pubKeyCredParams.length === 0) throw new WebAuthnFailure("bad_options");
  const params: PublicKeyCredentialParameters[] = pubKeyCredParams.map((p: unknown) => {
    if (!isObject(p) || p["type"] !== "public-key" || typeof p["alg"] !== "number" || !ALLOWED_ALGORITHMS.includes(p["alg"])) throw new WebAuthnFailure("bad_options");
    return { type: "public-key", alg: p["alg"] };
  });
  if (!isObject(authenticatorSelection) || authenticatorSelection["userVerification"] !== "required" || authenticatorSelection["residentKey"] !== "required") throw new WebAuthnFailure("bad_options");
  if (attestation !== undefined && attestation !== "none") throw new WebAuthnFailure("bad_options");
  if (timeout !== undefined && (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout < 0)) throw new WebAuthnFailure("bad_options");
  const exclude: PublicKeyCredentialDescriptor[] = [];
  if (excludeCredentials !== undefined) {
    if (!Array.isArray(excludeCredentials)) throw new WebAuthnFailure("bad_options");
    for (const c of excludeCredentials) {
      if (!isObject(c) || (c["type"] !== undefined && c["type"] !== "public-key")) throw new WebAuthnFailure("bad_options");
      exclude.push({ type: "public-key", id: bytesOf(c["id"], 16, 1023) });
    }
  }
  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: { name: rp["name"], ...(typeof rp["id"] === "string" ? { id: rp["id"] } : {}) },
    user: { id: userId, name: user["name"], displayName: user["displayName"] },
    challenge: challengeBytes,
    pubKeyCredParams: params,
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
    attestation: "none",
    excludeCredentials: exclude,
  };
  if (typeof timeout === "number") publicKey.timeout = timeout;
  return publicKey;
}

function isBuffer(v: unknown): v is ArrayBuffer {
  return v instanceof ArrayBuffer || ArrayBuffer.isView(v);
}

/**
 * The wire shape of a `navigator.credentials.create` result. Checked structurally (the fields must be there and be binary), not with `instanceof`, so
 * the serialiser runs identically in a browser and under a test double. Only fields the server reads are sent.
 */
export function registrationToJson(credential: unknown): RegistrationJson {
  if (!isObject(credential) || credential["type"] !== "public-key" || typeof credential["id"] !== "string" || !isBuffer(credential["rawId"])) throw new WebAuthnFailure("failed");
  const response = credential["response"];
  if (!isObject(response) || !isBuffer(response["clientDataJSON"]) || !isBuffer(response["attestationObject"])) throw new WebAuthnFailure("failed");
  const out: RegistrationJson = {
    id: credential["id"],
    rawId: encodeBase64Url(credential["rawId"]),
    type: "public-key",
    response: { clientDataJSON: encodeBase64Url(response["clientDataJSON"]), attestationObject: encodeBase64Url(response["attestationObject"]) },
  };
  const getTransports = response["getTransports"];
  if (typeof getTransports === "function") {
    try {
      const t: unknown = getTransports.call(response);
      if (Array.isArray(t)) {
        const list = t.filter((x): x is string => typeof x === "string" && x.length > 0 && x.length <= MAX_TRANSPORT_LENGTH).slice(0, MAX_TRANSPORTS);
        if (list.length > 0) out.response.transports = list;
      }
    } catch {
      // transports are an optional hint; a browser that cannot say simply sends none
    }
  }
  return out;
}

export interface CreateCredentialDeps {
  /** `navigator.credentials`. Injected so tests and the harness never touch a global. */
  readonly credentials: Pick<CredentialsContainer, "create"> | undefined;
  /** Whether WebAuthn exists in this browser; defaults to `typeof PublicKeyCredential !== "undefined"`. */
  readonly supported?: boolean;
}

/** Runs the create ceremony for the server's options and returns the serialised registration. */
export async function createCredential(deps: CreateCredentialDeps, optionsJson: unknown, signal?: AbortSignal): Promise<RegistrationJson> {
  const credentials = deps.credentials;
  const supported = deps.supported ?? typeof PublicKeyCredential !== "undefined";
  if (credentials === undefined || !supported) throw new WebAuthnFailure("unsupported");
  const publicKey = parseCreationOptions(optionsJson);
  let result: Credential | null;
  try {
    const request: CredentialCreationOptions = { publicKey };
    if (signal !== undefined) request.signal = signal;
    result = await credentials.create(request);
  } catch (e) {
    const name = typeof e === "object" && e !== null && "name" in e ? String((e as { name: unknown }).name) : "";
    throw new WebAuthnFailure(name === "NotAllowedError" || name === "AbortError" ? "cancelled" : "failed");
  }
  if (result === null) throw new WebAuthnFailure("cancelled");
  return registrationToJson(result);
}

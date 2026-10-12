/**
 * A software WebAuthn authenticator for tests: an ES256 key pair and a `credentials.get` double that produces REAL assertions (a genuine ECDSA
 * signature over `authenticatorData || sha256(clientDataJSON)`, the exact thing a browser's authenticator signs), so the fake partner server can
 * verify them for real. The Playwright suite hands the same private key to Chromium's virtual authenticator (`WebAuthn.addCredential`), so the
 * node-level and browser-level tests exercise one credential.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { encodeBase64Url } from "../../src/webauthn/base64url";
import { type Cbor, cborEncode } from "./cbor";

export interface SoftCredential {
  readonly credentialId: Uint8Array;
  readonly userHandle: Uint8Array;
  readonly privateKey: KeyObject;
  /** SPKI DER of the public key: what the fake server stores as the credential's `publicKey`. */
  readonly publicKeySpki: Uint8Array;
  /** PKCS8 DER of the private key, base64 (the form `WebAuthn.addCredential` takes). */
  readonly privateKeyPkcs8Base64: string;
}

export function newSoftCredential(userHandle: Uint8Array = randomBytes(16)): SoftCredential {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    credentialId: randomBytes(32),
    userHandle,
    privateKey,
    publicKeySpki: new Uint8Array(publicKey.export({ type: "spki", format: "der" })),
    privateKeyPkcs8Base64: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

export function publicKeyFromSpki(spki: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
}

export function privateKeyFromPkcs8(base64: string): KeyObject {
  return createPrivateKey({ key: Buffer.from(base64, "base64"), format: "der", type: "pkcs8" });
}

export interface AssertionKnobs {
  /** The origin written into `clientDataJSON` (default: the page's). */
  origin?: string;
  rpId?: string;
  /** The authenticator-data flags byte (default 0x05: user present + user verified). */
  flags?: number;
  counter?: number;
  /** Replaces the challenge the browser would sign (a tampered or replayed one). */
  challenge?: Uint8Array;
  userHandle?: Uint8Array | null;
}

export interface SoftAuthenticator {
  readonly credential: SoftCredential;
  readonly credentials: Pick<CredentialsContainer, "get" | "create">;
  /** Every credential `create` made, in order (each with its own key pair): sign in with one by building a second authenticator around it. */
  readonly created: SoftCredential[];
  /** Every `create` request it served. */
  readonly createRequests: CredentialCreationOptions[];
  /** The next `create` rejects with this error name; consumed once. */
  failNextCreateWith: string | null;
  /** Every `get` request it served, for assertions about what the page asked for. */
  readonly requests: CredentialRequestOptions[];
  knobs: AssertionKnobs;
  /** The next `get` rejects with this error name (a DOMException-shaped object); consumed once. */
  failNextWith: string | null;
  /** The next `get` resolves with null; consumed once. */
  returnNullNext: boolean;
}

const sha256 = (data: Uint8Array | string): Buffer => createHash("sha256").update(data).digest();

export function createSoftAuthenticator(opts: { origin: string; rpId: string; credential?: SoftCredential }): SoftAuthenticator {
  const credential = opts.credential ?? newSoftCredential();
  let counter = 0;
  const self: SoftAuthenticator = {
    credential,
    requests: [],
    knobs: {},
    failNextWith: null,
    returnNullNext: false,
    created: [],
    createRequests: [],
    failNextCreateWith: null,
    credentials: {
      async create(request?: CredentialCreationOptions): Promise<Credential | null> {
        const pk = request?.publicKey;
        if (pk === undefined) throw new Error("soft authenticator: publicKey options required");
        self.createRequests.push(request!);
        if (self.failNextCreateWith !== null) {
          const name = self.failNextCreateWith;
          self.failNextCreateWith = null;
          throw Object.assign(new Error(name), { name });
        }
        const fresh = newSoftCredential(new Uint8Array(pk.user.id as ArrayBuffer));
        self.created.push(fresh);
        const rpId = pk.rp.id ?? new URL(opts.origin).hostname;
        const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: encodeBase64Url(pk.challenge as ArrayBuffer), origin: self.knobs.origin ?? opts.origin, crossOrigin: false }));
        const spki = Buffer.from(fresh.publicKeySpki);
        // an uncompressed P-256 point sits at the end of the SPKI: 0x04 || x(32) || y(32)
        const x = spki.subarray(spki.length - 64, spki.length - 32);
        const y = spki.subarray(spki.length - 32);
        const cose = new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(x)], [-3, new Uint8Array(y)]]);
        const idLen = Buffer.alloc(2);
        idLen.writeUInt16BE(fresh.credentialId.length);
        // UP | UV | AT
        const authData = Buffer.concat([sha256(rpId), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen, Buffer.from(fresh.credentialId), Buffer.from(cborEncode(cose))]);
        const attestationObject = cborEncode(new Map<Cbor, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]]));
        const ab = (b: Uint8Array): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
        return {
          id: encodeBase64Url(fresh.credentialId),
          rawId: ab(fresh.credentialId),
          type: "public-key",
          response: { clientDataJSON: ab(clientDataJSON), attestationObject: ab(attestationObject), getTransports: () => ["internal"] },
        } as unknown as Credential;
      },
      async get(request?: CredentialRequestOptions): Promise<Credential | null> {
        if (request?.publicKey === undefined) throw new Error("soft authenticator: publicKey options required");
        self.requests.push(request);
        if (self.failNextWith !== null) {
          const name = self.failNextWith;
          self.failNextWith = null;
          throw Object.assign(new Error(name), { name });
        }
        if (self.returnNullNext) {
          self.returnNullNext = false;
          return null;
        }
        const challenge = self.knobs.challenge ?? new Uint8Array(request.publicKey.challenge as ArrayBuffer);
        const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: encodeBase64Url(challenge), origin: self.knobs.origin ?? opts.origin, crossOrigin: false }));
        counter += 1;
        const authData = Buffer.concat([sha256(self.knobs.rpId ?? opts.rpId), Buffer.from([self.knobs.flags ?? 0x05]), Buffer.alloc(4)]);
        authData.writeUInt32BE(self.knobs.counter ?? counter, 33);
        const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), { key: credential.privateKey, dsaEncoding: "der" });
        const handle = self.knobs.userHandle === undefined ? credential.userHandle : self.knobs.userHandle;
        const ab = (b: Uint8Array): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
        return {
          id: encodeBase64Url(credential.credentialId),
          rawId: ab(credential.credentialId),
          type: "public-key",
          response: {
            clientDataJSON: ab(clientDataJSON),
            authenticatorData: ab(authData),
            signature: ab(signature),
            userHandle: handle === null ? null : ab(handle),
          },
        } as unknown as Credential;
      },
    },
  };
  return self;
}

// supabase/tests/deno-unit/software-authenticator.ts
//
// A SOFTWARE WebAuthn authenticator for the partner-lane wrapper tests (docs/security/partner-auth-design.md, S0, PA-0a). It builds, by hand, exactly the
// bytes a browser would hand to the Edge: `clientDataJSON`, CBOR attestation objects, authenticator data and assertion signatures, using Web Crypto
// (ES256 on P-256, RS256 as RSASSA-PKCS1-v1_5/SHA-256 with e = 65537, and Ed25519 for the "algorithm outside the allow-list" cases). Nothing here is
// production code: it is a test double that can be told to misbehave in exactly one way at a time.
//
// It deliberately depends on NOTHING but Web Crypto and the platform (no library under test): a fixture built with the library it tests would share
// that library's mistakes. The one thing it does not re-implement is the encoding of a response into JSON; it emits the same `*ResponseJSON` shape
// `@simplewebauthn/browser` would.
//
// No network, no files, no clock: deterministic apart from key generation and the random credential id.

export type AuthAlg = "ES256" | "RS256" | "EdDSA";

export const COSE_ALG: Record<AuthAlg, number> = { ES256: -7, RS256: -257, EdDSA: -8 };

// authenticator data flags (WebAuthn L2 6.1)
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;

// ----- encoding helpers ------------------------------------------------------------------------------------------------------------------

export function b64u(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function fromB64u(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const utf8 = (s: string) => new TextEncoder().encode(s);

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
}

// ----- a minimal CBOR encoder (just what an attestation object and a COSE key need) -----------------------------------------------------

type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>;

function cborHead(major: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function cbor(v: Cbor): Uint8Array {
  if (typeof v === "number") return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === "string") {
    const b = utf8(v);
    return concat(cborHead(3, b.length), b);
  }
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
  const parts: Uint8Array[] = [cborHead(5, v.size)];
  for (const [k, val] of v) parts.push(cbor(k), cbor(val));
  return concat(...parts);
}

// ----- signature encoding ---------------------------------------------------------------------------------------------------------------

/** Web Crypto returns ECDSA as raw r||s; a WebAuthn assertion carries the ASN.1 DER `Ecdsa-Sig-Value`. */
export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const int = (b: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v: Uint8Array = b.slice(i);
    if (v[0]! & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(0x02, v.length), v);
  };
  const body = concat(int(raw.slice(0, half)), int(raw.slice(half)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

// ----- the authenticator ----------------------------------------------------------------------------------------------------------------

export interface CeremonyFlags {
  up?: boolean;
  uv?: boolean;
  be?: boolean;
  bs?: boolean;
}

export interface ClientDataOverrides {
  type?: string;
  /** Written as-is into clientDataJSON (so `true`, `"true"`, `1`, `null` can each be tried). Omitted from the JSON when undefined. */
  crossOrigin?: unknown;
  topOrigin?: string;
  origin?: string;
  /** Replaces the challenge the browser would have signed over (base64url). */
  challenge?: string;
}

export interface RegisterOptions {
  rpId: string;
  origin: string;
  challenge: Uint8Array;
  flags?: CeremonyFlags;
  /** The counter to write into the authenticator data (default 0, as a synced passkey does). */
  counter?: number;
  /** Hash a different RP ID into the authenticator data. */
  rpIdHashOf?: string;
  client?: ClientDataOverrides;
  /** `none` (default), or `packed` (a self attestation the library would verify) or any other string with an empty attStmt. */
  fmt?: string;
  /** Replaces the attestation statement map entirely (for `none` with a non-empty statement, or garbage under another fmt). */
  attStmt?: Map<Cbor, Cbor>;
  /** What the browser reports as `id` and `rawId` (default: the real credential id). */
  reportedId?: string;
  /** Replace the COSE public key bytes written into the authenticator data. */
  coseKeyOverride?: Uint8Array;
}

export interface AssertOptions {
  rpId: string;
  origin: string;
  challenge: Uint8Array;
  flags?: CeremonyFlags;
  /** The counter to report. Default: this authenticator's own running counter + 1. */
  counter?: number;
  rpIdHashOf?: string;
  client?: ClientDataOverrides;
  /** What the browser reports as `id` and `rawId`. */
  reportedId?: string;
  /** The user handle to return: default this authenticator's; `null` omits it. */
  userHandle?: Uint8Array | null;
  /** Flip one bit of the signature. */
  tamperSignature?: boolean;
  /** Sign with this authenticator's key but over a different payload than the one reported (the data the server hashes is not what was signed). */
  tamperAuthenticatorData?: boolean;
  /** Sign with another key entirely. */
  signWith?: SoftwareAuthenticator;
}

export interface RegistrationResponseJSONLike {
  id: string;
  rawId: string;
  type: "public-key";
  clientExtensionResults: Record<string, never>;
  response: { clientDataJSON: string; attestationObject: string; transports: string[] };
}

export interface AuthenticationResponseJSONLike {
  id: string;
  rawId: string;
  type: "public-key";
  clientExtensionResults: Record<string, never>;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string };
}

export class SoftwareAuthenticator {
  readonly alg: AuthAlg;
  readonly credentialId: Uint8Array;
  readonly userHandle: Uint8Array;
  /** The count this authenticator reports next minus one: `assert()` without an explicit counter reports `counter + 1`. */
  counter = 0;
  private constructor(
    alg: AuthAlg,
    private readonly priv: CryptoKey,
    readonly cosePublicKey: Uint8Array,
    /** The raw public-key components (ES256: x, y; RS256: n, e; Ed25519: x), for tools that verify outside WebAuthn (the database-side spike). */
    readonly keyParams: { x?: Uint8Array; y?: Uint8Array; n?: Uint8Array; e?: Uint8Array },
    credentialId: Uint8Array,
    userHandle: Uint8Array,
  ) {
    this.alg = alg;
    this.credentialId = credentialId;
    this.userHandle = userHandle;
  }

  static async create(alg: AuthAlg, userHandle: Uint8Array = crypto.getRandomValues(new Uint8Array(16))): Promise<SoftwareAuthenticator> {
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    let priv: CryptoKey;
    let cose: Map<Cbor, Cbor>;
    let keyParams: { x?: Uint8Array; y?: Uint8Array; n?: Uint8Array; e?: Uint8Array };
    if (alg === "ES256") {
      const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      priv = kp.privateKey;
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)); // 0x04 || X || Y
      keyParams = { x: raw.slice(1, 33), y: raw.slice(33, 65) };
      cose = new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, keyParams.x!], [-3, keyParams.y!]]);
    } else if (alg === "RS256") {
      const kp = await crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" },
        true,
        ["sign", "verify"],
      );
      priv = kp.privateKey;
      const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
      keyParams = { n: fromB64u(jwk.n!), e: fromB64u(jwk.e!) };
      cose = new Map<Cbor, Cbor>([[1, 3], [3, -257], [-1, keyParams.n!], [-2, keyParams.e!]]);
    } else {
      const kp = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
      priv = kp.privateKey;
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
      keyParams = { x: raw };
      cose = new Map<Cbor, Cbor>([[1, 1], [3, -8], [-1, 6], [-2, raw]]);
    }
    return new SoftwareAuthenticator(alg, priv, cbor(cose), keyParams, credentialId, userHandle);
  }

  /** The id as the browser reports it. */
  get id(): string {
    return b64u(this.credentialId);
  }

  private async sign(data: Uint8Array): Promise<Uint8Array> {
    const buf = data as Uint8Array<ArrayBuffer>;
    if (this.alg === "ES256") return ecdsaRawToDer(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.priv, buf)));
    if (this.alg === "RS256") return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", this.priv, buf));
    return new Uint8Array(await crypto.subtle.sign("Ed25519", this.priv, buf));
  }

  private static flagByte(f: CeremonyFlags | undefined, at: boolean): number {
    // defaults model a platform authenticator after a biometric: UP and UV set, not backup-eligible
    const up = f?.up ?? true;
    const uv = f?.uv ?? true;
    return (up ? FLAG_UP : 0) | (uv ? FLAG_UV : 0) | (f?.be ? FLAG_BE : 0) | (f?.bs ? FLAG_BS : 0) | (at ? FLAG_AT : 0);
  }

  private static counterBytes(n: number): Uint8Array {
    return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }

  private static clientData(type: string, o: { origin: string; challenge: Uint8Array; client?: ClientDataOverrides }): Uint8Array {
    const c = o.client ?? {};
    const obj: Record<string, unknown> = {
      type: c.type ?? type,
      challenge: c.challenge ?? b64u(o.challenge),
      origin: c.origin ?? o.origin,
    };
    // a browser writes `crossOrigin: false` explicitly; an override replaces it, `undefined` is dropped by JSON.stringify
    obj.crossOrigin = "crossOrigin" in c ? c.crossOrigin : false;
    if (c.topOrigin !== undefined) obj.topOrigin = c.topOrigin;
    return utf8(JSON.stringify(obj));
  }

  /** A create ceremony: attestation object with the credential's public key, and the matching clientDataJSON. */
  async register(o: RegisterOptions): Promise<RegistrationResponseJSONLike> {
    const rpIdHash = await sha256(utf8(o.rpIdHashOf ?? o.rpId));
    const credLen = Uint8Array.of((this.credentialId.length >> 8) & 0xff, this.credentialId.length & 0xff);
    const attested = concat(new Uint8Array(16), credLen, this.credentialId, o.coseKeyOverride ?? this.cosePublicKey);
    const authData = concat(rpIdHash, Uint8Array.of(SoftwareAuthenticator.flagByte(o.flags, true)), SoftwareAuthenticator.counterBytes(o.counter ?? 0), attested);
    const clientDataJSON = SoftwareAuthenticator.clientData("webauthn.create", o);
    const fmt = o.fmt ?? "none";
    let attStmt: Map<Cbor, Cbor> = o.attStmt ?? new Map();
    if (fmt === "packed" && o.attStmt === undefined) {
      // self attestation: sig over authData || SHA-256(clientDataJSON) with the credential key itself, alg named in the statement
      const sig = await this.sign(concat(authData, await sha256(clientDataJSON)));
      attStmt = new Map<Cbor, Cbor>([["alg", COSE_ALG[this.alg]], ["sig", sig]]);
    }
    const attestationObject = cbor(new Map<Cbor, Cbor>([["fmt", fmt], ["attStmt", attStmt], ["authData", authData]]));
    const id = o.reportedId ?? this.id;
    return { id, rawId: id, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ["internal"] } };
  }

  /** A get ceremony. Advances this authenticator's own counter to the value it reports (unless an explicit counter says otherwise). */
  async assert(o: AssertOptions): Promise<AuthenticationResponseJSONLike> {
    const counter = o.counter ?? this.counter + 1;
    this.counter = counter;
    const rpIdHash = await sha256(utf8(o.rpIdHashOf ?? o.rpId));
    const authData = concat(rpIdHash, Uint8Array.of(SoftwareAuthenticator.flagByte(o.flags, false)), SoftwareAuthenticator.counterBytes(counter));
    const clientDataJSON = SoftwareAuthenticator.clientData("webauthn.get", o);
    const signer = o.signWith ?? this;
    const signedAuthData = o.tamperAuthenticatorData ? Uint8Array.from(authData, (b, i) => (i === 33 ? b ^ 1 : b)) : authData; // flip a bit in the counter field of the copy that gets signed
    let signature = await signer.sign(concat(signedAuthData, await sha256(clientDataJSON)));
    if (o.tamperSignature) {
      signature = Uint8Array.from(signature);
      signature[signature.length - 1]! ^= 0x01;
    }
    const id = o.reportedId ?? this.id;
    const userHandle = o.userHandle === undefined ? this.userHandle : o.userHandle;
    return {
      id,
      rawId: id,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        ...(userHandle === null ? {} : { userHandle: b64u(userHandle) }),
      },
    };
  }
}

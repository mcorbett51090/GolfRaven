/**
 * `NativeAttestor`: the `Attestor` over the local Expo module (`modules/golfraven-attest`), and `selectAttestor`, which decides whether it is used at all.
 *
 * SELECTION (`selectAttestor`): the native attestor only where it can work: the module is linked (not Expo Go, not the web, not a binary built without
 * it), the platform says it is supported (an iOS simulator is not), and on Android a Play Cloud project number is configured. Everywhere else the
 * result is `UnattestableAttestor`, with the reason, and a request then carries `hardwareSupportsAttestation: false` and no token.
 *
 * `NativeAttestor` is thin on purpose: it maps the module's `{ ok, code }` results to `AttestResult`, checks shapes, and never throws. It holds no state, hashes
 * nothing and decides nothing about WHEN to attest (`redeemer.ts`).
 *
 * Unverified on a device `[unverified]`: no line of the Swift / Kotlin behind `NativeAttestModule` has run here (no Xcode, no Android toolchain, no Apple or
 * Google account); every behaviour above the module is tested against a fake with the module's documented result shapes.
 */
import { bytesToBase64Url } from "./binding";
import type { NativeAttestModule, NativeResult } from "./native-module";
import type { AttestPlatform, AttestResult, Attestor, UnattestableReason } from "./types";
import { UnattestableAttestor } from "./unattestable";

/** The module's key id: 44 characters of standard base64 ending in one `=` (the server's `KEY_ID_RE`). */
const KEY_ID_RE = /^[A-Za-z0-9+/]{43}=$/;
const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const TOKEN_RE = /^[A-Za-z0-9._~+/=-]+$/;
/** The server's `INSTALL_LINK_RE` (`rewards/request-shape.ts`): an opaque id of 16-128 characters `[A-Za-z0-9._~-]`. */
const INSTALL_LINK_RE = /^[A-Za-z0-9._~-]{16,128}$/;

/** Standard base64 of bytes (the form `NativeAttestModule` takes a hash in). Pure; no `btoa` is needed. */
export function bytesToBase64(bytes: Uint8Array): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += A[b0 >> 2]! + A[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)]!;
    out += b1 === undefined ? "=" : A[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)]!;
    out += b2 === undefined ? "=" : A[b2 & 63]!;
  }
  return out;
}

const MAX_TOKEN_CHARS = 16 * 1024; // the server's bound for an assertion / integrity token (`token-request-shape.ts`)
const MAX_ATTESTATION_CHARS = 24 * 1024; // and for a key attestation (`attest-key-request.ts`)

function isText(v: unknown, re: RegExp): v is string {
  return typeof v === "string" && re.test(v);
}

function failed<T>(message: string, code?: "invalid_key" | "unavailable" | "other"): AttestResult<T> {
  return { kind: "failed", message, ...(code ? { code } : {}) };
}

export class NativeAttestor implements Attestor {
  readonly capability: { platform: AttestPlatform; hardwareSupportsAttestation: boolean };

  constructor(
    private readonly mod: NativeAttestModule,
    platform: "ios" | "android",
    private readonly playCloudProjectNumber: string | null,
  ) {
    // Capability is "this device CAN attest". Whether a given request WILL is decided per request (`redeemer.ts`), which is what the wire claim follows.
    this.capability = { platform, hardwareSupportsAttestation: true };
  }

  /** Maps the module's answer; a rejection from the bridge, a malformed answer and `ok:false` are all `failed` (never a thrown error, never `unattestable`). */
  private async call<T extends object, V>(run: () => Promise<NativeResult<T>>, pick: (r: T) => V | null, what: string): Promise<AttestResult<V>> {
    let r: NativeResult<T>;
    try {
      r = await run();
    } catch (e) {
      return failed(`${what}: the native module failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (typeof r !== "object" || r === null) return failed(`${what}: the native module returned no result`);
    if (!r.ok) {
      if (r.code === "unsupported") return { kind: "unattestable", reason: "platform_unsupported" };
      return failed(`${what}: ${r.message}`, r.code === "invalid_key" ? "invalid_key" : r.code === "unavailable" ? "unavailable" : "other");
    }
    const v = pick(r);
    return v === null ? failed(`${what}: the native module returned a malformed result`) : { kind: "ok", value: v };
  }

  private wrongPlatform<T>(wanted: "ios" | "android"): AttestResult<T> | null {
    return this.capability.platform === wanted ? null : { kind: "unattestable", reason: "platform_unsupported" };
  }

  generateKey(): Promise<AttestResult<{ keyId: string }>> {
    const w = this.wrongPlatform<{ keyId: string }>("ios");
    if (w) return Promise.resolve(w);
    return this.call(() => this.mod.generateKey(), (r) => (isText(r.keyId, KEY_ID_RE) ? { keyId: r.keyId } : null), "generateKey");
  }

  attestKey(keyId: string, clientDataHash: Uint8Array): Promise<AttestResult<{ attestation: string }>> {
    const w = this.wrongPlatform<{ attestation: string }>("ios");
    if (w) return Promise.resolve(w);
    if (clientDataHash.byteLength !== 32) return Promise.resolve(failed("attestKey: clientDataHash must be 32 bytes"));
    return this.call(() => this.mod.attestKey(keyId, bytesToBase64(clientDataHash)), (r) => (isText(r.attestation, B64_RE) && r.attestation.length <= MAX_ATTESTATION_CHARS ? { attestation: r.attestation } : null), "attestKey");
  }

  assert(keyId: string, clientDataHash: Uint8Array): Promise<AttestResult<{ assertion: string }>> {
    const w = this.wrongPlatform<{ assertion: string }>("ios");
    if (w) return Promise.resolve(w);
    if (clientDataHash.byteLength !== 32) return Promise.resolve(failed("assert: clientDataHash must be 32 bytes"));
    return this.call(() => this.mod.generateAssertion(keyId, bytesToBase64(clientDataHash)), (r) => (isText(r.assertion, B64_RE) && r.assertion.length <= MAX_TOKEN_CHARS ? { assertion: r.assertion } : null), "generateAssertion");
  }

  /** iOS DeviceCheck token, for reward activation (P4.2c). Not part of `Attestor`: check-in does not use it. */
  deviceCheckToken(): Promise<AttestResult<{ token: string }>> {
    const w = this.wrongPlatform<{ token: string }>("ios");
    if (w) return Promise.resolve(w);
    return this.call(() => this.mod.deviceCheckToken(), (r) => (isText(r.token, B64_RE) ? { token: r.token } : null), "deviceCheckToken");
  }

  /** Android install link id for reward activation (P4.2b-3b). A binary built before the module had this function answers `unattestable` (the activation then carries no link and is held). */
  installLinkId(): Promise<AttestResult<{ installLinkId: string }>> {
    const w = this.wrongPlatform<{ installLinkId: string }>("android");
    if (w) return Promise.resolve(w);
    if (typeof this.mod.installLinkId !== "function") return Promise.resolve({ kind: "unattestable", reason: "not_implemented" });
    return this.call(() => this.mod.installLinkId(), (r) => (isText(r.installLinkId, INSTALL_LINK_RE) ? { installLinkId: r.installLinkId } : null), "installLinkId");
  }

  integrityToken(requestHash: Uint8Array): Promise<AttestResult<{ integrityToken: string }>> {
    const w = this.wrongPlatform<{ integrityToken: string }>("android");
    if (w) return Promise.resolve(w);
    if (requestHash.byteLength !== 32) return Promise.resolve(failed("integrityToken: requestHash must be 32 bytes"));
    const cloud = this.playCloudProjectNumber;
    if (cloud === null) return Promise.resolve({ kind: "unattestable", reason: "not_configured" });
    return this.call(
      () => this.mod.integrityToken(cloud, bytesToBase64Url(requestHash)),
      (r) => (isText(r.token, TOKEN_RE) && r.token.length <= MAX_TOKEN_CHARS ? { integrityToken: r.token } : null),
      "integrityToken",
    );
  }
}

export interface SelectAttestorInput {
  /** The loaded module, or `null` when it is not linked (`native-module-loader.ts`). */
  module: NativeAttestModule | null;
  /** `Platform.OS`. */
  platform: string;
  /** `EXPO_PUBLIC_PLAY_CLOUD_PROJECT_NUMBER`, parsed (`parsePlayCloudProjectNumber`); `null` = not configured. */
  playCloudProjectNumber: string | null;
}

/** The attestor this build uses on this device: `NativeAttestor` only when it can attest, `UnattestableAttestor` (with the reason) otherwise. Never throws. */
export async function selectAttestor(input: SelectAttestorInput): Promise<Attestor> {
  const { module: mod, platform, playCloudProjectNumber } = input;
  if (mod === null) return new UnattestableAttestor("not_implemented");
  if (platform !== "ios" && platform !== "android") return new UnattestableAttestor("platform_unsupported");
  if (platform === "android" && playCloudProjectNumber === null) return new UnattestableAttestor("not_configured");
  let supported: boolean;
  try {
    supported = (await mod.capability()).supported === true;
  } catch {
    return new UnattestableAttestor("platform_unsupported");
  }
  if (!supported) return new UnattestableAttestor("platform_unsupported" satisfies UnattestableReason);
  return new NativeAttestor(mod, platform, platform === "android" ? playCloudProjectNumber : null);
}

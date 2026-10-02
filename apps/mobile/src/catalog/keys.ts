/**
 * The compiled-in catalog trust anchors (build plan §3.5 "Signing": a
 * `kid`-addressed keyset of at least 2 Ed25519 public keys compiled into
 * the app and the import function; §4.8 rotation).
 *
 * **Intentionally empty in this slice.** Per §3.5 the production keyset is
 * generated under the §4.8 runbook at the P3 pre-build gate, with a second
 * reviewer on the protected signing environment; until then the signer uses
 * a pre-P3 keyset "that no app build ever compiles in". So a build made now
 * verifies NOTHING and — because the verifier fails closed — applies no
 * catalog (every manifest is `UNKNOWN_KID`). That is the correct behaviour
 * before the keyset exists, not a bug. `assertReleaseKeyset` is the gate a
 * release build must pass once keys are added.
 */
import { base64UrlToBytes } from "./bytes";

export interface TrustedKey {
  /** `^[a-z0-9-]{1,64}$`, the manifest's `kid`. */
  kid: string;
  /** The raw 32-byte Ed25519 public key, unpadded base64url (the same
   * convention as `app.catalog_signing_key.public_key_b64url`). */
  publicKeyB64Url: string;
}

export const TRUSTED_KEYSET: readonly TrustedKey[] = [];

const KID_RE = /^[a-z0-9-]{1,64}$/;

/** Throws unless the keyset is releasable: >= 2 distinct, well-formed keys
 * (so a rotation never needs an app release first, §4.8). */
export function assertReleaseKeyset(keys: readonly TrustedKey[]): void {
  const seen = new Set<string>();
  for (const k of keys) {
    if (!KID_RE.test(k.kid)) throw new Error(`keyset: malformed kid "${k.kid}"`);
    if (seen.has(k.kid)) throw new Error(`keyset: duplicate kid "${k.kid}"`);
    seen.add(k.kid);
    let raw: Uint8Array;
    try {
      raw = base64UrlToBytes(k.publicKeyB64Url);
    } catch {
      throw new Error(`keyset: kid "${k.kid}" public key is not unpadded base64url`);
    }
    if (raw.length !== 32) throw new Error(`keyset: kid "${k.kid}" public key is ${raw.length} bytes, want 32`);
  }
  if (seen.size < 2) throw new Error(`keyset: need at least 2 keys for rotation (§4.8), have ${seen.size}`);
}

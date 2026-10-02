/**
 * The two primitives the catalog verifier needs, behind an interface so the
 * verifier itself (`verify.ts`) is pure and testable with any backend.
 *
 * Why not `expo-crypto` / WebCrypto: Hermes has no `crypto.subtle`, and
 * `expo-crypto` offers digests but no Ed25519 verification (checked against
 * the 57.0.3 type definitions, see SPIKE.md). `@noble/curves` +
 * `@noble/hashes` are pure JS, audited, dependency-free, and `@noble/hashes`
 * is already pinned to the same version by `@golfraven/rules`.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "./bytes";

export interface CatalogCrypto {
  /** Lower-case hex SHA-256 of the exact bytes. */
  sha256Hex(bytes: Uint8Array): string;
  /** `false` (never throws) on any malformed key/signature or a bad signature. */
  ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

export const nobleCatalogCrypto: CatalogCrypto = {
  sha256Hex(bytes) {
    return bytesToHex(sha256(bytes));
  },
  ed25519Verify(publicKey, message, signature) {
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    try {
      // zip215:false = RFC 8032 strict verification (rejects non-canonical
      // encodings), the conservative end of the two behaviours; every honest
      // signature from the Node signer verifies under both.
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  },
};

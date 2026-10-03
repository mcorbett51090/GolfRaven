/**
 * The only `Attestor` this build ships (P4.2b-1). It performs no attestation and says so with a typed `unattestable` result for every operation;
 * `capability.hardwareSupportsAttestation` is `false`, so a request that carries no token is graded `unattestable` by the server (G3-08: no token on
 * hardware that does NOT support attestation) rather than `failed`. That is a SELF-REPORT: this build omits the attestation, and it must not claim
 * to be unable on hardware that is able once a native module exists. P4.2b-2 replaces this class (`README.md` "Attestation seam").
 */
import type { AttestResult, Attestor } from "./types";

export class UnattestableAttestor implements Attestor {
  readonly capability = { platform: "none", hardwareSupportsAttestation: false } as const;

  private unattestable<T>(): Promise<AttestResult<T>> {
    return Promise.resolve({ kind: "unattestable", reason: "not_implemented" });
  }
  generateKey(): Promise<AttestResult<{ keyId: string }>> {
    return this.unattestable();
  }
  attestKey(): Promise<AttestResult<{ attestation: string }>> {
    return this.unattestable();
  }
  assert(): Promise<AttestResult<{ assertion: string }>> {
    return this.unattestable();
  }
  integrityToken(): Promise<AttestResult<{ integrityToken: string }>> {
    return this.unattestable();
  }
}

/**
 * The `Attestor` of every build or device that cannot attest (P4.2b-1; since P4.2b-2 the fallback `selectAttestor` returns, see `native.ts`). It performs
 * no attestation and says so with a typed `unattestable` result for every operation; `capability.hardwareSupportsAttestation` is `false`, so a request
 * that carries no token is graded `unattestable` by the server (G3-08: no token on hardware that does NOT support attestation) rather than `failed`.
 */
import type { AttestResult, Attestor, UnattestableReason } from "./types";

export class UnattestableAttestor implements Attestor {
  readonly capability = { platform: "none", hardwareSupportsAttestation: false } as const;

  constructor(readonly reason: UnattestableReason = "not_implemented") {}

  private unattestable<T>(): Promise<AttestResult<T>> {
    return Promise.resolve({ kind: "unattestable", reason: this.reason });
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

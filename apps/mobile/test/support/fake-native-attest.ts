/**
 * A fake of the local Expo module (`NativeAttestModule`): the same result shapes the Swift / Kotlin report, with an event log, scripted failures and a model of App Attest keys
 * (a key can be "destroyed" as a reinstall does). Everything above the module is tested against this; the real Swift / Kotlin are `[unverified]` on a device.
 */
import { createHash } from "node:crypto";
import type { NativeAttestModule, NativeResult } from "../../src/attest/native-module";

export type NativeEvent =
  | { op: "generateKey" }
  | { op: "attestKey"; keyId: string; hashHex: string }
  | { op: "generateAssertion"; keyId: string; hashHex: string }
  | { op: "integrityToken"; cloud: string; requestHash: string }
  | { op: "deviceCheckToken" };

const fail = (code: "unsupported" | "invalid_key" | "unavailable" | "other", message = code): NativeResult<never> => ({ ok: false, code, message });

export class FakeNativeAttestModule implements NativeAttestModule {
  readonly events: NativeEvent[] = [];
  supported = true;
  /** Key ids this fake device holds (a reinstall empties it: `destroyKeys()`). */
  readonly keys = new Set<string>();
  /** Scripted failures: the next call of that op returns this (then it is cleared). */
  next: Partial<Record<"generateKey" | "attestKey" | "generateAssertion" | "integrityToken", NativeResult<never>[]>> = {};
  /** `generateAssertion` waits for this before it answers (to make the platform slow). */
  assertionGate: Promise<void> | null = null;
  /** When set, every call of that op returns this failure, forever. */
  always: Partial<Record<"generateKey" | "attestKey" | "generateAssertion" | "integrityToken", NativeResult<never>>> = {};
  private n = 0;
  private counter = new Map<string, number>();

  private scripted(op: "generateKey" | "attestKey" | "generateAssertion" | "integrityToken"): NativeResult<never> | null {
    const q = this.next[op];
    if (q && q.length > 0) return q.shift()!;
    return this.always[op] ?? null;
  }

  capability(): Promise<{ supported: boolean }> {
    return Promise.resolve({ supported: this.supported });
  }

  generateKey(): Promise<NativeResult<{ keyId: string }>> {
    this.events.push({ op: "generateKey" });
    const s = this.scripted("generateKey");
    if (s) return Promise.resolve(s);
    this.n += 1;
    const keyId = createHash("sha256").update(`fake-key-${this.n}`).digest("base64"); // 44 characters, standard base64, one "="
    this.keys.add(keyId);
    return Promise.resolve({ ok: true, keyId });
  }

  attestKey(keyId: string, hashB64: string): Promise<NativeResult<{ attestation: string }>> {
    this.events.push({ op: "attestKey", keyId, hashHex: Buffer.from(hashB64, "base64").toString("hex") });
    const s = this.scripted("attestKey");
    if (s) return Promise.resolve(s);
    if (!this.keys.has(keyId)) return Promise.resolve(fail("invalid_key"));
    return Promise.resolve({ ok: true, attestation: Buffer.from(`attestation:${keyId}:${hashB64}`).toString("base64") });
  }

  async generateAssertion(keyId: string, hashB64: string): Promise<NativeResult<{ assertion: string }>> {
    this.events.push({ op: "generateAssertion", keyId, hashHex: Buffer.from(hashB64, "base64").toString("hex") });
    if (this.assertionGate) await this.assertionGate;
    const s = this.scripted("generateAssertion");
    if (s) return s;
    if (!this.keys.has(keyId)) return fail("invalid_key");
    const counter = (this.counter.get(keyId) ?? 0) + 1;
    this.counter.set(keyId, counter);
    return { ok: true, assertion: Buffer.from(`assertion:${keyId}:${counter}:${hashB64}`).toString("base64") };
  }

  deviceCheckToken(): Promise<NativeResult<{ token: string }>> {
    this.events.push({ op: "deviceCheckToken" });
    return Promise.resolve({ ok: true, token: Buffer.from("devicecheck").toString("base64") });
  }

  integrityToken(cloud: string, requestHash: string): Promise<NativeResult<{ token: string }>> {
    this.events.push({ op: "integrityToken", cloud, requestHash });
    const s = this.scripted("integrityToken");
    if (s) return Promise.resolve(s);
    return Promise.resolve({ ok: true, token: `it.${requestHash}` });
  }

  /** A reinstall: the Secure Enclave keys are gone. */
  destroyKeys(): void {
    this.keys.clear();
  }

  ops(op?: NativeEvent["op"]): NativeEvent[] {
    return op ? this.events.filter((e) => e.op === op) : this.events;
  }
}

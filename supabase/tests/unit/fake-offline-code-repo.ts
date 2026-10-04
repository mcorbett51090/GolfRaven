// supabase/tests/unit/fake-offline-code-repo.ts
//
// An in-memory `Repo["offlineCode"]` (migration 0045): the same observable contract as private.offline_seed_for_actor (and, as `makeFakeStaffRecorder`, the
// private.offline_code_record_step_for_actor primitive), so the handler and the P5-shaped composition can be unit-tested without a database. The seed comes from the
// independent reference derivation (offline-seed-reference.ts) with a test key held HERE, never in production code. The database-side truth (the real
// function, the real Vault, FORCE RLS, concurrency) is the pgTAP matrix 23_* and the Deno integration suite.

import type { Repo, OfflineStepInput, OfflineStepRecordResult } from "../../functions/_shared/types.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import { OFFLINE_CODE_DB_WINDOW_STEPS, OFFLINE_CODE_STEP_SECONDS } from "../../functions/_shared/offline-code/params.ts";
import type { FakeState } from "./fake-repo.ts";
import { SHIM_OFFLINE_SEED_KEY, deriveSeedReference } from "./offline-seed-reference.ts";

export interface FakeOfflineState {
  /** device id -> { owner, seed version } (the fake's counterpart of app.device.offline_seed_version). Devices default to version 1 on first use. */
  versions: Map<string, number>;
  /** `${deviceId}:${version}:${step}` -> facility (the replay table). */
  steps: Map<string, string>;
  /** staff uid -> facilities where that user holds a staff or manager scope. */
  scopes: Map<string, Set<string>>;
  /** The derivation key; `null` simulates "not provisioned in Vault" (55000 -> 503). */
  key: string | null;
  /** Every call, for assertions. */
  provisionCalls: Array<{ uid: string; deviceId: string; rotate: boolean }>;
}

const states = new WeakMap<FakeState, FakeOfflineState>();

export function offlineState(state: FakeState): FakeOfflineState {
  let s = states.get(state);
  if (!s) {
    s = { versions: new Map(), steps: new Map(), scopes: new Map(), key: SHIM_OFFLINE_SEED_KEY, provisionCalls: [] };
    states.set(state, s);
  }
  return s;
}

export function grantStaffScope(state: FakeState, uid: string, facilityId: string): void {
  const o = offlineState(state);
  const set = o.scopes.get(uid) ?? new Set<string>();
  set.add(facilityId);
  o.scopes.set(uid, set);
}

export function makeFakeOfflineCodeRepo(state: FakeState, uid: string): Repo["offlineCode"] {
  const o = offlineState(state);
  return {
    async provisionSeed(deviceId, rotate) {
      o.provisionCalls.push({ uid, deviceId, rotate });
      const row = state.devices.get(deviceId);
      if (!row || row.userId !== uid) return null; // not the caller's: the same answer as nonexistent
      if (o.key === null) {
        throw new HttpError(503, "offline_seed_unavailable", "offline codes are not available right now");
      }
      const current = o.versions.get(deviceId) ?? 1;
      const version = rotate ? current + 1 : current;
      o.versions.set(deviceId, version);
      return { seed: await deriveSeedReference(o.key, uid, deviceId, version), seedVersion: version, issuedAt: state.now.toISOString() };
    },
  };
}

/** The staff lane's replay record: the in-memory model of the DATABASE primitive private.offline_code_record_step_for_actor, which since 0047 (X9) is not a Repo
 * method (edge_actor cannot execute it). It stays here because the unit tests compose it with verifyOfflineCode the way S3's partner definer will; the real
 * primitive's proofs are 23_offline_totp_seed_record.sql and the Deno integration suite. */
export function makeFakeStaffRecorder(state: FakeState, uid: string): { recordStep(input: OfflineStepInput): Promise<OfflineStepRecordResult> } {
  const o = offlineState(state);
  return {
    async recordStep(input: OfflineStepInput): Promise<OfflineStepRecordResult> {
      if (!o.scopes.get(uid)?.has(input.facilityId)) throw new HttpError(403, "forbidden", "you hold no staff scope at that facility");
      const row = state.devices.get(input.deviceId);
      if (!row) return "no_such_device";
      if (row.userId === uid) throw new HttpError(422, "self_attestation_refused", "a staff member cannot attest their own account");
      if (input.seedVersion !== (o.versions.get(input.deviceId) ?? 1)) return "stale_seed_version";
      const nowStep = Math.floor(state.now.getTime() / 1000 / OFFLINE_CODE_STEP_SECONDS);
      if (Math.abs(input.step - nowStep) > OFFLINE_CODE_DB_WINDOW_STEPS) return "step_out_of_window";
      const key = `${input.deviceId}:${input.seedVersion}:${input.step}`;
      if (o.steps.has(key)) return "replayed";
      o.steps.set(key, input.facilityId);
      return "recorded";
    },
  };
}

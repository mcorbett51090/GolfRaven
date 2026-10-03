// supabase/tests/integration/device-platform.deno.test.ts
//
// 0042: the platform of a device first seen without one stays UNKNOWN (NULL) until its first platform-bearing use; the first wins. The REAL
// handlers through the REAL `withOwnership` / `Repo` against the harness cluster, in BOTH harness modes. The bug this closes: an Android device first
// seen at checkin-challenge was stored as 'ios', and rewards-activate then answered 422 platform_mismatch to its Android activation.

import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, freshUuid, makeActor, FAC_X } from "./_helpers.ts";
import { withOwnership } from "../../functions/_shared/privileged.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleActivation } from "../../functions/_shared/rewards/activate-handler.ts";
import { toHex } from "../../functions/_shared/rewards/binding.ts";
import type { ActivationRequest } from "../../functions/_shared/rewards/request-shape.ts";
import type { AttestationPorts } from "../../functions/_shared/rewards/types.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import { sha256 } from "../unit/rewards-test-crypto.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));
const noPorts: AttestationPorts = { ios: null, android: null };

async function freshUser(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `pf-${label}-${uid.slice(0, 8)}`);
  return { uid, actor: makeActor(uid) };
}
type User = Awaited<ReturnType<typeof freshUser>>;

/** The device is first seen the way a real client first shows it: at POST /v1/checkin/challenge, which carries no platform. */
async function firstSeenAtChallenge(u: User): Promise<string> {
  const deviceId = freshUuid();
  await withOwnership(u.actor, (repo: Repo) => handleChallengeRequest({ deviceId }, repo, randomBytes, digestHex));
  return deviceId;
}
const platformOf = async (deviceId: string) => (await adminSql()`select platform from app.device where id = ${deviceId}`)[0]!.platform as string | null;

async function newCode(u: User): Promise<string> {
  const offerId = freshUuid();
  const id = freshUuid();
  await adminSql()`set role service_role`;
  await adminSql()`
    insert into app.offer (id, trail_id, facility_id, eligibility, funder, budget_cap, face_value, valid_from, valid_to, status)
    values (${offerId}, 'trl_t', ${FAC_X}, '{}'::jsonb, 'operator', 100, 10, current_date, current_date + 30, 'live')`;
  await adminSql()`
    insert into app.offer_code (id, offer_id, user_id, facility_id, state, earned_at, expires_at)
    values (${id}, ${offerId}, ${u.uid}, ${FAC_X}, 'earned', now() - interval '10 days', now() + interval '20 days')`;
  return id;
}
const noneReq = (deviceId: string, platform: "ios" | "android"): ActivationRequest => ({ deviceId, platform, attestation: { kind: "none", hardwareSupportsAttestation: false } });
async function activate(u: User, deviceId: string, platform: "ios" | "android"): Promise<string | null> {
  const id = await newCode(u);
  try {
    await withOwnership(u.actor, (repo: Repo) => handleActivation(id, noneReq(deviceId, platform), repo, { ports: noPorts, sha256 }));
    return null;
  } catch (e) {
    if (e instanceof HttpError) return `${e.status} ${e.code}`;
    throw e;
  }
}

Deno.test("device-platform: a device first seen at checkin-challenge has an UNKNOWN platform (NULL), not 'ios'", DT, async () => {
  const u = await freshUser("unknown");
  assertEquals(await platformOf(await firstSeenAtChallenge(u)), null);
});

Deno.test("device-platform: an Android device first seen at checkin-challenge, then activated on Android, is NOT refused; it is Android afterwards", DT, async () => {
  const u = await freshUser("android");
  const dev = await firstSeenAtChallenge(u);
  assertEquals(await activate(u, dev, "android"), null);
  assertEquals(await platformOf(dev), "android");
  // first wins: a later iOS activation is refused
  assertEquals(await activate(u, dev, "ios"), "422 platform_mismatch");
  assertEquals(await platformOf(dev), "android");
});

Deno.test("device-platform: an unknown device activated as iOS becomes iOS; an Android activation is then refused", DT, async () => {
  const u = await freshUser("ios");
  const dev = await firstSeenAtChallenge(u);
  assertEquals(await activate(u, dev, "ios"), null);
  assertEquals(await platformOf(dev), "ios");
  assertEquals(await activate(u, dev, "android"), "422 platform_mismatch");
});

Deno.test("device-platform: a device first seen as iOS (ensureOwn with a platform, as attest-key / push-token callers do) is still refused an Android activation", DT, async () => {
  const u = await freshUser("ios-first");
  const dev = await withOwnership(u.actor, async (repo: Repo) => (await repo.device.ensureOwn(freshUuid(), "ios")).id);
  assertEquals(await platformOf(dev), "ios");
  assertEquals(await activate(u, dev, "android"), "422 platform_mismatch");
  assertEquals(await platformOf(dev), "ios");
});

Deno.test("device-platform: claimPlatform is first-wins and actor-scoped through the real definer", DT, async () => {
  const a = await freshUser("claim-a");
  const b = await freshUser("claim-b");
  const dev = await firstSeenAtChallenge(a);
  assertEquals(await withOwnership(b.actor, (repo: Repo) => repo.device.claimPlatform(dev, "android")), null, "another account's device: null, nothing set");
  assertEquals(await platformOf(dev), null);
  assertEquals(await withOwnership(a.actor, (repo: Repo) => repo.device.claimPlatform(dev, "android")), "android");
  assertEquals(await withOwnership(a.actor, (repo: Repo) => repo.device.claimPlatform(dev, "ios")), "android");
  assertEquals(await platformOf(dev), "android");
});

Deno.test("device-platform: a refused activation rolls its claim back with the rest of the transaction", DT, async () => {
  const u = await freshUser("rollback");
  const dev = await firstSeenAtChallenge(u);
  // a reward that does not exist: the 404 comes BEFORE the platform is looked at, so nothing is claimed
  try {
    await withOwnership(u.actor, (repo: Repo) => handleActivation(freshUuid(), noneReq(dev, "android"), repo, { ports: noPorts, sha256 }));
  } catch (e) {
    assertEquals((e as HttpError).status, 404);
  }
  assertEquals(await platformOf(dev), null);
});

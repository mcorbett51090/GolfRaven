// supabase/tests/integration/offline-code.deno.test.ts
//
// P4.2b-3a: the offline staff code against the REAL database. The REAL handler (_shared/me/offline-seed-handler.ts), the REAL Repo built by privileged.ts
// (every call is `SET LOCAL ROLE edge_actor` + a bound actor), the REAL Vault-keyed derivation (private.offline_seed_derive, which no TypeScript can reach)
// and the REAL replay table, in the harness cluster tools/db/test.sh builds. The derivation is checked against an INDEPENDENT reference
// (../unit/offline-seed-reference.ts: the shim's K, written without the database function).
//
// What only a real database can show: provisioning for the caller's own device works and another account's is refused; the seed is deterministic for
// (user, device, version) and differs with each of the three; K cannot be reached; recording a used step is ATOMIC under concurrency (N parallel staff
// requests for one step: exactly one `recorded`); a rotation invalidates; deletion removes the rows; the export carries no seed.

import { assert, assertEquals, assertNotEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, makeActor, rawCount } from "./_helpers.ts";
import { hitRateLimitForActor, openScopedTx, userBind, withOwnership } from "../../functions/_shared/privileged.ts";
import { handleOfflineSeedRequest } from "../../functions/_shared/me/offline-seed-handler.ts";
import { OFFLINE_SEED_REVEAL_BUCKET, OFFLINE_SEED_REVEAL_PER_HOUR, OFFLINE_CODE_STEP_SECONDS } from "../../functions/_shared/offline-code/params.ts";
import { base32Decode, hotp, stepOf } from "../../functions/_shared/offline-code/totp.ts";
import { verifyOfflineCode } from "../../functions/_shared/offline-code/verify.ts";
import { HttpError } from "../../functions/_shared/http.ts";
import type { Repo } from "../../functions/_shared/types.ts";
import type postgres from "postgres";
import { SHIM_OFFLINE_SEED_KEY, deriveSeedReference, toHex } from "../unit/offline-seed-reference.ts";

type TxSql = postgres.TransactionSql;
const DT = { sanitizeOps: false, sanitizeResources: false };

// helpers.sql's principals: staff-x (staff at fac_x), staff-y (staff at fac_y).
const STAFF_X = "00000000-0000-0000-0000-1000000000a1";
const STAFF_Y = "00000000-0000-0000-0000-1000000000a3";
const FAC_X = "fac_x";

async function freshPlayer(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `oc-${label}-${uid.slice(0, 8)}`);
  const actor = makeActor(uid);
  const deviceId = freshUuid();
  await withOwnership(actor, (repo: Repo) => repo.device.ensureOwn(deviceId, "android"));
  return { uid, actor, deviceId };
}
type Player = Awaited<ReturnType<typeof freshPlayer>>;

const provision = (p: Player, rotate = false, deviceId = p.deviceId) => withOwnership(p.actor, (repo: Repo) => handleOfflineSeedRequest({ deviceId, rotate }, repo));
const nowStep = () => stepOf(Date.now() / 1000);
const record = (staffUid: string, deviceId: string, seedVersion: number, step: number, facilityId = FAC_X) =>
  withOwnership(makeActor(staffUid), (repo: Repo) => repo.offlineCode.recordStep({ deviceId, seedVersion, step, facilityId }));
async function httpError(p: Promise<unknown>): Promise<HttpError | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return e;
    throw e;
  }
}

Deno.test("provisioning: the caller's own device returns the seed the independent reference derives (user, device, version 1)", DT, async () => {
  const p = await freshPlayer("own");
  const res = await provision(p);
  assertEquals(res.seedVersion, 1);
  assertEquals(res.stepSeconds, 600);
  assertEquals(res.digits, 6);
  assertEquals(res.algorithm, "SHA256");
  assert(/^[A-Z2-7]{52}$/.test(res.seed));
  assert(Math.abs(Date.parse(res.issuedAt) - Date.now()) < 60_000, "issuedAt is the server clock");
  assertEquals(toHex(base32Decode(res.seed)), toHex(await deriveSeedReference(SHIM_OFFLINE_SEED_KEY, p.uid, p.deviceId, 1)), "the database derivation equals the independent one");
});

Deno.test("provisioning: deterministic for (user, device, version), and different for another device, another user, another version", DT, async () => {
  const a = await freshPlayer("det-a");
  const b = await freshPlayer("det-b");
  const second = freshUuid();
  await withOwnership(a.actor, (repo: Repo) => repo.device.ensureOwn(second, "ios"));
  const a1 = await provision(a);
  assertEquals((await provision(a)).seed, a1.seed, "re-provisioning returns the SAME seed");
  const aOther = await provision(a, false, second);
  const bSeed = await provision(b);
  const rotated = await provision(a, true);
  assertEquals(new Set([a1.seed, aOther.seed, bSeed.seed, rotated.seed]).size, 4, "device, user and version each change the seed");
  assertEquals(rotated.seedVersion, 2);
  assertEquals(toHex(base32Decode(rotated.seed)), toHex(await deriveSeedReference(SHIM_OFFLINE_SEED_KEY, a.uid, a.deviceId, 2)));
  assertEquals((await provision(a)).seed, rotated.seed, "after the rotation a plain call returns the NEW seed");
});

Deno.test("provisioning: another account's device is a 404 (the same as a device that does not exist), and cannot be rotated", DT, async () => {
  const a = await freshPlayer("own-a");
  const b = await freshPlayer("own-b");
  const foreign = await httpError(provision(b, false, a.deviceId));
  assertEquals(foreign?.status, 404);
  const missing = await httpError(provision(b, false, freshUuid()));
  assertEquals(missing?.status, 404);
  assertEquals(missing?.code, foreign?.code, "no oracle: a foreign device and a missing one answer identically");
  assertEquals((await httpError(provision(b, true, a.deviceId)))?.status, 404);
  const rows = await adminSql()`select offline_seed_version from app.device where id = ${a.deviceId}`;
  assertEquals(rows[0]!.offline_seed_version, 1, "A's device was not rotated by B's attempt");
});

Deno.test("provisioning never creates a device row", DT, async () => {
  const a = await freshPlayer("nocreate");
  const ghost = freshUuid();
  assertEquals((await httpError(provision(a, false, ghost)))?.status, 404);
  assertEquals(await rawCount(`select count(*)::int as n from app.device where id = '${ghost}'`), 0);
});

Deno.test("K: as the real edge_actor, the Vault, the derivation core and the replay table are out of reach; only the two wrappers answer", DT, async () => {
  const p = await freshPlayer("k");
  const refusedWith = async (run: (trx: TxSql) => Promise<unknown>): Promise<string> => {
    try {
      await openScopedTx("actor", userBind(p.uid), run);
    } catch (e) {
      return String((e as { code?: unknown }).code);
    }
    return "no error";
  };
  assertEquals(await refusedWith((trx) => trx`select decrypted_secret from vault.decrypted_secrets where name = 'offline_seed_key'`), "42501", "the Vault is not readable");
  assertEquals(await refusedWith((trx) => trx`select private.offline_seed_derive(${p.uid}::uuid, ${p.deviceId}::uuid, 1)`), "42501", "the derivation core is not callable");
  assertEquals(await refusedWith((trx) => trx`select count(*) from app.offline_code_step`), "42501", "the replay table is not readable");
  assertEquals(await refusedWith((trx) => trx`update app.device set offline_seed_version = 9 where id = ${p.deviceId}`), "42501", "the version is not writable");
  // control: the wrapper answers, and the seed is a function RESULT whose derivation the caller cannot see or redo
  const ok = await openScopedTx("actor", userBind(p.uid), (trx) => trx`select octet_length(o_seed) as n from private.offline_seed_for_actor(${p.deviceId}::uuid, false)`);
  assertEquals(ok[0]!.n, 32);
  // and a seed response never carries the key
  assert(!JSON.stringify(await provision(p)).includes(SHIM_OFFLINE_SEED_KEY));
});

Deno.test("recordStep: atomic under concurrency: N parallel staff requests for ONE step give exactly one `recorded`, the rest `replayed`, one row", DT, async () => {
  const p = await freshPlayer("race");
  const { seedVersion } = await provision(p);
  const step = nowStep();
  const N = 12;
  const results = await Promise.all(Array.from({ length: N }, () => record(STAFF_X, p.deviceId, seedVersion, step)));
  assertEquals(results.filter((r) => r === "recorded").length, 1, `exactly one of ${N} concurrent records wins: ${JSON.stringify(results)}`);
  assertEquals(results.filter((r) => r === "replayed").length, N - 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.offline_code_step where device_id = '${p.deviceId}' and seed_version = ${seedVersion} and step = ${step}`), 1);
  // different steps in parallel do not collide
  const steps = [step - 1, step + 1, step + 2];
  const more = await Promise.all(steps.map((s) => record(STAFF_X, p.deviceId, seedVersion, s)));
  assertEquals(more, ["recorded", "recorded", "recorded"]);
});

Deno.test("recordStep: concurrent staff at TWO facilities racing on one step still produce exactly one winner", DT, async () => {
  const p = await freshPlayer("race2");
  const step = nowStep();
  const results = await Promise.all([
    ...Array.from({ length: 6 }, () => record(STAFF_X, p.deviceId, 1, step, "fac_x")),
    ...Array.from({ length: 6 }, () => record(STAFF_Y, p.deviceId, 1, step, "fac_y")),
  ]);
  assertEquals(results.filter((r) => r === "recorded").length, 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.offline_code_step where device_id = '${p.deviceId}'`), 1);
});

Deno.test("recordStep: statuses, scope and self-attestation through the real Repo", DT, async () => {
  const p = await freshPlayer("status");
  const step = nowStep();
  assertEquals(await record(STAFF_X, p.deviceId, 1, step), "recorded");
  assertEquals(await record(STAFF_X, p.deviceId, 1, step), "replayed");
  assertEquals(await record(STAFF_X, p.deviceId, 2, step), "stale_seed_version");
  assertEquals(await record(STAFF_X, p.deviceId, 1, step + 20), "step_out_of_window");
  assertEquals(await record(STAFF_X, freshUuid(), 1, step), "no_such_device");
  // scope: staff-y holds no scope at fac_x; a plain player holds none anywhere
  assertEquals((await httpError(record(STAFF_Y, p.deviceId, 1, step, "fac_x")))?.status, 403);
  assertEquals((await httpError(record(p.uid, p.deviceId, 1, step, "fac_x")))?.status, 403);
  // an ADMIN passes the scope check for any facility string; a facility that does not exist is a clean 422, not an opaque failure at COMMIT
  const unknown = await httpError(record("00000000-0000-0000-0000-4000000000d0", p.deviceId, 1, step + 1, "fac_does_not_exist"));
  assertEquals(unknown?.status, 422);
  assertEquals(unknown?.code, "unknown_facility");
  assertEquals(await rawCount(`select count(*)::int as n from app.offline_code_step where facility_id = 'fac_does_not_exist'`), 0);
  // a staff member's OWN device: 422 self_attestation_refused
  const own = freshUuid();
  await withOwnership(makeActor(STAFF_X), (repo: Repo) => repo.device.ensureOwn(own, "android"));
  const self = await httpError(record(STAFF_X, own, 1, step));
  assertEquals(self?.status, 422);
  assertEquals(self?.code, "self_attestation_refused");
  await ensureServiceRole();
  await adminSql()`delete from app.device where id = ${own}`;
});

Deno.test("the full chain: provision -> the device computes the code offline -> staff verifies -> atomic record -> replay refused -> rotation invalidates", DT, async () => {
  const p = await freshPlayer("chain");
  const issued = await provision(p);
  const device = async (seedB32: string, t: number) => hotp(base32Decode(seedB32), stepOf(t));
  // P5's staff lane derives the player's seed in the database; until that definer exists the reference stands in for it (the provisioning test above proved
  // the reference IS the database's derivation).
  const staffSeed = (version: number) => deriveSeedReference(SHIM_OFFLINE_SEED_KEY, p.uid, p.deviceId, version);
  const typed = await device(issued.seed, Date.now() / 1000);
  const verdict = await verifyOfflineCode({ seed: await staffSeed(issued.seedVersion), code: typed, now: new Date() });
  assert(verdict.ok, JSON.stringify(verdict));
  assertEquals(await record(STAFF_X, p.deviceId, issued.seedVersion, verdict.ok ? verdict.step : -1), "recorded");
  assertEquals(await record(STAFF_X, p.deviceId, issued.seedVersion, verdict.ok ? verdict.step : -1), "replayed", "the same code, again: refused");
  // rotation: the OLD seed's code no longer verifies against the NEW seed, and a record at the old version is refused
  const rotated = await provision(p, true);
  assertEquals(rotated.seedVersion, 2);
  assertEquals((await verifyOfflineCode({ seed: await staffSeed(2), code: typed, now: new Date() })).ok, false, "an old seed's code is refused after rotation");
  assertEquals(await record(STAFF_X, p.deviceId, 1, nowStep() + 1), "stale_seed_version");
  const fresh = await device(rotated.seed, Date.now() / 1000);
  const v2 = await verifyOfflineCode({ seed: await staffSeed(2), code: fresh, now: new Date() });
  assert(v2.ok);
  assertEquals(await record(STAFF_X, p.deviceId, 2, v2.ok ? v2.step : -1), "recorded", "the same step of the NEW seed is a different code and is accepted once");
});

Deno.test("rotation under concurrency: parallel rotations get distinct, increasing versions", DT, async () => {
  const p = await freshPlayer("rotate-race");
  const results = await Promise.all(Array.from({ length: 6 }, () => provision(p, true)));
  const versions = results.map((r) => r.seedVersion).sort((x, y) => x - y);
  assertEquals(versions, [2, 3, 4, 5, 6, 7], "each rotation is its own version");
  assertEquals(new Set(results.map((r) => r.seed)).size, 6);
  assertEquals((await provision(p)).seedVersion, 7);
});

Deno.test("seed reveal is rate-limited: the 21st call in the window is refused (the bucket the endpoint hits before withOwnership)", DT, async () => {
  const p = await freshPlayer("limit");
  const outcomes: boolean[] = [];
  for (let i = 0; i < OFFLINE_SEED_REVEAL_PER_HOUR + 1; i++) outcomes.push((await hitRateLimitForActor(p.actor, OFFLINE_SEED_REVEAL_BUCKET, 3_600, OFFLINE_SEED_REVEAL_PER_HOUR)).ok);
  assertEquals(outcomes.slice(0, OFFLINE_SEED_REVEAL_PER_HOUR).every(Boolean), true);
  assertEquals(outcomes[OFFLINE_SEED_REVEAL_PER_HOUR], false);
  // the limit is per actor
  const q = await freshPlayer("limit-other");
  assertEquals((await hitRateLimitForActor(q.actor, OFFLINE_SEED_REVEAL_BUCKET, 3_600, OFFLINE_SEED_REVEAL_PER_HOUR)).ok, true);
});

Deno.test("a missing derivation key is a 503 offline_seed_unavailable (nothing from the database on the wire), and the key's return restores service", DT, async () => {
  const p = await freshPlayer("nokey");
  await ensureServiceRole();
  const sql = adminSql();
  const saved = await sql`select id, name, secret from vault.secrets where name = 'offline_seed_key'`;
  assertEquals(saved.length, 1, "the harness seeded the key");
  const row = saved[0]!;
  try {
    await sql`delete from vault.secrets where name = 'offline_seed_key'`;
    const err = await httpError(provision(p));
    assertEquals(err?.status, 503);
    assertEquals(err?.code, "offline_seed_unavailable");
    assert(!/vault|offline_seed_key|secret|55000/i.test(err!.message), `message names nothing: ${err!.message}`);
  } finally {
    await sql`insert into vault.secrets (id, name, secret) values (${row.id}, ${row.name}, ${row.secret}) on conflict (name) do nothing`;
  }
  assertEquals((await provision(p)).seedVersion, 1, "with the key back, provisioning works again");
});

Deno.test("deletion and export: the replay rows are exported to their subject (never a seed) and deleted with the account", DT, async () => {
  const p = await freshPlayer("lifecycle");
  const other = await freshPlayer("lifecycle-other");
  const issued = await provision(p);
  const step = nowStep();
  assertEquals(await record(STAFF_X, p.deviceId, 1, step), "recorded");
  assertEquals(await record(STAFF_X, other.deviceId, 1, step), "recorded");

  const exported = await withOwnership(p.actor, (repo: Repo) => repo.me.exportMyData());
  const steps = exported["offline_code_step"] as Array<Record<string, unknown>>;
  assertEquals(steps.length, 1);
  assertEquals(Object.keys(steps[0]!).sort(), ["device_id", "facility_id", "seed_version", "step", "used_at", "user_id"]);
  assertEquals(steps[0]!.device_id, p.deviceId);
  assertEquals(steps[0]!.facility_id, FAC_X);
  const device = (exported["device"] as Array<Record<string, unknown>>).find((d) => d.id === p.deviceId)!;
  assertEquals(device.offline_seed_version, 1);
  const text = JSON.stringify(exported);
  assert(!text.includes(issued.seed), "the base32 seed is not in the export");
  assert(!text.includes(toHex(base32Decode(issued.seed))), "nor its hex");
  assert(!text.includes(SHIM_OFFLINE_SEED_KEY), "nor the key");

  await withOwnership(p.actor, (repo: Repo) => repo.me.deleteMyData());
  assertEquals(await rawCount(`select count(*)::int as n from app.offline_code_step where user_id = '${p.uid}'`), 0, "the account's replay rows are gone");
  assertEquals(await rawCount(`select count(*)::int as n from app.offline_code_step where user_id = '${other.uid}'`), 1, "another account's are untouched");
});

Deno.test("the step arithmetic the database and the TypeScript core share: a step is floor(unix seconds / 600)", DT, async () => {
  const rows = await adminSql()`select floor(extract(epoch from clock_timestamp()) / 600)::bigint as s`;
  assert(Math.abs(Number(rows[0]!.s) - nowStep()) <= 1);
  assertEquals(OFFLINE_CODE_STEP_SECONDS, 600);
  assertNotEquals(nowStep(), 0);
});

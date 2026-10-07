// supabase/tests/integration/review-account.deno.test.ts
//
// 0051, the App Store review account, through the REAL `getActorFromRequest` (the one choke point every authenticated Edge Function passes through), the REAL
// privileged.ts and the harness cluster, as edge_system / edge_actor. GoTrue is the only stand-in: a local HTTP stub answers `GET /auth/v1/user` (the call
// `auth.getUser` makes) for a token the test builds at RUNTIME (nothing token-shaped is committed). Proved here:
//   1. outside every window a review-account request is 403 `review_account_disabled`, through `handleRequest` (the way every entrypoint wraps it), and the audit row PERSISTS
//      after the refusal (a status, not a RAISE: the 0020 lesson); a second request under the same session adds no row, a new session adds one;
//   2. inside a window the same account is let through (Actor returned), with ONE `session_allowed` row per session;
//   3. the window ENDING (its end moves to the past) disables the very next request;
//   4. an ordinary account is never audited and never refused, in or out of a window;
//   5. the database backstop: `withOwnership` for a disabled review account fails at the binder even if a caller skipped the gate;
//   6. the audit rows carry no email, no token and no address;
//   7. FAIL CLOSED (review LOW-2 / LOW-3): when the gate cannot read the window, or cannot write the audit row, the review account's request is refused with a server error and NEVER let through,
//      while an ordinary account is unaffected;
//   8. the gate's overhead for ordinary accounts (review LOW-4): measured with and without the in-process negative cache; the review account is asked on EVERY request, never cached.
// The reward 403 for the review account (inside a window) is rewards-activate.deno.test.ts.

import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawOwnerSql } from "./_helpers.ts";
import { getActorFromRequest, resetReviewGateCacheForTests, reviewGateDbCallsForTests, setReviewGateClockForTests, withOwnership } from "../../functions/_shared/privileged.ts";
import { errorResponse, handleRequest, HttpError } from "../../functions/_shared/http.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

function b64url(o: unknown): string {
  return btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/** A JWT-shaped token built at runtime: the stub reads `sub`, the gate reads `session_id`. Never verified (the stub plays GoTrue). */
function tokenFor(uid: string, sessionId: string | null): string {
  return `${b64url({ alg: "none", typ: "JWT" })}.${b64url(sessionId === null ? { sub: uid } : { sub: uid, session_id: sessionId })}.${b64url("x")}`;
}

// A local stand-in for GoTrue's `GET /auth/v1/user`: the bearer's `sub` is the user it answers with.
let stubCalls = 0; // how many times "GoTrue" was asked
const server = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen: () => {} }, (req) => {
  stubCalls++;
  const auth = req.headers.get("authorization") ?? "";
  const parts = auth.slice(7).split(".");
  try {
    const sub = JSON.parse(atob(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"))).sub as string;
    return new Response(JSON.stringify({ id: sub, aud: "authenticated", role: "authenticated", app_metadata: {}, user_metadata: {}, created_at: new Date().toISOString() }), {
      headers: { "content-type": "application/json" },
    });
  } catch {
    return new Response(JSON.stringify({ message: "bad token" }), { status: 401, headers: { "content-type": "application/json" } });
  }
});
const savedEnv = { url: Deno.env.get("SUPABASE_URL"), anon: Deno.env.get("SUPABASE_ANON_KEY") };
Deno.env.set("SUPABASE_URL", `http://127.0.0.1:${(server.addr as Deno.NetAddr).port}`);
Deno.env.set("SUPABASE_ANON_KEY", "review-account-test-anon");

function req(token: string): Request {
  return new Request("http://edge.test/v1/anything", { method: "POST", headers: { authorization: `Bearer ${token}` } });
}
/** What every entrypoint does: getActorFromRequest inside handleRequest (an HttpError becomes its own response). */
async function entry(token: string): Promise<Response> {
  return await handleRequest(async () => {
    const actor = await getActorFromRequest(req(token));
    if (!actor) return errorResponse(401, "unauthorized", "missing or invalid Authorization token");
    return new Response(JSON.stringify({ data: { uid: actor.uid } }), { status: 200 });
  });
}

async function reviewUser(label: string): Promise<string> {
  const uid = freshUuid();
  await createTestUser(uid, `rv-${label}-${uid.slice(0, 8)}`);
  await ensureServiceRole();
  // at most ONE review account exists (0051, unique index): this test's replaces the previous one (the earlier account becomes an ordinary one)
  await adminSql()`delete from app.app_review_demo_account where retired_at is null`;
  await adminSql()`insert into app.app_review_demo_account (user_id) values (${uid})`;
  return uid;
}
async function openWindow(startOffset: string, endOffset: string): Promise<string> {
  await ensureServiceRole();
  const rows = await adminSql()`insert into app.app_review_window (starts_at, ends_at, note) values (now() + ${startOffset}::interval, now() + ${endOffset}::interval, 'integration') returning id`;
  return rows[0]!.id as string;
}
async function dropWindow(id: string): Promise<void> {
  await ensureServiceRole();
  await adminSql()`delete from app.app_review_window where id = ${id}`;
}
async function auditRows(uid: string): Promise<Array<{ action: string; subject_id: string | null; subject_table: string | null; detail: unknown }>> {
  await ensureServiceRole();
  return (await adminSql()`select action, subject_id, subject_table, detail from app.audit_log where actor_user_id = ${uid} order by created_at, id`) as never;
}
async function noWindowsAtAll(): Promise<void> {
  await ensureServiceRole();
  // the suite's windows are all removed by their own test; a stray one would make "outside every window" meaningless here
  const n = (await adminSql()`select count(*)::int as n from app.app_review_window where now() >= starts_at and now() < ends_at`)[0]!.n as number;
  assertEquals(n, 0, "no window may be open when a test starts");
}

Deno.test("review account: outside every window a request is 403 review_account_disabled, and the audit row PERSISTS after the refusal", DT, async () => {
  await noWindowsAtAll();
  const uid = await reviewUser("closed");
  const s1 = freshUuid();
  const res = await entry(tokenFor(uid, s1));
  assertEquals(res.status, 403);
  assertEquals((await res.json()).error.code, "review_account_disabled");
  // committed with the refusal, not rolled back
  let rows = await auditRows(uid);
  assertEquals(rows.length, 1);
  assertEquals(rows[0]!.action, "review_account.session_refused");
  assertEquals(rows[0]!.subject_id, s1);
  assertEquals(rows[0]!.subject_table, "auth_session");
  // same session again: refused again, nothing more written (dedupe per session)
  assertEquals((await entry(tokenFor(uid, s1))).status, 403);
  assertEquals((await auditRows(uid)).length, 1);
  // a NEW session: its own row
  assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 403);
  rows = await auditRows(uid);
  assertEquals(rows.length, 2);
  // a token with no readable session id: audited on every request
  assertEquals((await entry(tokenFor(uid, null))).status, 403);
  assertEquals((await entry(tokenFor(uid, null))).status, 403);
  assertEquals((await auditRows(uid)).length, 4);
  // minimal data: the outcome, the session id, the actor; no email, token or address
  for (const r of await auditRows(uid)) {
    assertEquals(r.detail, { outcome: "refused" });
    assert(!JSON.stringify(r).match(/@|bearer|eyJ/i), "an audit row holds no email, token or address");
  }
});

Deno.test("review account: inside a window the request passes, with one session_allowed row per session; the window ending disables the next request", DT, async () => {
  await noWindowsAtAll();
  const uid = await reviewUser("open");
  const s1 = freshUuid();
  const w = await openWindow("-1 hour", "1 hour");
  try {
    const res = await entry(tokenFor(uid, s1));
    assertEquals(res.status, 200);
    assertEquals((await res.json()).data.uid, uid);
    assertEquals((await entry(tokenFor(uid, s1))).status, 200);
    assertEquals((await auditRows(uid)).filter((r) => r.action === "review_account.session_allowed" && r.subject_id === s1).length, 1);
    // the window ENDS (its end moves to the past; its start is an hour ago so the CHECK holds): the very next request is refused
    await ensureServiceRole();
    await adminSql()`update app.app_review_window set ends_at = now() - interval '1 second' where id = ${w}`;
    const res2 = await entry(tokenFor(uid, s1));
    assertEquals(res2.status, 403);
    assertEquals((await res2.json()).error.code, "review_account_disabled");
    const rows = await auditRows(uid);
    assertEquals(rows.filter((r) => r.action === "review_account.session_allowed").length, 1, "the allowed row stays");
    assertEquals(rows.filter((r) => r.action === "review_account.session_refused" && r.subject_id === s1).length, 1, "and the refusal is its own row");
  } finally {
    await dropWindow(w);
  }
});

Deno.test("review account: a window in the past or the future is not a window (outside every window)", DT, async () => {
  await noWindowsAtAll();
  const uid = await reviewUser("offwin");
  const past = await openWindow("-3 days", "-2 days");
  const future = await openWindow("2 days", "3 days");
  try {
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 403);
  } finally {
    await dropWindow(past);
    await dropWindow(future);
  }
});

Deno.test("a RETIRED review account is refused ALWAYS, with a window OPEN: a 403, an audit row, and no actor-bound transaction; retired cannot be undone", DT, async () => {
  await noWindowsAtAll();
  resetReviewGateCacheForTests();
  const uid = await reviewUser("retired");
  const w = await openWindow("-1 hour", "1 hour");
  try {
    await ensureServiceRole();
    // control: while ACTIVE, the open window lets it through
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
    await adminSql()`update app.app_review_demo_account set retired_at = now() where user_id = ${uid}`;
    const s1 = freshUuid();
    const res = await entry(tokenFor(uid, s1));
    assertEquals(res.status, 403);
    assertEquals((await res.json()).error.code, "review_account_disabled");
    const refused = (await auditRows(uid)).filter((r) => r.action === "review_account.session_refused" && r.subject_id === s1);
    assertEquals(refused.length, 1, "the refusal is audited, the window being open");
    await assertRejects(() => withOwnership({ uid, role: "authenticated" }, async () => "never reached"), Error); // the database binder refuses it too
    // a retired account is still a review account, and its row cannot be revived or removed while its Auth user exists
    assertEquals((await adminSql()`select private.is_demo_account(${uid}::uuid) as d`)[0]!.d, true);
    await assertRejects(() => adminSql()`update app.app_review_demo_account set retired_at = null where user_id = ${uid}`, Error);
    await assertRejects(() => adminSql()`delete from app.app_review_demo_account where user_id = ${uid}`, Error);
  } finally {
    await dropWindow(w);
  }
});

Deno.test("an ordinary account is never audited and never refused, with or without a window", DT, async () => {
  await noWindowsAtAll();
  const uid = freshUuid();
  await createTestUser(uid, `rv-plain-${uid.slice(0, 8)}`);
  assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
  const w = await openWindow("-1 hour", "1 hour");
  try {
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
  } finally {
    await dropWindow(w);
  }
  assertEquals((await auditRows(uid)).length, 0);
});

Deno.test("a bad token is still a 401 (the gate runs only after Auth has verified it)", DT, async () => {
  const res = await entry("not.a.jwt");
  assertEquals(res.status, 401);
});

Deno.test("a partner session or invite token (gr_ps_ / gr_inv_) is refused before GoTrue is asked and before the gate runs (composition with PA-11)", DT, async () => {
  const uid = await reviewUser("prefix");
  const before = stubCalls;
  for (const t of [`gr_ps_${"a".repeat(40)}`, `GR_PS_${"a".repeat(40)}`, `gr_inv_${"b".repeat(40)}`]) {
    const res = await entry(t);
    assertEquals(res.status, 401);
  }
  assertEquals(stubCalls, before, "no request reached GoTrue with a partner token");
  assertEquals((await auditRows(uid)).length, 0, "and the gate never ran");
});

Deno.test("the database backstop: withOwnership for a disabled review account fails at the binder even with no gate in front of it", DT, async () => {
  await noWindowsAtAll();
  const uid = await reviewUser("backstop");
  await assertRejects(() => withOwnership({ uid, role: "authenticated" }, async () => "never reached"), Error);
  // ...and the same call works once a window is open
  const w = await openWindow("-1 hour", "1 hour");
  try {
    assertEquals(await withOwnership({ uid, role: "authenticated" }, async () => "reached"), "reached");
  } finally {
    await dropWindow(w);
  }
});

Deno.test("an HttpError from the gate is the 403 the entrypoints return (code is stable)", DT, async () => {
  await noWindowsAtAll();
  const uid = await reviewUser("code");
  const err = await getActorFromRequest(req(tokenFor(uid, freshUuid()))).then(() => null, (e: unknown) => e);
  assert(err instanceof HttpError);
  assertEquals((err as HttpError).status, 403);
  assertEquals((err as HttpError).code, "review_account_disabled");
});

Deno.test("LOW-3: when the audit row cannot be written, the review account is refused (a server error, never a pass, in or out of a window); an ordinary account is unaffected", DT, async () => {
  await noWindowsAtAll();
  resetReviewGateCacheForTests();
  const uid = await reviewUser("auditfail");
  const plain = freshUuid();
  await createTestUser(plain, `rv-plain2-${plain.slice(0, 8)}`);
  const owner = rawOwnerSql();
  // a trigger the OWNER plants (the audit_log insert-only trigger is untouched): every review-account audit INSERT fails
  await owner.unsafe(`create function app.zz_review_audit_fail() returns trigger language plpgsql as $f$ begin if new.action like 'review_account.%' then raise exception 'forced audit failure' using errcode = 'XX000'; end if; return new; end $f$`);
  await owner.unsafe(`create trigger zz_review_audit_fail before insert on app.audit_log for each row execute function app.zz_review_audit_fail()`);
  const w = await openWindow("-1 hour", "1 hour");
  try {
    for (const label of ["inside a window", "outside every window"]) {
      if (label === "outside every window") await dropWindow(w);
      const res = await entry(tokenFor(uid, freshUuid()));
      assert(res.status >= 500, `${label}: a failed audit write must not become ${res.status}`);
      assertEquals((await auditRows(uid)).length, 0, `${label}: and nothing was recorded`);
    }
    assertEquals((await entry(tokenFor(plain, freshUuid()))).status, 200, "an ordinary account never reaches the audit write");
  } finally {
    await owner.unsafe(`drop trigger if exists zz_review_audit_fail on app.audit_log`);
    await owner.unsafe(`drop function if exists app.zz_review_audit_fail()`);
    await dropWindow(w);
  }
  // control: with the trigger gone the same request is audited and answered normally
  const w2 = await openWindow("-1 hour", "1 hour");
  try {
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
    assertEquals((await auditRows(uid)).length, 1);
  } finally {
    await dropWindow(w2);
  }
});

Deno.test("LOW-2: when the gate cannot read the window (a lock held past lock_timeout), the review account gets a server error, never a pass; an ordinary account is unaffected", DT, async () => {
  await noWindowsAtAll();
  resetReviewGateCacheForTests();
  const uid = await reviewUser("lockfail");
  const plain = freshUuid();
  await createTestUser(plain, `rv-plain3-${plain.slice(0, 8)}`);
  const w = await openWindow("-1 hour", "1 hour");
  try {
    await ensureServiceRole();
    // a second connection holds the window table: the gate's read waits, then fails on lock_timeout (5 s)
    let reviewStatus = 0;
    let plainStatus = 0;
    await adminSql().begin(async (tx) => {
      await tx`lock table app.app_review_window in access exclusive mode`;
      plainStatus = (await entry(tokenFor(plain, freshUuid()))).status;
      reviewStatus = (await entry(tokenFor(uid, freshUuid()))).status;
    });
    assertEquals(plainStatus, 200, "an ordinary account never reads the window");
    assert(reviewStatus >= 500, `the review account must be refused when the window cannot be read, got ${reviewStatus}`);
    assertEquals((await auditRows(uid)).length, 0);
  } finally {
    await dropWindow(w);
  }
});

Deno.test("LOW-4: the gate costs one transaction per ordinary account per 30 s, not one per request; the review account is asked on EVERY request; the numbers are logged", DT, async () => {
  await noWindowsAtAll();
  const plain = freshUuid();
  await createTestUser(plain, `rv-plain4-${plain.slice(0, 8)}`);
  const N = 100;
  const tok = tokenFor(plain, freshUuid());
  const timeIt = async (reset: boolean): Promise<{ ms: number; calls: number }> => {
    resetReviewGateCacheForTests();
    const c0 = reviewGateDbCallsForTests();
    const t0 = performance.now();
    for (let i = 0; i < N; i++) {
      if (reset) resetReviewGateCacheForTests();
      assertEquals((await entry(tok)).status, 200);
    }
    return { ms: performance.now() - t0, calls: reviewGateDbCallsForTests() - c0 };
  };
  await timeIt(false); // warm the pools
  const uncached = await timeIt(true);
  const cached = await timeIt(false);
  console.log(`review-gate overhead, ${N} authenticated requests of an ordinary account (auth stub on loopback, unix-socket database): WITHOUT the negative cache ${(uncached.ms / N).toFixed(2)} ms/request (${uncached.calls} gate transactions); WITH it ${(cached.ms / N).toFixed(2)} ms/request (${cached.calls} gate transaction)`);
  assertEquals(uncached.calls, N);
  assertEquals(cached.calls, 1, "one gate transaction serves the whole burst of an ordinary account");
  // the review account is NEVER cached: every request asks (and is audited per session)
  const rv = await reviewUser("nocache");
  const w = await openWindow("-1 hour", "1 hour");
  try {
    const c0 = reviewGateDbCallsForTests();
    const sid = freshUuid();
    for (let i = 0; i < 5; i++) assertEquals((await entry(tokenFor(rv, sid))).status, 200);
    assertEquals(reviewGateDbCallsForTests() - c0, 5, "the review account is asked on every request");
    assertEquals((await auditRows(rv)).filter((r) => r.action === "review_account.session_allowed").length, 1, "and still audited once per session");
  } finally {
    await dropWindow(w);
  }
});

Deno.test("LOW-4: the negative cache expires: an ordinary account is asked again after 30 s (a fake clock; not before)", DT, async () => {
  await noWindowsAtAll();
  resetReviewGateCacheForTests();
  const uid = freshUuid();
  await createTestUser(uid, `rv-ttl-${uid.slice(0, 8)}`);
  let t = 1_000_000;
  setReviewGateClockForTests(() => t);
  try {
    const c0 = reviewGateDbCallsForTests();
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
    assertEquals(reviewGateDbCallsForTests() - c0, 1);
    t += 29_000;
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
    assertEquals(reviewGateDbCallsForTests() - c0, 1, "still remembered after 29 s");
    t += 2_000; // 31 s after the first answer
    assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200);
    assertEquals(reviewGateDbCallsForTests() - c0, 2, "asked again after 31 s");
  } finally {
    setReviewGateClockForTests(null);
    resetReviewGateCacheForTests();
  }
});

Deno.test("the negative cache's bounded corner: an account that becomes the review account inside the TTL is skipped by the gate but NOT by the database (the binder refuses it outside a window); a reset closes the corner", DT, async () => {
  await noWindowsAtAll();
  resetReviewGateCacheForTests();
  const uid = freshUuid();
  await createTestUser(uid, `rv-late-${uid.slice(0, 8)}`);
  assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200); // cached as an ordinary account
  await ensureServiceRole();
  await adminSql()`delete from app.app_review_demo_account where retired_at is null`;
  await adminSql()`insert into app.app_review_demo_account (user_id) values (${uid})`;
  assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 200, "inside the TTL the gate is skipped (documented, bounded)");
  assertEquals((await auditRows(uid)).length, 0);
  await assertRejects(() => withOwnership({ uid, role: "authenticated" }, async () => "x"), Error); // ...but the database still refuses it outside a window
  resetReviewGateCacheForTests();
  assertEquals((await entry(tokenFor(uid, freshUuid()))).status, 403, "with the cache empty the gate applies at once");
});

Deno.test({ name: "teardown: stop the Auth stub and restore the environment", sanitizeOps: false, sanitizeResources: false, fn: async () => {
  await server.shutdown();
  if (savedEnv.url === undefined) Deno.env.delete("SUPABASE_URL"); else Deno.env.set("SUPABASE_URL", savedEnv.url);
  if (savedEnv.anon === undefined) Deno.env.delete("SUPABASE_ANON_KEY"); else Deno.env.set("SUPABASE_ANON_KEY", savedEnv.anon);
} });

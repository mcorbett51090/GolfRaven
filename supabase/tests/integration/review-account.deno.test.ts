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
//   6. the audit rows carry no email, no token and no address.
// The reward 403 for the review account (inside a window) is rewards-activate.deno.test.ts.

import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid } from "./_helpers.ts";
import { getActorFromRequest, withOwnership } from "../../functions/_shared/privileged.ts";
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
  await adminSql()`delete from app.app_review_demo_account`;
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

Deno.test({ name: "teardown: stop the Auth stub and restore the environment", sanitizeOps: false, sanitizeResources: false, fn: async () => {
  await server.shutdown();
  if (savedEnv.url === undefined) Deno.env.delete("SUPABASE_URL"); else Deno.env.set("SUPABASE_URL", savedEnv.url);
  if (savedEnv.anon === undefined) Deno.env.delete("SUPABASE_ANON_KEY"); else Deno.env.set("SUPABASE_ANON_KEY", savedEnv.anon);
} });

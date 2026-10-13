// supabase/tests/integration/partner-members.deno.test.ts
//
// Slice S1.5 / 0054 (docs/security/partner-auth-design.md 4.5, 6.4, 6.5, 8, 22.4, 130): the REAL `partner-members` handler over the REAL privileged.ts (`partnerDb.withMembers` = `withPartnerSession`, `withMint`, `hitRateLimit`), REAL
// manager and staff sessions minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as
// `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port and the pgTAP matrix calls the definers with its own SQL. Neither runs (1) the recovery token's hash contract: the EDGE generates the `gr_enr_`
// token and passes the database only its SHA-256, and a disagreement would issue a recovery nobody can redeem; (2) the roster and the reach rule as they behave under the BOUND `edge_partner` transaction, for a manager of
// another facility; (3) the second-credential ceremony end to end: the Edge's creation options, a REAL registration from a software authenticator verified by the REAL registration wrapper, the credential the database
// stores, and a REAL sign-in with it afterwards, which only works if the stored public key is the one the authenticator holds.
//
// The same shortcut as the other partner integration files: a session's step-up state (a passkey reauth in the last 5 minutes, a PIN grant of 50 s, one per action) is written by the OWNER with the guard trigger off for
// that statement only; the reauth and the PIN themselves are proved elsewhere. Not driven: `totp-reset` and `admin/enrolments` (class A3: aal 2 and a TOTP), the PIN reset's PIN itself (a row is planted), and the
// enrolment token's redemption (it is branch N of the invites lane: GoTrue's email OTP).

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  adminSql,
  ensureServiceRole,
  freshUuid,
  rawOwnerSql,
  withTemporaryOwnerAccess as withOwnerAccess,
} from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { handlePartnerMembersRequest } from "../../functions/_shared/partner/members-handler.ts";
import {
  assertionVerifier,
  registrationVerifier,
} from "../../functions/_shared/partner/webauthn-port.ts";
import {
  parseChallengeToken,
  uuidToBytes,
} from "../../functions/_shared/partner/session-shape.ts";
import {
  newPartnerEnrolmentToken,
  newPartnerSessionToken,
  PARTNER_ENROLMENT_TOKEN_RE,
  sha256Hex,
} from "../../functions/_shared/partner/token.ts";
import { partnerDb } from "../../functions/_shared/privileged.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const HELD = new Set(["app.partner_credential", "app.partner_org"]);
const rows = <T>(
  table: string,
  query: (sql: ReturnType<typeof rawOwnerSql>) => Promise<T>,
): Promise<T> =>
  withOwnerAccess(
    table,
    query as never,
    HELD.has(table) ? "insert, delete" : "select, insert, update, delete",
  ) as Promise<T>;
await rawOwnerSql().unsafe(
  "grant select, update on app.partner_credential, app.partner_org to current_user",
);

const RP = {
  rpId: "partners.example.test",
  origin: "https://partners.example.test",
};
await rows(
  "app.partner_rp_config",
  (sql) =>
    sql`insert into app.partner_rp_config (rp_id, origin) values (${RP.rpId}, ${RP.origin}) on conflict (singleton) do update set rp_id = excluded.rp_id, origin = excluded.origin`,
);
const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const FAC = "fac_x"; // seeded by the harness (helpers.sql)
/** A second facility: an organisation scoped to it has no scope over fac_x (the reach rule and the roster are facility-scoped). */
const OTHER_FAC = "fac_y";

async function sessionCall(path: string, body: unknown): Promise<Response> {
  const headers = new Headers({
    origin: RP.origin,
    "content-type": "application/json",
  });
  return await handlePartnerSessionRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-session/${path}`,
      { method: "POST", headers, body: JSON.stringify(body) },
    ),
    {
      db: partnerDb,
      allowedOrigin: RP.origin,
      webauthn: assertionVerifier,
      otp: {
        send: () => Promise.reject(new Error("unused")),
        verify: () => Promise.reject(new Error("unused")),
      },
      nowMs: () => Date.now(),
      newSessionToken: newPartnerSessionToken,
    },
  );
}

interface Member {
  readonly uid: string;
  readonly token: string;
  readonly hash: string;
  readonly auth: SoftwareAuthenticator;
}
let seq = 0;
/** A run-unique suffix for account labels: every integration file shares one database. */
const RUN = freshUuid().slice(0, 8);

/** Signs `auth` in through the REAL mint (options, a real assertion, verify): a session, or the refusal's response. */
async function signInWith(auth: SoftwareAuthenticator): Promise<Response> {
  const o = await sessionCall("options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parsed.nonce,
  });
  return await sessionCall("verify", {
    challengeToken: d.challengeToken,
    credential: cred,
  });
}
/** A real credential for `uid` and a session from the real mint. */
async function signInAs(uid: string): Promise<Member> {
  const auth = await SoftwareAuthenticator.create("ES256", uuidToBytes(uid)!);
  await rows(
    "app.partner_credential",
    (sql) =>
      sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), -7, 0)`,
  );
  const res = await signInWith(auth);
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, token, hash: await sha256Hex(token), auth };
}

/** The auth user createTestUser would make, with an address or without one (a recovery needs one). */
async function newAuthUser(
  uid: string,
  name: string,
  withEmail: boolean,
): Promise<void> {
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into auth.users (id, email) values (${uid}, ${withEmail ? name + "@integration.test" : null})`;
  await sql`insert into app.profile (user_id, handle) values (${uid}, ${"u" + uid.replace(/-/g, "").slice(0, 19)})`;
}

/** A facility org scoped to `facility`. */
async function newOrg(facility = FAC): Promise<string> {
  seq += 1;
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"members org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, facility_id) values (${org}, ${facility})`,
  );
  return org;
}
/** A member of `org` with a role, a real credential and a session from the real mint. */
async function newMember(
  org: string,
  role: "staff" | "manager",
  label: string,
  withEmail = true,
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await newAuthUser(uid, `mem-${label}-${RUN}-${seq}`, withEmail);
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${role}, now() - interval '60 days')`,
  );
  return await signInAs(uid);
}

/** Step-up state a session cannot be BORN with: the guard trigger is off for this one statement. Class A2: a passkey reauth in the last 5 minutes and a PIN grant of 50 s, one per action. */
async function stepUp(m: Member): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set reauth_until = clock_timestamp() + interval '200 seconds', pin_grant_until = clock_timestamp() + interval '50 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
}

async function memCall(
  m: Member | null,
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
  withStepUp = method === "POST" || method === "DELETE",
): Promise<Response> {
  if (m !== null && withStepUp) await stepUp(m);
  const headers = new Headers({ origin: RP.origin });
  if (m !== null) headers.set("authorization", `Bearer ${m.token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  else if (method === "POST") headers.set("content-type", "application/json");
  return await handlePartnerMembersRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-members/${path}`,
      {
        method,
        headers,
        body:
          body === undefined
            ? method === "POST"
              ? "{}"
              : undefined
            : JSON.stringify(body),
      },
    ),
    {
      db: partnerDb,
      allowedOrigin: RP.origin,
      registration: registrationVerifier,
      nowMs: () => Date.now(),
      newEnrolmentToken: newPartnerEnrolmentToken,
    },
  );
}
const errOf = async (res: Response) => (await res.json()).error?.code as string;
const dataOf = async (res: Response) =>
  (await res.json()).data as Record<string, unknown>;

const membershipRows = async (uid: string, org: string) =>
  (
    await rows(
      "app.partner_member",
      (sql) =>
        sql`select revoked_at from app.partner_member where user_id = ${uid} and org_id = ${org}`,
    )
  ).map((r) => ({ revoked: r.revoked_at !== null }));
const credentialRows = async (uid: string) =>
  (await rows(
    "app.partner_credential",
    (sql) =>
      sql`select encode(credential_id, 'hex') as id_hex, encode(public_key, 'hex') as key_hex, alg::int as alg, revoked_at, id::text as id from app.partner_credential where user_id = ${uid} order by created_at, id`,
  )) as unknown as Array<{
    id_hex: string;
    key_hex: string;
    alg: number;
    revoked_at: Date | null;
    id: string;
  }>;
const sessionLive = async (m: Member): Promise<boolean> => {
  const r = await memCall(m, "GET", "credentials");
  if (r.status === 200) return true;
  assertEquals(r.status, 401, await r.clone().text());
  return false;
};
const ids = (res: unknown, key: string): string[] =>
  ((res as Record<string, Array<Record<string, unknown>>>)[key] ?? []).map(
    (x) => String(x.userId),
  );

Deno.test(
  "S1.5 / 6.5: a manager's roster lists the facility's active members with role, facility and an ISO time; a manager of another facility sees none of them; staff, an unknown query parameter and no bearer are refused",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s1 = await newMember(org, "staff", "s1");
    const s2 = await newMember(org, "staff", "s2");
    const otherOrg = await newOrg(OTHER_FAC);
    const n = await newMember(otherOrg, "manager", "other");
    const t = await newMember(otherOrg, "staff", "t");

    const res = await memCall(mgr, "GET", `members?orgId=${org}`);
    assertEquals(res.status, 200, await res.clone().text());
    const data = await dataOf(res);
    const members = data.members as Array<Record<string, unknown>>;
    for (const who of [s1, s2]) {
      const row = members.find((x) => x.userId === who.uid)!;
      assert(row, "the roster lists the active staff member");
      assertEquals(
        [row.orgId, row.role, row.facilityId, row.invitedBy],
        [org, "staff", FAC, null],
      );
      assert(!Number.isNaN(Date.parse(String(row.createdAt))), "an ISO time");
    }
    assert(
      !ids(data, "members").includes(t.uid),
      "the other facility's staff is not on this roster",
    );

    const all = await dataOf(await memCall(mgr, "GET", "members"));
    assert(
      ids(all, "members").includes(s1.uid) &&
        !ids(all, "members").includes(t.uid),
      "with no orgId: everything in scope, nothing outside it",
    );
    const theirs = await memCall(n, "GET", `members?orgId=${org}`);
    assertEquals(theirs.status, 200, await theirs.clone().text());
    const seen = ids(await dataOf(theirs), "members");
    assert(
      !seen.includes(s1.uid) && !seen.includes(s2.uid),
      "a manager of another facility does not see this facility's members",
    );

    assertEquals(
      (await memCall(s1, "GET", "members")).status,
      403,
      "staff are not on the manager's list",
    );
    assertEquals((await memCall(mgr, "GET", "members?bogus=1")).status, 400);
    assertEquals((await memCall(null, "GET", "members")).status, 401);
  },
);

Deno.test(
  "S1.5 / 6.5: revoking a membership marks it revoked and drops it from the roster; the same call again is 404; acting on oneself is 422; another facility's manager is refused and nothing changes",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s1 = await newMember(org, "staff", "s1");
    const s2 = await newMember(org, "staff", "s2");
    const n = await newMember(await newOrg(OTHER_FAC), "manager", "other");

    const self = await memCall(mgr, "POST", `members/${mgr.uid}/revoke`, {
      orgId: org,
    });
    assertEquals(self.status, 422, await self.clone().text());
    assertEquals(await membershipRows(mgr.uid, org), [{ revoked: false }]);

    const foreign = await memCall(n, "POST", `members/${s1.uid}/revoke`, {
      orgId: org,
    });
    assertEquals([foreign.status, await errOf(foreign)], [403, "forbidden"]);
    assertEquals(
      await membershipRows(s1.uid, org),
      [{ revoked: false }],
      "outside the reach rule: nothing changed",
    );

    const unknown = await memCall(
      mgr,
      "POST",
      `members/${freshUuid()}/revoke`,
      { orgId: org },
    );
    assertEquals([unknown.status, await errOf(unknown)], [404, "not_found"]);

    const ok = await memCall(mgr, "POST", `members/${s1.uid}/revoke`, {
      orgId: org,
    });
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await dataOf(ok), { revoked: true });
    assertEquals(await membershipRows(s1.uid, org), [{ revoked: true }]);
    // the revoked person is signed out: their very next call is the binder's one 401 (control: another member's session still works). Which part of the database produces that 401 was not traced.
    assertEquals(
      await sessionLive(s1),
      false,
      "the revoked member's session is refused",
    );
    assertEquals(
      await sessionLive(s2),
      true,
      "another member's session is untouched",
    );
    const roster = ids(
      await dataOf(await memCall(mgr, "GET", `members?orgId=${org}`)),
      "members",
    );
    assert(
      !roster.includes(s1.uid) && roster.includes(s2.uid),
      "the revoked member is off the roster, the other is not",
    );
    const again = await memCall(mgr, "POST", `members/${s1.uid}/revoke`, {
      orgId: org,
    });
    assertEquals([again.status, await errOf(again)], [404, "not_found"]);
  },
);

Deno.test(
  "S1.5 / 6.5: a recovery returns a gr_enr_ token once: the database holds the SHA-256 of it for that person, issued by that manager, for 24 hours; the person's credentials and sessions are revoked; a second recovery revokes the first token; an address-less person is 409 no_email and nothing is written",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s1 = await newMember(org, "staff", "s1");
    const noMail = await newMember(org, "staff", "nomail", false);
    const n = await newMember(await newOrg(OTHER_FAC), "manager", "other");
    const tokenRows = async (uid: string) =>
      (await rows(
        "app.partner_enrolment_token",
        (sql) =>
          sql`select token_hash, purpose::text as purpose, issued_by::text as issued_by, expires_at, consumed_at, revoked_at from app.partner_enrolment_token where user_id = ${uid} order by created_at, id`,
      )) as unknown as Array<{
        token_hash: string;
        purpose: string;
        issued_by: string;
        expires_at: Date;
        consumed_at: Date | null;
        revoked_at: Date | null;
      }>;

    const self = await memCall(mgr, "POST", `members/${mgr.uid}/recover`);
    assertEquals(self.status, 422, await self.clone().text());
    const foreign = await memCall(n, "POST", `members/${s1.uid}/recover`);
    assertEquals(foreign.status, 403, await foreign.clone().text());
    assertEquals(
      (await tokenRows(s1.uid)).length,
      0,
      "outside the reach rule: no token",
    );
    assert(
      (await credentialRows(s1.uid)).every((c) => c.revoked_at === null) &&
        (await sessionLive(s1)),
      "outside the reach rule: the person is untouched",
    );

    const res = await memCall(mgr, "POST", `members/${s1.uid}/recover`);
    assertEquals(res.status, 201, await res.clone().text());
    const d = await dataOf(res);
    const token = String(d.token);
    assert(PARTNER_ENROLMENT_TOKEN_RE.test(token), "the Edge's token format");
    assertEquals(
      d.enrolUrl,
      `${RP.origin}/enrol#${token}`,
      "the token travels in the link's fragment",
    );
    const ttlH = (Date.parse(String(d.expiresAt)) - Date.now()) / 3_600_000;
    assert(ttlH > 23 && ttlH <= 24, `expires in 24 hours (${ttlH} h)`);
    const [row] = await tokenRows(s1.uid);
    assertEquals(
      [
        row!.token_hash,
        row!.purpose,
        row!.issued_by,
        row!.consumed_at,
        row!.revoked_at,
      ],
      [await sha256Hex(token), "recover", mgr.uid, null, null],
    );
    assert(
      !JSON.stringify(row).includes(token),
      "the plaintext token is in no column",
    );
    assert(
      (await credentialRows(s1.uid)).every((c) => c.revoked_at !== null),
      "every credential of the person is revoked",
    );
    assertEquals(
      await sessionLive(s1),
      false,
      "the person's session is revoked",
    );

    const second = await memCall(mgr, "POST", `members/${s1.uid}/recover`);
    assertEquals(second.status, 201, await second.clone().text());
    const rowsNow = await tokenRows(s1.uid);
    assertEquals(rowsNow.length, 2);
    assertEquals(
      [rowsNow[0]!.revoked_at !== null, rowsNow[1]!.revoked_at],
      [true, null],
      "the earlier token is revoked, the new one is live",
    );

    const nm = await memCall(mgr, "POST", `members/${noMail.uid}/recover`);
    assertEquals([nm.status, await errOf(nm)], [409, "no_email"]);
    assertEquals(
      (await tokenRows(noMail.uid)).length,
      0,
      "no_email writes no token",
    );
    assert(
      (await credentialRows(noMail.uid)).every((c) => c.revoked_at === null) &&
        (await sessionLive(noMail)),
      "no_email revokes nothing",
    );
  },
);

Deno.test(
  "S1.5 / 6.5: a PIN reset on a person with no PIN is 409 pin_not_set; on a locked PIN it clears the lock and the counters and sets must_change; outside the reach rule and on oneself it is refused",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s1 = await newMember(org, "staff", "s1");
    const s2 = await newMember(org, "staff", "s2");
    const n = await newMember(await newOrg(OTHER_FAC), "manager", "other");
    const pinRow = async (uid: string) =>
      (
        await rows(
          "app.partner_pin",
          (sql) =>
            sql`select failed_count::int as failed_count, failed_today::int as failed_today, locked_at, next_attempt_at, must_change from app.partner_pin where user_id = ${uid}`,
        )
      )[0] as unknown as {
        failed_count: number;
        failed_today: number;
        locked_at: Date | null;
        next_attempt_at: Date | null;
        must_change: boolean;
      };

    const none = await memCall(mgr, "POST", `members/${s1.uid}/pin-reset`);
    assertEquals([none.status, await errOf(none)], [409, "pin_not_set"]);

    // a PIN the person set and then locked by five wrong attempts (the verifier bytes are a placeholder: this cell does not verify a PIN)
    await rows(
      "app.partner_pin",
      (sql) =>
        sql`insert into app.partner_pin (user_id, salt, iterations, verifier, failed_count, failed_today, failed_day, last_failed_at, next_attempt_at, locked_at, must_change)
            values (${s2.uid}, decode(${"ab".repeat(16)}, 'hex'), 210000, decode(${"cd".repeat(32)}, 'hex'), 5, 5, current_date, now(), now() + interval '5 minutes', now(), false)`,
    );
    const foreign = await memCall(n, "POST", `members/${s2.uid}/pin-reset`);
    assertEquals(foreign.status, 403, await foreign.clone().text());
    assertEquals(
      (await pinRow(s2.uid)).locked_at !== null,
      true,
      "outside the reach rule: still locked",
    );
    const self = await memCall(mgr, "POST", `members/${mgr.uid}/pin-reset`);
    assertEquals(self.status, 422, await self.clone().text());

    const ok = await memCall(mgr, "POST", `members/${s2.uid}/pin-reset`);
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await dataOf(ok), { reset: true });
    const after = await pinRow(s2.uid);
    assertEquals(
      [
        after.failed_count,
        after.failed_today,
        after.locked_at,
        after.next_attempt_at,
        after.must_change,
      ],
      [0, 0, null, null, true],
    );
    const alarm = await rows(
      "app.partner_auth_alarm",
      (sql) =>
        sql`select count(*)::int as n from app.partner_auth_alarm where kind = 'pin_reset' and bucket_key = ${s2.uid}`,
    );
    assertEquals(Number(alarm[0]!.n), 1, "the reset raised its alarm row");
  },
);

Deno.test(
  "S1.5 / 6.5: the stolen-iPad button revokes every session of the organisation (the count is the live sessions) and, with createdAfter, the credentials of the others too; another facility's manager is refused, an unknown organisation is 404, a time in the future is 422",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s1 = await newMember(org, "staff", "s1");
    const s2 = await newMember(org, "staff", "s2");
    const n = await newMember(await newOrg(OTHER_FAC), "manager", "other");

    const foreign = await memCall(
      n,
      "POST",
      `orgs/${org}/sessions/revoke-all`,
      {},
    );
    assertEquals(foreign.status, 403, await foreign.clone().text());
    assert(
      (await sessionLive(s1)) && (await sessionLive(s2)),
      "outside the reach rule: nobody was signed out",
    );
    // observed, not judged (design 130): an organisation id that does not exist is 404 while one outside the caller's reach is 403 (0054: not_found is returned before the scope check), so a manager can tell the two apart
    const unknown = await memCall(
      mgr,
      "POST",
      `orgs/${freshUuid()}/sessions/revoke-all`,
      {},
    );
    assertEquals([unknown.status, await errOf(unknown)], [404, "not_found"]);
    const future = await memCall(
      mgr,
      "POST",
      `orgs/${org}/sessions/revoke-all`,
      { createdAfter: new Date(Date.now() + 3_600_000).toISOString() },
    );
    assertEquals(future.status, 422, await future.clone().text());
    assert(await sessionLive(s1), "a refused request signs nobody out");

    const ok = await memCall(
      mgr,
      "POST",
      `orgs/${org}/sessions/revoke-all`,
      {},
    );
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await dataOf(ok), {
      revokedSessions: 3,
      revokedCredentials: 0,
    });
    for (const who of [mgr, s1, s2])
      assertEquals(
        await sessionLive(who),
        false,
        "every session of the organisation is gone",
      );
    assert(
      (await credentialRows(s1.uid)).every((c) => c.revoked_at === null),
      "without createdAfter no credential is revoked",
    );

    // with createdAfter: the credentials of the OTHER covered members created after it are revoked as well, the caller's own is not
    const org2 = await newOrg();
    const m2 = await newMember(org2, "manager", "mgr");
    const a = await newMember(org2, "staff", "a");
    const b = await newMember(org2, "staff", "b");
    const since = new Date(Date.now() - 86_400_000).toISOString();
    const both = await memCall(m2, "POST", `orgs/${org2}/sessions/revoke-all`, {
      createdAfter: since,
    });
    assertEquals(both.status, 200, await both.clone().text());
    assertEquals(await dataOf(both), {
      revokedSessions: 3,
      revokedCredentials: 2,
    });
    assert(
      (await credentialRows(a.uid)).every((c) => c.revoked_at !== null) &&
        (await credentialRows(b.uid)).every((c) => c.revoked_at !== null),
      "the others' credentials are revoked",
    );
    assert(
      (await credentialRows(m2.uid)).every((c) => c.revoked_at === null),
      "the caller's own credential is not",
    );
  },
);

Deno.test(
  "S1.5: a person lists their own credentials, sets and clears the display note (a stranger's credential id is 404), and a manager lists a covered person's credentials while a manager outside the reach rule gets none",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s = await newMember(org, "staff", "s");
    const other = await newMember(org, "staff", "other");
    const n = await newMember(await newOrg(OTHER_FAC), "manager", "n");

    const list = async (m: Member, q = "") =>
      (await dataOf(await memCall(m, "GET", `credentials${q}`)))
        .credentials as Array<Record<string, unknown>>;
    const mine = await list(s);
    assertEquals(mine.length, 1);
    const cred = mine[0]!;
    assertEquals(
      [
        cred.note,
        cred.revokedAt,
        typeof cred.label,
        typeof cred.backupEligible,
        typeof cred.backupState,
      ],
      [null, null, "string", "boolean", "boolean"],
    );
    assert(!Number.isNaN(Date.parse(String(cred.createdAt))), "an ISO time");

    const set = await memCall(s, "PATCH", `credentials/${cred.id}`, {
      note: "  Front desk iPad  ",
    });
    assertEquals(set.status, 200, await set.clone().text());
    assertEquals(await dataOf(set), { note: "Front desk iPad" });
    assertEquals((await list(s))[0]!.note, "Front desk iPad");
    for (const clear of [null, "   "]) {
      const r = await memCall(s, "PATCH", `credentials/${cred.id}`, {
        note: clear,
      });
      assertEquals(r.status, 200, await r.clone().text());
      assertEquals((await list(s))[0]!.note, null);
    }
    const strangerCred = (await list(other))[0]!;
    const stranger = await memCall(
      s,
      "PATCH",
      `credentials/${strangerCred.id}`,
      { note: "mine now" },
    );
    assertEquals([stranger.status, await errOf(stranger)], [404, "not_found"]);
    assertEquals(
      (await list(other))[0]!.note,
      null,
      "a stranger's note was not written",
    );
    assertEquals(
      (await memCall(s, "PATCH", `credentials/${freshUuid()}`, { note: "x" }))
        .status,
      404,
    );

    assertEquals(
      (await list(mgr, `?userId=${s.uid}`)).length,
      1,
      "a manager sees a covered person's credentials",
    );
    assertEquals(
      (await list(n, `?userId=${s.uid}`)).length,
      0,
      "outside the reach rule the answer is empty, not an error",
    );
  },
);

/** Registers a SECOND credential for `m` through the handler (options, a real registration, register); returns the new authenticator and the credential id the database gave it. */
async function addSecondCredential(
  m: Member,
): Promise<{ auth2: SoftwareAuthenticator; credentialId: string }> {
  const opts = await memCall(m, "POST", "credentials/options");
  assertEquals(opts.status, 200, await opts.clone().text());
  const od = await dataOf(opts);
  assertEquals(
    (
      (od.options as { excludeCredentials?: unknown[] }).excludeCredentials ??
      []
    ).length,
    1,
    "the options exclude the credential the person already holds",
  );
  const parsed = parseChallengeToken(String(od.challengeToken))!;
  const auth2 = await SoftwareAuthenticator.create(
    "ES256",
    uuidToBytes(m.uid)!,
  );
  const credential = await auth2.register({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parsed.nonce,
  });
  const res = await memCall(m, "POST", "credentials", {
    challengeToken: od.challengeToken,
    credential,
  });
  assertEquals(res.status, 201, await res.clone().text());
  return { auth2, credentialId: String((await dataOf(res)).credentialId) };
}

Deno.test(
  "S1.5 / 6.4: a second credential is registered through a real ceremony: the database stores exactly the credential id and public key the authenticator holds, the person can sign in with it, and the add-notice reaches the person and their manager, who can each acknowledge theirs once",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const s = await newMember(org, "staff", "s");
    const { auth2, credentialId } = await addSecondCredential(s);

    const stored = (await credentialRows(s.uid)).find(
      (c) => c.id === credentialId,
    )!;
    assert(stored, "the new credential is stored for that person");
    assertEquals(
      [stored.id_hex, stored.key_hex, stored.alg, stored.revoked_at],
      [hex(auth2.credentialId), hex(auth2.cosePublicKey), -7, null],
    );

    // the stored public key is the one the authenticator holds: a real sign-in with the second credential works
    const signIn = await signInWith(auth2);
    assertEquals(signIn.status, 201, await signIn.clone().text());
    const second: Member = {
      uid: s.uid,
      token: ((await signIn.json()).data as { token: string }).token,
      hash: "",
      auth: auth2,
    };
    assert(
      await sessionLive(second),
      "the session minted by the second credential works",
    );
    assertEquals(
      (
        (await dataOf(await memCall(second, "GET", "credentials")))
          .credentials as unknown[]
      ).length,
      2,
    );

    // the add-notice: the person sees it, and so does the manager whose reach covers them
    const mineN = (await dataOf(await memCall(s, "GET", "credentials/notices")))
      .notices as Array<Record<string, unknown>>;
    const notice = mineN.find((x) => x.credentialId === credentialId)!;
    assert(notice, "the person's own notice");
    assertEquals(
      [notice.credentialRevokedAt, typeof notice.label],
      [null, "string"],
    );
    const reach = (
      await dataOf(await memCall(mgr, "GET", "credentials/notices/reach"))
    ).notices as Array<Record<string, unknown>>;
    const forMgr = reach.find((x) => x.credentialId === credentialId)!;
    assert(forMgr, "the manager's reach notice");
    assertEquals(forMgr.subjectUserId, s.uid);

    // each acknowledges once
    const ack = await memCall(
      s,
      "POST",
      `credentials/notices/${notice.noticeId}/ack`,
    );
    assertEquals(ack.status, 200, await ack.clone().text());
    assertEquals(await dataOf(ack), { acked: true });
    const again = await memCall(
      s,
      "POST",
      `credentials/notices/${notice.noticeId}/ack`,
    );
    assertEquals([again.status, await errOf(again)], [409, "already_acked"]);
    assert(
      !(
        (await dataOf(await memCall(s, "GET", "credentials/notices")))
          .notices as Array<Record<string, unknown>>
      ).some((x) => x.noticeId === notice.noticeId),
      "an acknowledged notice is off the list",
    );
    const unknown = await memCall(
      s,
      "POST",
      `credentials/notices/${freshUuid()}/ack`,
    );
    assertEquals([unknown.status, await errOf(unknown)], [404, "not_found"]);
  },
);

Deno.test(
  "S1.5 / 6.4: revoking a credential is 200 then 409 already_revoked, a stranger's or an unknown id is 404, and the revoked credential can no longer sign in",
  DT,
  async () => {
    const org = await newOrg();
    const s = await newMember(org, "staff", "s");
    const other = await newMember(org, "staff", "other");
    const { auth2, credentialId } = await addSecondCredential(s);
    const strangerCred = (await credentialRows(other.uid))[0]!;

    const stranger = await memCall(
      s,
      "DELETE",
      `credentials/${strangerCred.id}`,
    );
    assertEquals([stranger.status, await errOf(stranger)], [404, "not_found"]);
    assertEquals(
      (await credentialRows(other.uid))[0]!.revoked_at,
      null,
      "a stranger's credential was not revoked",
    );
    assertEquals(
      (await memCall(s, "DELETE", `credentials/${freshUuid()}`)).status,
      404,
    );

    const ok = await memCall(s, "DELETE", `credentials/${credentialId}`);
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await dataOf(ok), { revoked: true });
    assert(
      (await credentialRows(s.uid)).find((c) => c.id === credentialId)!
        .revoked_at instanceof Date,
      "revoked_at is set",
    );
    const twice = await memCall(s, "DELETE", `credentials/${credentialId}`);
    assertEquals([twice.status, await errOf(twice)], [409, "already_revoked"]);

    const refused = await signInWith(auth2);
    assert(
      refused.status >= 400 && refused.status < 500,
      `a revoked credential cannot sign in (${refused.status})`,
    );
    assert(
      await sessionLive(s),
      "the person's first credential and session are untouched",
    );
  },
);

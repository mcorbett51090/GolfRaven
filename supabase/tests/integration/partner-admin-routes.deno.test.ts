// supabase/tests/integration/partner-admin-routes.deno.test.ts
//
// Slice S1.3 / 0053 and S1.5 / 0054 (docs/security/partner-auth-design.md 4.1, 6.4, 6.5, 8, 136): the class-A3 routes of the members lane that no earlier file drove: `members/{id}/totp-reset` and `admin/enrolments`, and the
// redemption of the ADMIN enrolment token they issue. The REAL `partner-members` and `partner-invites` handlers over the REAL privileged.ts, REAL sessions from the REAL partner-session mint (the harness's seeded admin, a
// REAL operator, a REAL manager), against the REAL database tools/db/test.sh builds. As in partner-onboarding.deno.test.ts, the only fake is GoTrue's email OTP port.
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handlers mocked ports and the pgTAP matrix calls the definers with its own SQL. Neither runs the chain from an admin's A3 call to the row it changes (the TOTP
// seed version bump, the cleared enrolment, the target's sessions revoked) or the admin enrolment's token hash contract (the Edge generates a `gr_enr_` token and the database holds only its SHA-256), and the admin
// enrolment token's redemption by a person who is an admin and has no credential yet.
//
// The same shortcut as the other partner integration files: a session's step-up state (aal 2 and a live `mfa_until`, class A3) is written by the OWNER with the guard trigger off for that statement only; TOTP itself is proved
// elsewhere. A second admin (the enrolment's target) is a row the OWNER inserts into app.admin_user for the length of a cell and deletes again: admin membership is shared state.

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
import { handlePartnerInvitesRequest } from "../../functions/_shared/partner/invites-handler.ts";
import { handlePartnerMembersRequest } from "../../functions/_shared/partner/members-handler.ts";
import {
  assertionVerifier,
  registrationVerifier,
} from "../../functions/_shared/partner/webauthn-port.ts";
import type { EmailOtpPort } from "../../functions/_shared/partner/ports.ts";
import {
  parseChallengeToken,
  uuidToBytes,
} from "../../functions/_shared/partner/session-shape.ts";
import {
  newPartnerEnrolmentToken,
  newPartnerInviteToken,
  newPartnerSessionToken,
  PARTNER_ENROLMENT_TOKEN_RE,
  PARTNER_SESSION_TOKEN_RE,
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
const b64u = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
const FAC = "fac_x"; // seeded by the harness (helpers.sql)
const CODE = "123456";
/** A run-unique suffix for addresses and labels: every integration file shares one database. */
const RUN = freshUuid().slice(0, 8);
let seq = 0;

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// the email OTP (GoTrue): a recording fake over the real auth tables
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
interface FakeOtp {
  readonly port: EmailOtpPort;
  readonly sent: string[];
  readonly verifyCalls: string[];
  readonly closed: string[];
  /** age in seconds of the GoTrue session the next verify creates (a stale one is refused by the database) */
  ageSeconds: number;
}
/** `createsAccount`: an invite's OTP may create the account (the invitee has none yet); an enrolment's proves an account that exists. */
function makeOtp(createsAccount: boolean): FakeOtp {
  const o: FakeOtp = {
    port: undefined as unknown as EmailOtpPort,
    sent: [],
    verifyCalls: [],
    closed: [],
    ageSeconds: 0,
  };
  const port: EmailOtpPort = {
    send(email) {
      o.sent.push(email);
      return Promise.resolve();
    },
    async verify(email, code) {
      o.verifyCalls.push(email);
      if (code !== CODE) return { ok: false as const };
      await ensureServiceRole();
      const sql = adminSql();
      let found =
        await sql`select id::text as id from auth.users where lower(email) = ${email}`;
      if (found.length === 0) {
        if (!createsAccount) return { ok: false as const };
        const id = freshUuid();
        await sql`insert into auth.users (id, email, email_confirmed_at) values (${id}, ${email}, now())`;
        found =
          await sql`select id::text as id from auth.users where id = ${id}`;
      } else {
        await sql`select 1`; // the account exists and its address is confirmed (a real verifyOtp confirms it)
      }
      const uid = found[0]!.id as string;
      const sid = freshUuid();
      await sql`insert into auth.sessions (id, user_id, created_at) values (${sid}, ${uid}, clock_timestamp() - ${o.ageSeconds + " seconds"}::interval)`;
      return {
        ok: true as const,
        userId: uid,
        sessionId: sid,
        async closeSession() {
          o.closed.push(sid);
          await sql`delete from auth.sessions where id = ${sid}`;
        },
      };
    },
  };
  return Object.assign(o, { port });
}
let otpInvite = makeOtp(true);
let otpEnrol = makeOtp(false);
function resetOtp(): void {
  otpInvite = makeOtp(true);
  otpEnrol = makeOtp(false);
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// sessions, organisations, members
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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
  readonly email: string;
  readonly token: string;
  readonly hash: string;
}
/** A real credential for `uid` and a session from the real mint. */
async function signInAs(uid: string, email: string): Promise<Member> {
  const auth = await SoftwareAuthenticator.create("ES256", uuidToBytes(uid)!);
  await rows(
    "app.partner_credential",
    (sql) =>
      sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), -7, 0)`,
  );
  const o = await sessionCall("options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const cred = await auth.assert({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parseChallengeToken(d.challengeToken)!.nonce,
  });
  const res = await sessionCall("verify", {
    challengeToken: d.challengeToken,
    credential: cred,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, email, token, hash: await sha256Hex(token) };
}
async function newOrg(): Promise<string> {
  seq += 1;
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"onboarding org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, facility_id) values (${org}, ${FAC})`,
  );
  return org;
}
/** A member of `org` (an account with a confirmed address) with a role; with a real credential and session unless `withCredential` is false. */
async function newMember(
  org: string,
  role: "staff" | "manager",
  label: string,
  withCredential = true,
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  const name = `adr-${label}-${RUN}-${seq}`;
  await ensureServiceRole();
  await adminSql()`insert into auth.users (id, email, email_confirmed_at) values (${uid}, ${name + "@integration.test"}, now())`;
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${role}, now() - interval '60 days')`,
  );
  const email = `${name}@integration.test`;
  return withCredential
    ? await signInAs(uid, email)
    : { uid, email, token: "", hash: "" };
}
async function stepUpA3(m: Member, aal = 2, mfaSeconds = 240): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = ${aal}, mfa_until = clock_timestamp() + ${mfaSeconds} * interval '1 second' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
}
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

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// the two handlers
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
async function invCall(
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  nowMs: () => number = () => Date.now(),
): Promise<Response> {
  if (m !== null && method === "POST") await stepUp(m);
  const headers = new Headers({ origin: RP.origin });
  if (m !== null) headers.set("authorization", `Bearer ${m.token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handlePartnerInvitesRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-invites/${path}`,
      {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      },
    ),
    {
      db: partnerDb,
      allowedOrigin: RP.origin,
      registration: registrationVerifier,
      inviteOtp: otpInvite.port,
      enrolmentOtp: otpEnrol.port,
      nowMs,
      newSessionToken: newPartnerSessionToken,
      newInviteToken: newPartnerInviteToken,
    },
  );
}
async function memCall(
  m: Member | { token: string },
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<Response> {
  if ("hash" in m && m.hash !== "" && method === "POST")
    await stepUp(m as Member); // class A2: a reauth and a PIN grant (a session minted by the registration has no hash here)
  const headers = new Headers({
    origin: RP.origin,
    authorization: `Bearer ${m.token}`,
  });
  if (method === "POST") headers.set("content-type", "application/json");
  return await handlePartnerMembersRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-members/${path}`,
      {
        method,
        headers,
        body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
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

async function createdInvite(
  mgr: Member,
  org: string,
  email: string,
): Promise<{ id: string; token: string }> {
  const res = await invCall(mgr, "POST", "invites", {
    orgId: org,
    role: "staff",
    email,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const d = await dataOf(res);
  return { id: String(d.inviteId), token: String(d.token) };
}
const newAddress = (label: string): string => {
  seq += 1;
  return `adr-${label}-${RUN}-${seq}@integration.test`;
};
const inviteRow = async (id: string) =>
  (
    await rows(
      "app.partner_invite",
      (sql) =>
        sql`select accepted_by::text as accepted_by, accepted_at, attempts::int as attempts, registered_credential_id::text as registered from app.partner_invite where id = ${id}`,
    )
  )[0] as unknown as {
    accepted_by: string | null;
    accepted_at: Date | null;
    attempts: number;
    registered: string | null;
  };
const credentialsOf = async (uid: string) =>
  (await rows(
    "app.partner_credential",
    (sql) =>
      sql`select id::text as id, encode(credential_id, 'hex') as id_hex, encode(public_key, 'hex') as key_hex, revoked_at from app.partner_credential where user_id = ${uid} order by created_at, id`,
  )) as unknown as Array<{
    id: string;
    id_hex: string;
    key_hex: string;
    revoked_at: Date | null;
  }>;

/** accept/verify with the right code: the response data (options, challengeToken, userId, refKind, refId, ...). */
async function verified(
  token: string,
  kind: "invites" | "enrolments",
): Promise<Record<string, unknown>> {
  const res = await invCall(null, "POST", `${kind}/accept/verify`, {
    token,
    code: CODE,
  });
  assertEquals(res.status, 200, await res.clone().text());
  return await dataOf(res);
}
/** A real registration for the accepted person: a new software authenticator (the person's user handle), a creation response over the challenge, and the credentials POST. */
async function register(
  d: Record<string, unknown>,
  over: {
    userId?: string;
    refKind?: string;
    refId?: string;
    challengeToken?: string;
    nowMs?: () => number;
  } = {},
): Promise<{ res: Response; auth: SoftwareAuthenticator }> {
  const nonce = parseChallengeToken(String(d.challengeToken))!.nonce;
  const auth = await SoftwareAuthenticator.create(
    "ES256",
    uuidToBytes(String(d.userId))!,
  );
  const credential = await auth.register({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: nonce,
  });
  const res = await invCall(
    null,
    "POST",
    "credentials",
    {
      userId: over.userId ?? d.userId,
      refKind: over.refKind ?? d.refKind,
      refId: over.refId ?? d.refId,
      challengeToken: over.challengeToken ?? d.challengeToken,
      credential,
    },
    over.nowMs,
  );
  return { res, auth };
}

const ADMIN_UID = "00000000-0000-0000-0000-4000000000d0"; // seeded by the harness (helpers.sql) into app.admin_user
let adminSession: Member | null = null;
/** The seeded admin, signed in once with a real credential; its step-up is re-seeded on every use because `mfa_until` is short. */
async function admin(aal = 2, mfaSeconds = 240): Promise<Member> {
  adminSession ??= await signInAs(ADMIN_UID, "admin@integration.test");
  await stepUpA3(adminSession, aal, mfaSeconds);
  return adminSession;
}
/** An operator of a fresh operator org (trail scope): a member who is not an admin. */
async function newOperator(label: string, withTotp = true): Promise<Member> {
  seq += 1;
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'operator', ${"admin routes org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, trail_id) values (${org}, 'trl_t')`,
  );
  const uid = freshUuid();
  const name = `adr-${label}-${RUN}-${seq}`;
  await ensureServiceRole();
  await adminSql()`insert into auth.users (id, email, email_confirmed_at) values (${uid}, ${name + "@integration.test"}, now())`;
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, 'operator', now() - interval '60 days')`,
  );
  if (withTotp) {
    await rows(
      "app.partner_totp",
      (sql) =>
        sql`insert into app.partner_totp (user_id, seed_version, enrolled_at, confirmed_at, last_step, failed_count, locked_until) values (${uid}, 3, now() - interval '30 days', now() - interval '30 days', 12345678, 2, now() + interval '1 minute')`,
    );
  }
  return await signInAs(uid, `${name}@integration.test`);
}
const totpRow = async (uid: string) =>
  (
    await rows(
      "app.partner_totp",
      (sql) =>
        sql`select seed_version::int as seed_version, enrolled_at, confirmed_at, enrol_session_id, last_step, failed_count::int as failed_count, locked_until, revoked_at from app.partner_totp where user_id = ${uid}`,
    )
  )[0] as unknown as
    | {
        seed_version: number;
        enrolled_at: Date | null;
        confirmed_at: Date | null;
        enrol_session_id: string | null;
        last_step: string | null;
        failed_count: number;
        locked_until: Date | null;
        revoked_at: Date | null;
      }
    | undefined;
/** Whether the session is alive: not the binder's one 401. An operator or admin at aal 1 is alive but refused (403) by the assurance level, so 200 and 403 both mean alive. */
const live = async (m: { token: string }): Promise<boolean> => {
  const r = await memCall(m, "GET", "credentials");
  await r.arrayBuffer();
  return r.status !== 401;
};

Deno.test(
  "S1.3 / 6.4, class A3: an admin resets an operator's TOTP: the seed version moves on, the enrolment, the confirmation, the replay step, the failure count and the lock are cleared, the person's sessions are revoked, and the answer is {reset: true}; a person with no TOTP is 409 totp_not_set",
  DT,
  async () => {
    const target = await newOperator("target");
    const before = (await totpRow(target.uid))!;
    assertEquals(
      [
        before.seed_version,
        before.failed_count,
        before.confirmed_at !== null,
        before.locked_until !== null,
      ],
      [3, 2, true, true],
    );
    assert(await live(target), "the target's session is live before the reset");

    const a = await admin();
    const res = await memCall(a, "POST", `members/${target.uid}/totp-reset`);
    assertEquals(res.status, 200, await res.clone().text());
    assertEquals(await dataOf(res), { reset: true });
    const after = (await totpRow(target.uid))!;
    assertEquals(
      [
        after.seed_version,
        after.enrolled_at,
        after.confirmed_at,
        after.enrol_session_id,
        after.last_step,
        after.failed_count,
        after.locked_until,
        after.revoked_at,
      ],
      [4, null, null, null, null, 0, null, null],
      "the seed moves on and the factor is unenrolled, unlocked and unconfirmed",
    );
    assertEquals(
      await live(target),
      false,
      "the person's sessions are revoked",
    );

    // a person with no TOTP row: nothing to reset
    const none = await newOperator("none", false);
    const r2 = await memCall(
      await admin(),
      "POST",
      `members/${none.uid}/totp-reset`,
    );
    assertEquals([r2.status, await errOf(r2)], [409, "totp_not_set"]);
    assertEquals(await totpRow(none.uid), undefined, "no row was invented");
  },
);

Deno.test(
  "S1.3 / 6.4, class A3, who may: only an admin resets a TOTP (an operator is 403 whoever the target is), the target must be an operator or an admin (a staff member is 403), oneself is 422, an admin at aal 1 or with a lapsed second factor is 403; a refusal changes nothing and signs nobody out",
  DT,
  async () => {
    const target = await newOperator("target");
    const peer = await newOperator("peer");
    const org = await newOrg();
    const staff = await newMember(org, "staff", "staff");
    const snapshot = await totpRow(target.uid);

    await stepUpA3(peer);
    const byOperator = await memCall(
      peer,
      "POST",
      `members/${target.uid}/totp-reset`,
    );
    assertEquals(
      [byOperator.status, await errOf(byOperator)],
      [403, "forbidden"],
    );

    const a = await admin();
    const staffTarget = await memCall(
      a,
      "POST",
      `members/${staff.uid}/totp-reset`,
    );
    assertEquals(
      [staffTarget.status, await errOf(staffTarget)],
      [403, "forbidden"],
      "a staff member has no TOTP to reset",
    );
    const self = await memCall(
      await admin(),
      "POST",
      `members/${ADMIN_UID}/totp-reset`,
    );
    assertEquals(self.status, 422, await self.clone().text());
    await admin(1);
    assertEquals(
      (await memCall(adminSession!, "POST", `members/${target.uid}/totp-reset`))
        .status,
      403,
      "aal 1",
    );
    await admin(2, -5);
    assertEquals(
      (await memCall(adminSession!, "POST", `members/${target.uid}/totp-reset`))
        .status,
      403,
      "a lapsed second factor",
    );

    assertEquals(
      await totpRow(target.uid),
      snapshot,
      "no refusal touched the TOTP row",
    );
    assert(
      (await live(target)) && (await live(peer)) && (await live(staff)),
      "no refusal signed anybody out",
    );
    // the control: the same admin with the step-up resets it
    assertEquals(
      (await memCall(await admin(), "POST", `members/${target.uid}/totp-reset`))
        .status,
      200,
    );
  },
);

Deno.test(
  "S1.5 / 6.4, class A3: an admin issues an enrolment token for ANOTHER admin: the database holds the SHA-256 of the gr_enr_ token for that person with purpose admin, issued by that admin, for 24 hours; the target must be an admin, the actor must be an admin at aal 2, and the body is strict",
  DT,
  async () => {
    const second = freshUuid();
    await ensureServiceRole();
    await adminSql()`insert into auth.users (id, email, email_confirmed_at) values (${second}, ${"adr-admin2-" + RUN + "@integration.test"}, now())`;
    await rows(
      "app.admin_user",
      (sql) => sql`insert into app.admin_user (user_id) values (${second})`,
    );
    try {
      const a = await admin();
      const res = await memCall(a, "POST", "admin/enrolments", {
        userId: second,
      });
      assertEquals(res.status, 201, await res.clone().text());
      const d = await dataOf(res);
      const token = String(d.token);
      assert(PARTNER_ENROLMENT_TOKEN_RE.test(token), "the Edge's token format");
      assertEquals(d.enrolUrl, `${RP.origin}/enrol#${token}`);
      const ttlH = (Date.parse(String(d.expiresAt)) - Date.now()) / 3_600_000;
      assert(ttlH > 23 && ttlH <= 24, `expires in 24 hours (${ttlH} h)`);
      const [row] = await rows(
        "app.partner_enrolment_token",
        (sql) =>
          sql`select token_hash, purpose::text as purpose, issued_by::text as issued_by, user_id::text as user_id, consumed_at, revoked_at from app.partner_enrolment_token where id = ${String(d.tokenId)}`,
      );
      assertEquals(
        [
          row!.token_hash,
          row!.purpose,
          row!.issued_by,
          row!.user_id,
          row!.consumed_at,
          row!.revoked_at,
        ],
        [await sha256Hex(token), "admin", ADMIN_UID, second, null, null],
      );
      assert(
        !JSON.stringify(row).includes(token),
        "the plaintext token is in no column",
      );

      // who may not
      const notAdmin = await newOperator("target");
      const toOperator = await memCall(
        await admin(),
        "POST",
        "admin/enrolments",
        { userId: notAdmin.uid },
      );
      assertEquals(
        [toOperator.status, await errOf(toOperator)],
        [403, "forbidden"],
        "the target must be an admin",
      );
      const toSelf = await memCall(await admin(), "POST", "admin/enrolments", {
        userId: ADMIN_UID,
      });
      assertEquals(toSelf.status, 422, "another admin, not oneself");
      const op = await newOperator("actor", false);
      await stepUpA3(op);
      const byOperator = await memCall(op, "POST", "admin/enrolments", {
        userId: second,
      });
      assertEquals(
        [byOperator.status, await errOf(byOperator)],
        [403, "forbidden"],
        "only an admin issues one",
      );
      await admin(1);
      assertEquals(
        (
          await memCall(adminSession!, "POST", "admin/enrolments", {
            userId: second,
          })
        ).status,
        403,
        "aal 1",
      );
      for (const bad of [
        {},
        { userId: "nope" },
        { userId: second, extra: 1 },
      ]) {
        assertEquals(
          (await memCall(await admin(), "POST", "admin/enrolments", bad))
            .status,
          400,
          JSON.stringify(bad),
        );
      }
      const tokens = await rows(
        "app.partner_enrolment_token",
        (sql) =>
          sql`select count(*)::int as n from app.partner_enrolment_token where user_id = ${second}`,
      );
      assertEquals(Number(tokens[0]!.n), 1, "no refusal issued a token");
    } finally {
      await rows(
        "app.admin_user",
        (sql) => sql`delete from app.admin_user where user_id = ${second}`,
      );
    }
  },
);

Deno.test(
  "S1.5 / 6.4: the admin enrolment token is redeemed by the admin it was issued for, who has no credential yet: the code goes through the enrolment port, the proof says purpose admin, a real registration stores the key and mints a session; a person who is not an admin cannot redeem it, and the token cannot be used twice",
  DT,
  async () => {
    resetOtp();
    const second = freshUuid();
    const email = `adr-admin3-${RUN}@integration.test`;
    await ensureServiceRole();
    await adminSql()`insert into auth.users (id, email, email_confirmed_at) values (${second}, ${email}, now())`;
    await rows(
      "app.admin_user",
      (sql) => sql`insert into app.admin_user (user_id) values (${second})`,
    );
    try {
      const issued = await dataOf(
        await memCall(await admin(), "POST", "admin/enrolments", {
          userId: second,
        }),
      );
      const token = String(issued.token);

      const start = await invCall(null, "POST", "enrolments/accept/start", {
        token,
      });
      assertEquals(start.status, 200, await start.clone().text());
      assertEquals(
        otpEnrol.sent,
        [email],
        "the code goes to the admin's own address",
      );

      const d = await verified(token, "enrolments");
      assertEquals(
        [d.refKind, d.refId, d.purpose, d.userId],
        ["enrolment", issued.tokenId, "admin", second],
      );
      const { res, auth } = await register(d);
      assertEquals(res.status, 201, await res.clone().text());
      const session = await dataOf(res);
      const [cred] = await credentialsOf(second);
      assertEquals(
        [cred!.id_hex, cred!.key_hex],
        [hex(auth.credentialId), hex(auth.cosePublicKey)],
      );
      // the first session is aal 1: alive, but an admin needs the second factor for everything (403, not 401) until it is raised
      const fresh = {
        token: String(session.token),
        hash: await sha256Hex(String(session.token)),
        uid: second,
        email,
      };
      assertEquals(
        (await memCall(fresh, "GET", "credentials")).status,
        403,
        "alive but below the required assurance level",
      );
      await stepUpA3(fresh);
      assertEquals(
        (await memCall(fresh, "GET", "credentials")).status,
        200,
        "and it works once the second factor is raised",
      );
      const [t] = await rows(
        "app.partner_enrolment_token",
        (sql) =>
          sql`select consumed_at, registered_credential_id::text as registered from app.partner_enrolment_token where id = ${String(issued.tokenId)}`,
      );
      assert(t!.consumed_at instanceof Date && t!.registered === cred!.id);
      const reuse = await invCall(null, "POST", "enrolments/accept/verify", {
        token,
        code: CODE,
      });
      assertEquals([reuse.status, await errOf(reuse)], [403, "accept_refused"]);
    } finally {
      await rows(
        "app.admin_user",
        (sql) => sql`delete from app.admin_user where user_id = ${second}`,
      );
    }

    // an admin token for a person who is not (or is no longer) an admin: the proof is refused
    const notAdmin = await newOperator("notadmin", false);
    const forged = freshUuid();
    const forgedToken = await newPartnerEnrolmentToken();
    await rows(
      "app.partner_enrolment_token",
      (sql) =>
        sql`insert into app.partner_enrolment_token (id, user_id, purpose, issued_by, token_hash, expires_at) values (${forged}, ${notAdmin.uid}, 'admin', ${ADMIN_UID}, ${forgedToken.hash}, now() + interval '1 hour')`,
    );
    // that person has a credential, so the database answers existing_member_sign_in first: a 409, and nothing consumed
    const refused = await invCall(null, "POST", "enrolments/accept/verify", {
      token: forgedToken.token,
      code: CODE,
    });
    assert(
      refused.status === 409 || refused.status === 403,
      `refused (${refused.status})`,
    );
    const [after] = await rows(
      "app.partner_enrolment_token",
      (sql) =>
        sql`select consumed_at from app.partner_enrolment_token where id = ${forged}`,
    );
    assertEquals(after!.consumed_at, null, "a refused proof consumes nothing");
  },
);

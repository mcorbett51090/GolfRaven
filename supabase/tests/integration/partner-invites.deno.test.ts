// supabase/tests/integration/partner-invites.deno.test.ts
//
// Slice S1.5 / 0054 (docs/security/partner-auth-design.md 4.5, 6.1, 8, 22.4, 129): the REAL `partner-invites` handler over the REAL privileged.ts (`partnerDb.withInvites` = `withPartnerSession`, `hitRateLimit`,
// `hitSystemRateLimit`), REAL manager and staff sessions minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the
// provisioned `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port; the pgTAP matrix calls the definers directly. Neither runs three properties that live BETWEEN them: (1) the handler's promise "COMMIT ON EVERY
// STATUS (PA-14)": a refusal the database makes (a wrong mailbox, an unconfirmed address, `already_member`) is a RETURNED row, so the attempt count it incremented must be COMMITTED, which only holds if the Edge's transaction
// really commits on that path and the invite is really locked after ten of them; (2) the list is filtered by the TABLE POLICY under the bound `edge_partner` transaction, so another organisation's manager sees nothing, and
// the revoke of another organisation's invite is the same 404 as an unknown id; (3) the two daily caps (20 a day per inviter, 3 a day per invitee address) are counted by real buckets in the database.
//
// Branch E (an existing member joins another organisation) is driven end to end. Branch N (accept/start, accept/verify, credentials) needs GoTrue's email OTP and a fresh GoTrue session, neither of which the harness has; it
// stays covered by the unit suite and the pgTAP matrix, and is not driven here.
//
// The same shortcut as the other partner integration files: a session's step-up state (a passkey reauth in the last 5 minutes, a PIN grant of 50 s, one per action) is written by the OWNER with the guard trigger off for
// that statement only; the reauth and the PIN themselves are proved elsewhere.

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
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import {
  parseChallengeToken,
  uuidToBytes,
} from "../../functions/_shared/partner/session-shape.ts";
import {
  newPartnerInviteToken,
  newPartnerSessionToken,
  PARTNER_INVITE_TOKEN_RE,
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

async function sessionCall(
  method: string,
  path: string,
  body: unknown,
): Promise<Response> {
  const headers = new Headers({
    origin: RP.origin,
    "content-type": "application/json",
  });
  return await handlePartnerSessionRequest(
    new Request(
      `https://project.example.test/functions/v1/partner-session/${path}`,
      { method, headers, body: JSON.stringify(body) },
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
let seq = 0;
/** A run-unique suffix: the daily caps are counted per address and per member in a database every integration file shares. */
const RUN = freshUuid().slice(0, 8);
/** A real credential for `uid` and a session from the real mint (the software authenticator's real assertion). */
async function signInAs(uid: string, email: string): Promise<Member> {
  const auth = await SoftwareAuthenticator.create("ES256", uuidToBytes(uid)!);
  await rows(
    "app.partner_credential",
    (sql) =>
      sql`insert into app.partner_credential (user_id, credential_id, public_key, alg, sign_count) values (${uid}, decode(${hex(auth.credentialId)}::text, 'hex'), decode(${hex(auth.cosePublicKey)}::text, 'hex'), -7, 0)`,
  );
  const o = await sessionCall("POST", "options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parsed.nonce,
  });
  const res = await sessionCall("POST", "verify", {
    challengeToken: d.challengeToken,
    credential: cred,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, email, token, hash: await sha256Hex(token) };
}

/** A facility org scoped to `facility` (fac_x and fac_y are seeded by helpers.sql). */
async function newOrg(facility = FAC): Promise<string> {
  seq += 1;
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'facility', ${"invite org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, facility_id) values (${org}, ${facility})`,
  );
  return org;
}
const FAC = "fac_x";
/** A second facility: an organisation scoped to it has no scope over fac_x. The policies filter by FACILITY scope (an invite is visible to its inviter, an admin, and a manager or operator of the invite's facility), so two organisations on the SAME facility do see each other's invites. */
const OTHER_FAC = "fac_y";

/** A member of `org` with a role, a real credential and a session from the real mint. Its address is `<label>-<run>-<n>@integration.test`; `confirmed` sets GoTrue's email_confirmed_at (branch E needs it). */
async function newMember(
  org: string,
  role: "staff" | "manager",
  label: string,
  confirmed = true,
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  const name = `${label}-${RUN}-${seq}`;
  await newAuthUser(uid, name, confirmed);
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${role}, now() - interval '60 days')`,
  );
  return await signInAs(uid, `${name}@integration.test`);
}
/** The auth user createTestUser would make, with GoTrue's email_confirmed_at set (or not) AT INSERT: service_role may insert any column of auth.users but update only last_sign_in_at (shim.sql). */
async function newAuthUser(
  uid: string,
  name: string,
  confirmed: boolean,
): Promise<void> {
  await ensureServiceRole();
  const sql = adminSql();
  await sql`insert into auth.users (id, email, email_confirmed_at) values (${uid}, ${name + "@integration.test"}, ${confirmed ? new Date() : null})`;
  await sql`insert into app.profile (user_id, handle) values (${uid}, ${"u" + uid.replace(/-/g, "").slice(0, 19)})`;
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

async function invCall(
  m: Member | null,
  method: "GET" | "POST" | "DELETE",
  path: string,
  body?: unknown,
  withStepUp = method !== "GET",
): Promise<Response> {
  if (m !== null && withStepUp) await stepUp(m);
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
      registration: {
        options: () => Promise.reject(new Error("unused")),
        verify: () => Promise.reject(new Error("unused")),
      },
      inviteOtp: {
        send: () => Promise.reject(new Error("unused")),
        verify: () => Promise.reject(new Error("unused")),
      },
      enrolmentOtp: {
        send: () => Promise.reject(new Error("unused")),
        verify: () => Promise.reject(new Error("unused")),
      },
      nowMs: () => Date.now(),
      newSessionToken: newPartnerSessionToken,
      newInviteToken: newPartnerInviteToken,
    },
  );
}
const errOf = async (res: Response) => (await res.json()).error?.code as string;
const create = (m: Member, org: string, role: string, email: string) =>
  invCall(m, "POST", "invites", { orgId: org, role, email });
const accept = (m: Member, token: string) =>
  invCall(m, "POST", "invites/accept", { token });

interface InviteRow {
  id: string;
  org_id: string;
  role: string;
  facility_id: string | null;
  invited_by: string;
  invitee_email: string;
  token_hash: string;
  expires_at: Date;
  accepted_at: Date | null;
  accepted_by: string | null;
  revoked_at: Date | null;
  attempts: number;
}
const inviteRow = async (id: string): Promise<InviteRow> =>
  (
    await rows(
      "app.partner_invite",
      (sql) =>
        sql`select id::text as id, org_id::text as org_id, role::text as role, facility_id, invited_by::text as invited_by, invitee_email, token_hash, expires_at, accepted_at, accepted_by::text as accepted_by, revoked_at, attempts::int as attempts from app.partner_invite where id = ${id}`,
    )
  )[0] as unknown as InviteRow;
const invitesFor = async (email: string): Promise<number> =>
  Number(
    (
      await rows(
        "app.partner_invite",
        (sql) =>
          sql`select count(*)::int as n from app.partner_invite where invitee_email = ${email}`,
      )
    )[0]!.n,
  );
const membershipOf = async (uid: string, org: string) =>
  (
    await rows(
      "app.partner_member",
      (sql) =>
        sql`select role::text as role, invited_by::text as invited_by, revoked_at from app.partner_member where user_id = ${uid} and org_id = ${org}`,
    )
  ).map((r) => ({
    role: String(r.role),
    invited_by: r.invited_by === null ? null : String(r.invited_by),
    revoked: r.revoked_at !== null,
  }));
/** An invite created through the handler: the id and the one-time token. */
async function createdInvite(
  m: Member,
  org: string,
  role: string,
  email: string,
): Promise<{ id: string; token: string }> {
  const res = await create(m, org, role, email);
  assertEquals(res.status, 201, await res.clone().text());
  const d = (await res.json()).data as { inviteId: string; token: string };
  return { id: d.inviteId, token: d.token };
}

Deno.test(
  "S1.5: a manager's invite comes back once with its link; the database holds the SHA-256 of the token and the normalised address; the list shows it without the token, and another organisation's manager sees nothing",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "inv-mgr");
    const other = await newMember(
      await newOrg(OTHER_FAC),
      "manager",
      "inv-mgr",
    );

    const res = await create(
      mgr,
      org,
      "staff",
      "  New.Hire+Tag@Integration.TEST ",
    );
    assertEquals(res.status, 201, await res.clone().text());
    const d = (await res.json()).data as {
      inviteId: string;
      expiresAt: string;
      token: string;
      inviteUrl: string;
    };
    assert(PARTNER_INVITE_TOKEN_RE.test(d.token), "the Edge's token format");
    assertEquals(
      d.inviteUrl,
      `${RP.origin}/invite#${d.token}`,
      "the token travels in the link's fragment",
    );
    const ttlH = (Date.parse(d.expiresAt) - Date.now()) / 3_600_000;
    assert(ttlH > 71 && ttlH <= 72, `expires in 72 hours (${ttlH} h)`);

    const row = await inviteRow(d.inviteId);
    assertEquals(
      [
        row.token_hash,
        row.invitee_email,
        row.role,
        row.facility_id,
        row.invited_by,
        row.org_id,
        row.accepted_at,
        row.revoked_at,
        row.attempts,
      ],
      [
        await sha256Hex(d.token),
        "new.hire+tag@integration.test",
        "staff",
        FAC,
        mgr.uid,
        org,
        null,
        null,
        0,
      ],
    );
    assert(
      !JSON.stringify(row).includes(d.token),
      "the plaintext token is in no column",
    );

    const list = await invCall(mgr, "GET", `invites?orgId=${org}`);
    assertEquals(list.status, 200, await list.clone().text());
    const text = await list.text();
    assert(
      !text.includes(d.token) && !text.includes(row.token_hash),
      "the list never carries the token or its hash",
    );
    const mine = (
      JSON.parse(text).data.invites as Array<Record<string, unknown>>
    ).find((i) => i.id === d.inviteId)!;
    assert(mine, "the creator sees the invite");
    assertEquals(
      [
        mine.orgId,
        mine.role,
        mine.facilityId,
        mine.inviteeEmail,
        mine.invitedBy,
        mine.acceptedAt,
        mine.revokedAt,
        mine.attempts,
      ],
      [
        org,
        "staff",
        FAC,
        "new.hire+tag@integration.test",
        mgr.uid,
        null,
        null,
        0,
      ],
    );
    assert(
      !Number.isNaN(Date.parse(String(mine.createdAt))) &&
        !Number.isNaN(Date.parse(String(mine.expiresAt))),
      "ISO timestamps",
    );

    for (const q of [`invites?orgId=${org}`, "invites"]) {
      const theirs = await invCall(other, "GET", q);
      assertEquals(theirs.status, 200, await theirs.clone().text());
      assert(
        !((await theirs.json()).data.invites as Array<{ id: string }>).some(
          (i) => i.id === d.inviteId,
        ),
        `another organisation's manager does not see it (${q})`,
      );
    }
    // the control: the policy is the FACILITY scope, not the organisation, so a manager of another organisation at the same facility does see it
    const neighbour = await newMember(await newOrg(), "manager", "inv-mgr");
    const near = await invCall(neighbour, "GET", `invites?orgId=${org}`);
    assertEquals(near.status, 200, await near.clone().text());
    assert(
      ((await near.json()).data.invites as Array<{ id: string }>).some(
        (i) => i.id === d.inviteId,
      ),
      "a manager at the same facility sees it",
    );
    const anon = await invCall(null, "GET", "invites");
    assertEquals(anon.status, 401);
  },
);

Deno.test(
  "S1.5 / branch E: an existing member of another organisation accepts with the token from the link: the membership is written for that person with the inviter on it, the invite is spent, and the same token again is refused",
  DT,
  async () => {
    const orgA = await newOrg();
    const mgr = await newMember(orgA, "manager", "inv-mgr");
    const orgB = await newOrg();
    const invitee = await newMember(orgB, "staff", "inv-ee");

    const { id, token } = await createdInvite(
      mgr,
      orgA,
      "staff",
      invitee.email,
    );
    const ok = await accept(invitee, token);
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals((await ok.json()).data, { orgId: orgA, role: "staff" });

    assertEquals(await membershipOf(invitee.uid, orgA), [
      { role: "staff", invited_by: mgr.uid, revoked: false },
    ]);
    assertEquals(
      (await membershipOf(invitee.uid, orgB)).length,
      1,
      "the other membership is untouched",
    );
    const row = await inviteRow(id);
    assertEquals([row.accepted_by, row.attempts], [invitee.uid, 1]);
    assert(row.accepted_at instanceof Date, "the invite is spent");

    const again = await accept(invitee, token);
    assertEquals([again.status, await errOf(again)], [403, "invite_refused"]);
    assertEquals(
      (await membershipOf(invitee.uid, orgA)).length,
      1,
      "no second membership",
    );
  },
);

Deno.test(
  "S1.5 / PA-14: a refusal commits the attempt count (a wrong mailbox, then an unconfirmed address), and ten of them lock the invite against even the right mailbox",
  DT,
  async () => {
    const orgA = await newOrg();
    const mgr = await newMember(orgA, "manager", "inv-mgr");
    const orgB = await newOrg();
    const right = await newMember(orgB, "staff", "inv-right");
    const wrong = await newMember(orgB, "staff", "inv-wrong");
    const unconfirmed = await newMember(orgB, "staff", "inv-unconf", false);

    // a wrong mailbox (a forwarded link): refused, and the attempt is on the row
    const one = await createdInvite(mgr, orgA, "staff", right.email);
    const w = await accept(wrong, one.token);
    assertEquals([w.status, await errOf(w)], [403, "invite_refused"]);
    let row = await inviteRow(one.id);
    assertEquals([row.attempts, row.accepted_at], [1, null]);
    // the right mailbox still gets in, and its own attempt is counted too
    const ok = await accept(right, one.token);
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals((await inviteRow(one.id)).attempts, 2);

    // an address GoTrue has not confirmed: refused and counted (the confirmed `right` member above differs from this one in nothing but the confirmation, so it is the control)
    const two = await createdInvite(mgr, orgA, "staff", unconfirmed.email);
    const u = await accept(unconfirmed, two.token);
    assertEquals([u.status, await errOf(u)], [403, "invite_refused"]);
    assertEquals((await inviteRow(two.id)).attempts, 1);
    assertEquals(
      (await membershipOf(unconfirmed.uid, orgA)).length,
      0,
      "no membership from a refusal",
    );

    // ten refusals lock the invite: the eleventh attempt, from the right mailbox, is refused and no longer counted
    const target = await newMember(orgB, "staff", "inv-lock");
    const three = await createdInvite(mgr, orgA, "staff", target.email);
    for (let i = 0; i < 10; i++) {
      const r = await accept(wrong, three.token);
      assertEquals([r.status, await errOf(r)], [403, "invite_refused"]);
    }
    assertEquals((await inviteRow(three.id)).attempts, 10);
    const locked = await accept(target, three.token);
    assertEquals([locked.status, await errOf(locked)], [403, "invite_refused"]);
    row = await inviteRow(three.id);
    assertEquals([row.attempts, row.accepted_at], [10, null]);
    assertEquals((await membershipOf(target.uid, orgA)).length, 0);
  },
);

Deno.test(
  "S1.5: an address that is already an active member is 409 already_member (nothing written), accepting into an organisation you are already in is 409 already_member, and the revoke vocabulary is ok / 409 invite_revoked / 409 invite_accepted / 404 (another organisation's invite is the same 404 as an unknown id)",
  DT,
  async () => {
    const orgA = await newOrg();
    const mgr = await newMember(orgA, "manager", "inv-mgr");
    const other = await newMember(
      await newOrg(OTHER_FAC),
      "manager",
      "inv-mgr",
    );
    const member = await newMember(orgA, "staff", "inv-already");

    const dup = await create(mgr, orgA, "staff", member.email.toUpperCase());
    assertEquals([dup.status, await errOf(dup)], [409, "already_member"]);
    assertEquals(
      await invitesFor(member.email),
      0,
      "an already_member answer writes no invite",
    );

    // accepting into an organisation you are already in: the invite is planted by the owner (the handler would not have created it)
    const planted = await newPartnerInviteToken();
    await rows(
      "app.partner_invite",
      (sql) =>
        sql`insert into app.partner_invite (org_id, role, facility_id, invited_by, invitee_email, token_hash, expires_at) values (${orgA}, 'staff', ${FAC}, ${mgr.uid}, ${member.email}, ${planted.hash}, now() + interval '72 hours')`,
    );
    const already = await accept(member, planted.token);
    assertEquals(
      [already.status, await errOf(already)],
      [409, "already_member"],
    );
    assertEquals((await membershipOf(member.uid, orgA)).length, 1);

    // revoke
    const revokee = await newMember(await newOrg(), "staff", "inv-rev");
    const { id, token } = await createdInvite(
      mgr,
      orgA,
      "staff",
      revokee.email,
    );
    const foreign = await invCall(other, "DELETE", `invites/${id}`);
    assertEquals([foreign.status, await errOf(foreign)], [404, "not_found"]);
    assertEquals(
      (await inviteRow(id)).revoked_at,
      null,
      "another organisation's manager revoked nothing",
    );
    const unknown = await invCall(mgr, "DELETE", `invites/${freshUuid()}`);
    assertEquals([unknown.status, await errOf(unknown)], [404, "not_found"]);
    const ok = await invCall(mgr, "DELETE", `invites/${id}`);
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals((await ok.json()).data, { revoked: true });
    assert(
      (await inviteRow(id)).revoked_at instanceof Date,
      "revoked_at is set",
    );
    const twice = await invCall(mgr, "DELETE", `invites/${id}`);
    assertEquals([twice.status, await errOf(twice)], [409, "invite_revoked"]);
    const dead = await accept(revokee, token);
    assertEquals([dead.status, await errOf(dead)], [403, "invite_refused"]);
    assertEquals(
      (await membershipOf(revokee.uid, orgA)).length,
      0,
      "a revoked token joins nobody",
    );

    const spent = await createdInvite(mgr, orgA, "staff", revokee.email);
    assertEquals((await accept(revokee, spent.token)).status, 200);
    const late = await invCall(mgr, "DELETE", `invites/${spent.id}`);
    assertEquals([late.status, await errOf(late)], [409, "invite_accepted"]);
  },
);

Deno.test(
  "S1.5 / A2: a staff member cannot invite, a manager cannot invite a manager or an operator, a create without the reauth or without the PIN grant is refused, and a malformed body is 400: in every case nothing is written",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "inv-mgr");
    const staff = await newMember(org, "staff", "inv-staff");
    const email = (n: string) => `${n}-${RUN}-${seq}@integration.test`;

    // the control: the same manager, with the same kind of session and step-up, CAN invite staff, so each refusal below is about the thing it names and not about a create path that is closed for everyone
    await createdInvite(mgr, org, "staff", email("ctl"));

    for (const [who, role, why] of [
      [staff, "staff", "a staff member"],
      [
        mgr,
        "manager",
        "a manager inviting a manager (the grant must be a subset of the inviter's reach)",
      ],
      [mgr, "operator", "a manager inviting an operator (only an admin does)"],
    ] as const) {
      const to = email("deny");
      const res = await create(who, org, role, to);
      assertEquals(res.status, 403, `${why}: ${await res.clone().text()}`);
      assertEquals(await invitesFor(to), 0, `${why}: nothing written`);
    }

    // class A2 wants BOTH a passkey reauth in the last 5 minutes and a fresh PIN grant: each missing alone is a refusal
    for (const [label, seed] of [
      [
        "no PIN grant",
        "reauth_until = clock_timestamp() + interval '200 seconds'",
      ],
      [
        "no reauth",
        "pin_grant_until = clock_timestamp() + interval '50 seconds'",
      ],
    ] as const) {
      const to = email("step");
      await rows("app.partner_session", async (sql) => {
        await sql.unsafe(
          "alter table app.partner_session disable trigger partner_session_guard_trg",
        );
        try {
          await sql.unsafe(
            `update app.partner_session set reauth_until = null, pin_grant_until = null where token_hash = '${mgr.hash}'`,
          );
          await sql.unsafe(
            `update app.partner_session set ${seed} where token_hash = '${mgr.hash}'`,
          );
        } finally {
          await sql.unsafe(
            "alter table app.partner_session enable trigger partner_session_guard_trg",
          );
        }
      });
      const res = await invCall(
        mgr,
        "POST",
        "invites",
        { orgId: org, role: "staff", email: to },
        false,
      );
      assertEquals(res.status, 403, `${label}: ${await res.clone().text()}`);
      assertEquals(await invitesFor(to), 0, `${label}: nothing written`);
    }

    for (const body of [
      { orgId: org, role: "staff", email: email("bad"), extra: 1 },
      { orgId: org, role: "sponsor", email: email("bad") },
      { orgId: org, role: "staff", email: "not an address" },
      { orgId: "nope", role: "staff", email: email("bad") },
    ]) {
      const res = await invCall(mgr, "POST", "invites", body);
      assertEquals(res.status, 400, JSON.stringify(body));
    }
    assertEquals(await invitesFor(email("bad")), 0);
  },
);

Deno.test(
  "S1.5 / design 8: three invites a day to one address, then 429 with a Retry-After; twenty invites a day from one inviter, then 429: the refused create writes no invite",
  DT,
  async () => {
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "inv-mgr");
    const same = `cap-${RUN}-${seq}@integration.test`;
    for (let i = 0; i < 3; i++) await createdInvite(mgr, org, "staff", same);
    const fourth = await create(mgr, org, "staff", same);
    assertEquals([fourth.status, await errOf(fourth)], [429, "rate_limited"]);
    assert(
      Number(fourth.headers.get("retry-after")) >= 1,
      "a Retry-After in seconds",
    );
    assertEquals(await invitesFor(same), 3, "the refused fourth wrote nothing");

    const busy = await newMember(org, "manager", "inv-busy");
    for (let i = 0; i < 20; i++)
      await createdInvite(
        busy,
        org,
        "staff",
        `many-${RUN}-${seq}-${i}@integration.test`,
      );
    const over = `many-${RUN}-${seq}-over@integration.test`;
    const res = await create(busy, org, "staff", over);
    assertEquals([res.status, await errOf(res)], [429, "rate_limited"]);
    assertEquals(
      await invitesFor(over),
      0,
      "the refused twenty-first wrote nothing",
    );
    // the cap is the inviter's own: another manager is not slowed down
    const calm = await createdInvite(
      mgr,
      org,
      "staff",
      `calm-${RUN}-${seq}@integration.test`,
    );
    assert(calm.id.length > 0);
  },
);

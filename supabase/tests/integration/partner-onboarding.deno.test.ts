// supabase/tests/integration/partner-onboarding.deno.test.ts
//
// Slice S1.5 / 0054 (docs/security/partner-auth-design.md 6.1, 6.5, 8, 22.4, 135): the new person's way in. The REAL `partner-invites` handler (branch N: accept/start, accept/verify, credentials) over the REAL privileged.ts
// (`partnerDb.withInviteMint`, `hitSystemRateLimit`) and the REAL registration wrapper, against the REAL database tools/db/test.sh builds (as `edge_partner_minter`, the unbound lane). The ONE thing not real is GoTrue's email
// OTP: the invitee types a code from a mailbox, and the harness has no GoTrue, so the OTP port is a recording fake that does what `verifyOtp` does for the database's sake (it creates the account for an invite, and a REAL
// `auth.sessions` row for the proven person, and the handler closes it after the proof). Everything the database does with that proof, and everything the Edge does around it, is the real code.
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler mocked ports and the pgTAP matrix calls the definers with its own SQL. Neither runs the chain: the invite's address reaching the mail port, the accept
// definer's register challenge (a nonce, an expiry and a MAC the Edge must hand to the browser UNCHANGED, as the creation options' challenge and as the challenge token), a REAL registration ceremony from a software
// authenticator verified by the REAL wrapper, the first credential and the first SESSION minted in one transaction, and a sign-in-less session that then works. It is the first thing every new staff member does.
//
// Not driven: the GoTrue adapter itself (`partnerInviteEmailOtp` / `partnerEmailOtp` in privileged.ts: the real verifyOtp, its account creation and its session), and the admin enrolment (class A3).

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
  const name = `onb-${label}-${RUN}-${seq}`;
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
  return `onb-${label}-${RUN}-${seq}@integration.test`;
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

Deno.test(
  "S1.5 / 6.1, branch N: a new person's whole way in: the invite's address gets the code (an unknown token gets the same answer and no mail), the proof yields the register challenge the browser is given unchanged, a real passkey registration stores exactly the key the authenticator holds and mints the first session, and that session works",
  DT,
  async () => {
    resetOtp();
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const email = newAddress("new");
    const { id: inviteId, token } = await createdInvite(mgr, org, email);

    // accept/start: ONE constant answer, the code goes only to the address ON the invite
    const unknown = await invCall(null, "POST", "invites/accept/start", {
      token: "gr_inv_" + "A".repeat(43),
    });
    const real = await invCall(null, "POST", "invites/accept/start", { token });
    assertEquals([unknown.status, real.status], [200, 200]);
    assertEquals(
      await unknown.json(),
      await real.json(),
      "the answer does not say whether the token exists",
    );
    assertEquals(
      otpInvite.sent,
      [email],
      "one mail, to the invite's address, and none for the unknown token",
    );

    // a wrong code is the one 403; no GoTrue session is created
    const wrong = await invCall(null, "POST", "invites/accept/verify", {
      token,
      code: "000000",
    });
    assertEquals([wrong.status, await errOf(wrong)], [403, "accept_refused"]);
    assertEquals(otpInvite.closed.length, 0);

    // the proof: the accepted person, the register challenge and the creation options
    const d = await verified(token, "invites");
    assertEquals(
      [d.refKind, d.refId, d.orgId, d.role],
      ["invite", inviteId, org, "staff"],
    );
    assertEquals(
      otpInvite.closed.length,
      1,
      "the GoTrue session is closed after the definer, on the success path too",
    );
    const userId = String(d.userId);
    const ch = parseChallengeToken(String(d.challengeToken))!;
    const options = d.options as {
      challenge: string;
      rp: { id: string };
      user: { id: string; name: string };
      excludeCredentials?: unknown[];
      attestation?: string;
      authenticatorSelection?: { userVerification?: string };
    };
    assertEquals(
      options.challenge,
      b64u(ch.nonce),
      "the creation options carry the database's nonce unchanged",
    );
    assertEquals(
      [options.rp.id, options.user.id, options.user.name],
      [RP.rpId, b64u(uuidToBytes(userId)!), email],
    );
    assertEquals(
      [
        options.attestation,
        options.authenticatorSelection?.userVerification,
        (options.excludeCredentials ?? []).length,
      ],
      ["none", "required", 0],
    );
    assert(
      Date.parse(String(d.expiresAt)) > Date.now(),
      "the challenge is live",
    );
    const accepted = await inviteRow(inviteId);
    assertEquals(
      [accepted.accepted_by, accepted.attempts, accepted.registered],
      [userId, 1, null],
    );
    const [member] = await rows(
      "app.partner_member",
      (sql) =>
        sql`select role::text as role, invited_by::text as invited_by, org_id::text as org_id, revoked_at from app.partner_member where user_id = ${userId}`,
    );
    assertEquals(
      [member!.role, member!.invited_by, member!.org_id, member!.revoked_at],
      ["staff", mgr.uid, org, null],
      "the membership is created at the acceptance",
    );
    assertEquals((await credentialsOf(userId)).length, 0, "no credential yet");

    // the registration: a REAL ceremony, the first credential and the first session in one transaction
    const { res, auth } = await register(d);
    assertEquals(res.status, 201, await res.clone().text());
    const session = await dataOf(res);
    assert(
      PARTNER_SESSION_TOKEN_RE.test(String(session.token)),
      "a gr_ps_ session token",
    );
    assertEquals(session.aal, 1);
    assert(
      !Number.isNaN(Date.parse(String(session.expiresAt))) &&
        !Number.isNaN(Date.parse(String(session.enrolmentUntil))),
      "ISO expiry and enrolment-until",
    );
    const [cred] = await credentialsOf(userId);
    assertEquals(
      [cred!.id_hex, cred!.key_hex, cred!.revoked_at],
      [hex(auth.credentialId), hex(auth.cosePublicKey), null],
      "the database stores exactly the credential id and key the authenticator holds",
    );
    assertEquals((await inviteRow(inviteId)).registered, cred!.id);

    // the first session works: the person lists their own credentials, and staff are not on the manager's list
    const mine = await memCall(
      { token: String(session.token) },
      "GET",
      "credentials",
    );
    assertEquals(mine.status, 200, await mine.clone().text());
    assertEquals(
      ((await dataOf(mine)).credentials as Array<{ id: string }>).map(
        (c) => c.id,
      ),
      [cred!.id],
    );
    assertEquals(
      (await memCall({ token: String(session.token) }, "GET", "members"))
        .status,
      403,
    );

    // replays are refused: the token is spent, and the acceptance registers once
    const again = await invCall(null, "POST", "invites/accept/verify", {
      token,
      code: CODE,
    });
    assertEquals([again.status, await errOf(again)], [403, "accept_refused"]);
    const second = await register(d);
    assertEquals(second.res.status, 409, await second.res.clone().text());
    assertEquals(
      (await credentialsOf(userId)).length,
      1,
      "the replay stored nothing",
    );
  },
);

Deno.test(
  "S1.5 / 6.1, branch N refusals: an address that already has a passkey is 409 existing_member_sign_in, one that is a member without a passkey is 409 recover_required, a stale GoTrue session is refused: each is counted on the invite, none accepts it, and the GoTrue session is closed every time",
  DT,
  async () => {
    resetOtp();
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const otherOrg = await newOrg();

    // an existing member WITH a passkey, invited again
    const withKey = await newMember(otherOrg, "staff", "haskey");
    const a = await createdInvite(mgr, org, withKey.email);
    const r1 = await invCall(null, "POST", "invites/accept/verify", {
      token: a.token,
      code: CODE,
    });
    assertEquals(
      [r1.status, await errOf(r1)],
      [409, "existing_member_sign_in"],
    );
    const rowA = await inviteRow(a.id);
    assertEquals(
      [rowA.accepted_at, rowA.attempts],
      [null, 1],
      "counted, not accepted",
    );

    // an existing member WITHOUT a passkey (a recovery is the way in)
    const noKey = await newMember(otherOrg, "staff", "nokey", false);
    const b = await createdInvite(mgr, org, noKey.email);
    const r2 = await invCall(null, "POST", "invites/accept/verify", {
      token: b.token,
      code: CODE,
    });
    assertEquals([r2.status, await errOf(r2)], [409, "recover_required"]);
    assertEquals((await inviteRow(b.id)).accepted_at, null);

    // a GoTrue session older than the freshness window
    const c = await createdInvite(mgr, org, newAddress("stale"));
    otpInvite.ageSeconds = 300;
    const r3 = await invCall(null, "POST", "invites/accept/verify", {
      token: c.token,
      code: CODE,
    });
    assertEquals([r3.status, await errOf(r3)], [403, "accept_refused"]);
    otpInvite.ageSeconds = 0;
    const rowC = await inviteRow(c.id);
    assertEquals([rowC.accepted_at, rowC.attempts], [null, 1]);
    assertEquals(
      otpInvite.closed.length,
      3,
      "every verify that created a GoTrue session closed it, refusals included",
    );
    // the control: the same invite, with a fresh session, is accepted
    const ok = await invCall(null, "POST", "invites/accept/verify", {
      token: c.token,
      code: CODE,
    });
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals((await inviteRow(c.id)).attempts, 2);
  },
);

Deno.test(
  "S1.5 / 6.5, enrolment: a recovered person's way back: the recovery token's mail goes through the enrolment port, the proof yields the register challenge, a real registration stores the new key, consumes the token and mints a session; the old credentials and session stay dead and the token cannot be used again",
  DT,
  async () => {
    resetOtp();
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const person = await newMember(org, "staff", "lost");

    // the recovery is a partner-members route (issued by the manager); its token is the enrolment token this lane accepts
    const recovered = await memCall(
      mgr,
      "POST",
      `members/${person.uid}/recover`,
      undefined,
    );
    assertEquals(recovered.status, 201, await recovered.clone().text());
    const issued = await dataOf(recovered);
    const token = String(issued.token);
    assert(PARTNER_ENROLMENT_TOKEN_RE.test(token));

    const start = await invCall(null, "POST", "enrolments/accept/start", {
      token,
    });
    assertEquals(start.status, 200, await start.clone().text());
    assertEquals(
      [otpEnrol.sent, otpInvite.sent],
      [[person.email], []],
      "the code goes to the person's own address through the enrolment port",
    );

    const d = await verified(token, "enrolments");
    assertEquals(
      [d.refKind, d.refId, d.purpose, d.userId],
      ["enrolment", issued.tokenId, "recover", person.uid],
    );
    assertEquals(otpEnrol.closed.length, 1);
    const { res, auth } = await register(d);
    assertEquals(res.status, 201, await res.clone().text());
    const session = await dataOf(res);

    const creds = await credentialsOf(person.uid);
    const live = creds.filter((c) => c.revoked_at === null);
    assertEquals(live.length, 1, "exactly one live credential: the new one");
    assertEquals(
      [live[0]!.id_hex, live[0]!.key_hex],
      [hex(auth.credentialId), hex(auth.cosePublicKey)],
    );
    assert(
      creds.filter((c) => c.revoked_at !== null).length >= 1,
      "the old credentials stay revoked",
    );
    const [t] = await rows(
      "app.partner_enrolment_token",
      (sql) =>
        sql`select consumed_at, registered_credential_id::text as registered from app.partner_enrolment_token where id = ${String(issued.tokenId)}`,
    );
    assert(
      t!.consumed_at instanceof Date && t!.registered === live[0]!.id,
      "the token is consumed and points at the new credential",
    );

    assertEquals(
      (await memCall({ token: String(session.token) }, "GET", "credentials"))
        .status,
      200,
      "the new session works",
    );
    assertEquals(
      (await memCall(person, "GET", "credentials")).status,
      401,
      "the old session is dead",
    );
    const reuse = await invCall(null, "POST", "enrolments/accept/verify", {
      token,
      code: CODE,
    });
    assertEquals([reuse.status, await errOf(reuse)], [403, "accept_refused"]);
  },
);

Deno.test(
  "S1.5 / 6.1: a registration the database refuses leaves the acceptance usable: a tampered challenge, the wrong person, the wrong reference kind and a challenge the browser did not sign are each refused, an expired one is a 410, and the correct registration still succeeds afterwards",
  DT,
  async () => {
    resetOtp();
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const { id, token } = await createdInvite(mgr, org, newAddress("refuse"));
    const d = await verified(token, "invites");
    const ct = String(d.challengeToken);
    const [nonce, exp, mac] = ct.split(".") as [string, string, string];
    // a MAC with one character certainly CHANGED (the second-to-last of 43 base64url characters carries all six of its bits)
    const at = mac.length - 2;
    const flipped = `${nonce}.${exp}.${mac.slice(0, at)}${mac[at] === "A" ? "B" : "A"}${mac.slice(at + 1)}`;

    const tampered = await register(d, { challengeToken: flipped });
    assertEquals(
      [tampered.res.status, await errOf(tampered.res)],
      [403, "registration_refused"],
    );
    const stranger = await register(d, { userId: freshUuid() });
    assertEquals(
      [stranger.res.status, await errOf(stranger.res)],
      [403, "registration_refused"],
    );
    const wrongKind = await register(d, { refKind: "enrolment" });
    assertEquals(
      [wrongKind.res.status, await errOf(wrongKind.res)],
      [403, "registration_refused"],
    );
    const wrongRef = await register(d, { refId: freshUuid() });
    assertEquals(
      [wrongRef.res.status, await errOf(wrongRef.res)],
      [403, "registration_refused"],
    );
    // a ceremony over a challenge other than the database's: the wrapper refuses it
    const auth = await SoftwareAuthenticator.create(
      "ES256",
      uuidToBytes(String(d.userId))!,
    );
    const offChallenge = await auth.register({
      rpId: RP.rpId,
      origin: RP.origin,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
    });
    const off = await invCall(null, "POST", "credentials", {
      userId: d.userId,
      refKind: d.refKind,
      refId: d.refId,
      challengeToken: ct,
      credential: offChallenge,
    });
    assertEquals([off.status, await errOf(off)], [403, "registration_refused"]);
    // a clock past the challenge's expiry: the Edge refuses it itself, 410
    const late = await register(d, { nowMs: () => Date.now() + 3_600_000 });
    assertEquals([late.res.status, await errOf(late.res)], [410, "expired"]);

    assertEquals(
      (await credentialsOf(String(d.userId))).length,
      0,
      "no refusal stored a credential",
    );
    assertEquals((await inviteRow(id)).registered, null);
    const ok = await register(d);
    assertEquals(ok.res.status, 201, await ok.res.clone().text());
    assertEquals((await credentialsOf(String(d.userId))).length, 1);
  },
);

Deno.test(
  "S1.5 / design 8: a token earns 3 code mails an hour and 10 code attempts an hour, counted in the database for a token that exists: the extra mail is not sent and the extra attempt reaches no mail provider, each with the same constant answer",
  DT,
  async () => {
    resetOtp();
    const org = await newOrg();
    const mgr = await newMember(org, "manager", "mgr");
    const { token } = await createdInvite(mgr, org, newAddress("cap"));
    for (let i = 0; i < 5; i++)
      assertEquals(
        (await invCall(null, "POST", "invites/accept/start", { token })).status,
        200,
      );
    assertEquals(otpInvite.sent.length, 3, "five starts, three mails");
    for (let i = 0; i < 12; i++) {
      const res = await invCall(null, "POST", "invites/accept/verify", {
        token,
        code: "000000",
      });
      assertEquals([res.status, await errOf(res)], [403, "accept_refused"]);
    }
    assertEquals(
      otpInvite.verifyCalls.length,
      10,
      "twelve attempts, ten reached the provider",
    );
  },
);

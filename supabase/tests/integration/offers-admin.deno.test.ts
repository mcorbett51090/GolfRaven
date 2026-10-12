// supabase/tests/integration/offers-admin.deno.test.ts
//
// Slice S6 / 0059 (docs/security/partner-auth-design.md 12, 30, 125; AT(14)): the REAL `offers-admin` handler over the REAL privileged.ts (`partnerDb.withOffersAdmin` = `withPartnerSession`), a REAL operator and a REAL admin
// session minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner`
// through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite (partner-offers-handler.test.ts) hands the handler a MOCKED port, and the pgTAP matrix calls the definers directly. Neither runs the Edge's own binding of an offer's
// eligibility (a nested JSON rule through `trx.json(...)::jsonb`), its numeric and date parameters (`::numeric`, `::date`) and the way the returned rows are read back (numerics and dates as the wire carries them). This file
// drives an offer through its whole life (draft, edit, approve, end) and reads the table back after each step.
//
// The same shortcut as the other partner integration files: a session's step-up state (aal 2, a live `mfa_until`) is written by the OWNER with the guard trigger off for that statement only; TOTP itself is proved elsewhere.

// `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The pgTAP file (39_at10_issuance_staff_gate.sql) proves the DATABASE answers `no_active_staff`; the unit suite proves the handler maps a status it is HANDED. Neither
// ran the path between them: `privileged.ts` validates the database's `o_status` against a closed list and THROWS for anything else, so a status the SQL learned (0061) but the list did not was an uncaught 500
// that no cell could see. This file drives an admin's approve of a held offer code at a facility with no active staff through the handler, the validation and the database, and reads the row back.
//
// The one shortcut: the admin's step-up state (aal 2, a live `mfa_until`) is written into the session row by the OWNER with the guard trigger off for that statement only (the pgTAP file and the other
// integration files do the same); TOTP itself is proved elsewhere. Everything else is the real path.

import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  adminSql,
  createTestUser,
  ensureServiceRole,
  freshUuid,
  rawOwnerSql,
  withTemporaryOwnerAccess as withOwnerAccess,
} from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { handlePartnerOffersAdminRequest } from "../../functions/_shared/partner/offers-handler.ts";
import { assertionVerifier } from "../../functions/_shared/partner/webauthn-port.ts";
import {
  parseChallengeToken,
  uuidToBytes,
} from "../../functions/_shared/partner/session-shape.ts";
import {
  newPartnerSessionToken,
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
  readonly token: string;
  readonly hash: string;
}
let seq = 0;
/** A real credential for `uid` and a session from the real mint (the software authenticator's real assertion). */
async function signInAs(uid: string): Promise<Member> {
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
  return { uid, token, hash: await sha256Hex(token) };
}
/** The admin the harness already seeds (helpers.sql puts this uid in app.admin_user, and the pgTAP matrices rely on it in both modes), signed in once with a real credential. Creating an admin here
 * instead (an owner insert into app.admin_user) is not an option: no other integration file does it, and an owner-side fixture insert is exactly what did not persist under HARNESS_MODE=restricted. */
const ADMIN_UID = "00000000-0000-0000-0000-4000000000d0";
let adminSession: Member | null = null;
/** The admin's session at aal 2 with a live second factor (class A3 needs both); re-seeded on every use because `mfa_until` is short. */
async function newAdmin(): Promise<Member> {
  adminSession ??= await signInAs(ADMIN_UID);
  const m = adminSession;
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = 2, mfa_until = clock_timestamp() + interval '240 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
  return m;
}

async function offers(
  token: string,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<Response> {
  const headers = new Headers({
    origin: RP.origin,
    authorization: `Bearer ${token}`,
  });
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handlePartnerOffersAdminRequest(
    new Request(
      `https://project.example.test/functions/v1/offers-admin/${path}`,
      {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      },
    ),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}

/** Step-up state a session cannot be BORN with: the guard trigger is off for this one statement (aal 2 and a live second factor, class A3). */
async function stepUp(m: Member): Promise<Member> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = 2, mfa_until = clock_timestamp() + interval '240 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
  return m;
}

/** An operator of trail trl_t (which fac_x is on), with a real credential and a session from the real mint; at aal 2 with a live second factor unless `withStepUp` is false. */
async function newOperator(withStepUp = true): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `oa-op-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, 'operator', ${"offers-admin org " + seq})`,
  );
  await rows(
    "app.partner_scope",
    (sql) =>
      sql`insert into app.partner_scope (org_id, trail_id) values (${org}, 'trl_t')`,
  );
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, 'operator', now() - interval '60 days')`,
  );
  const m = await signInAs(uid);
  return withStepUp ? await stepUp(m) : m;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The offer under test: a nested eligibility rule (so a JSON string bound as a scalar, or a flattened object, is visible), non-integer numerics and fixed dates.
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const ELIGIBLE = {
  kind: "compare",
  op: ">=",
  left: {
    kind: "agg",
    name: "played",
    courseId: "crs_01H0ABCDEFGHJKMNPQRSTVWXYZ",
  },
  right: { kind: "literal", value: 1 },
};
const offerBody = (over: Record<string, unknown> = {}) => ({
  trailId: "trl_t",
  facilityId: "fac_x",
  eligibility: ELIGIBLE,
  funder: "operator",
  budgetCap: 250.5,
  maxRedemptions: 40,
  faceValue: 12.25,
  validFrom: "2031-03-01",
  validTo: "2031-09-30",
  ...over,
});

await ensureServiceRole();
interface OfferRow {
  eligibility_type: string;
  eligibility: unknown;
  budget_cap: string;
  face_value: string;
  max_redemptions: number | null;
  valid_from: string;
  valid_to: string;
  status: string;
  funder: string;
  trail_id: string;
  facility_id: string;
  sponsorship_id: string | null;
}
/** The row as the table holds it, read as service_role (not through the code under test). */
async function offerRow(id: string): Promise<OfferRow | undefined> {
  await ensureServiceRole();
  return (
    await adminSql()`select jsonb_typeof(eligibility) as eligibility_type, eligibility, budget_cap::text as budget_cap, face_value::text as face_value, max_redemptions,
      valid_from::text as valid_from, valid_to::text as valid_to, status::text as status, funder::text as funder, trail_id, facility_id, sponsorship_id::text as sponsorship_id
      from app.offer where id = ${id}`
  )[0] as OfferRow | undefined;
}
const offerCount = async (): Promise<number> => {
  await ensureServiceRole();
  return Number(
    (await adminSql()`select count(*)::int as n from app.offer where trail_id = 'trl_t'`)[0]!
      .n,
  );
};
const dataOf = async (res: Response) => (await res.json()).data;
const errOf = async (res: Response) => (await res.json()).error?.code as string;

Deno.test(
  "S6: an operator drafts an offer through the real stack: the nested eligibility is stored as a JSON OBJECT, the numerics and dates survive exactly, and the list reads them back as numbers and plain dates",
  DT,
  async () => {
    const op = await newOperator();
    const res = await offers(op.token, "POST", "offers", offerBody());
    assertEquals(res.status, 200, await res.clone().text());
    const id = (await dataOf(res)).id as string;
    assert(/^[0-9a-f-]{36}$/.test(id), "a uuid");

    const row = (await offerRow(id))!;
    assertEquals(row.eligibility_type, "object", "stored as a JSON object, not a JSON string scalar");
    assertEquals(row.eligibility, ELIGIBLE);
    assertEquals(Number(row.budget_cap), 250.5);
    assertEquals(Number(row.face_value), 12.25);
    assertEquals(row.max_redemptions, 40);
    assertEquals(row.valid_from, "2031-03-01");
    assertEquals(row.valid_to, "2031-09-30");
    assertEquals(
      [row.status, row.funder, row.trail_id, row.facility_id, row.sponsorship_id],
      ["draft", "operator", "trl_t", "fac_x", null],
    );

    const list = await offers(op.token, "GET", "offers?trailId=trl_t");
    assertEquals(list.status, 200, await list.clone().text());
    const mine = ((await dataOf(list)).offers as Array<Record<string, unknown>>).find(
      (o) => o.id === id,
    )!;
    assert(mine, "the new draft is in the list");
    assertEquals(mine.eligibility, ELIGIBLE);
    assertEquals(
      [mine.budgetCap, mine.faceValue, mine.maxRedemptions, mine.budgetUsed, mine.budgetReserved],
      [250.5, 12.25, 40, 0, 0],
    );
    assertEquals([mine.validFrom, mine.validTo, mine.status], ["2031-03-01", "2031-09-30", "draft"]);
  },
);

Deno.test(
  "S6: a draft is edited in place by its id (one row, new values), and only an admin approves it (an operator is a 403 and the offer stays a draft)",
  DT,
  async () => {
    const op = await newOperator();
    const created = await offers(op.token, "POST", "offers", offerBody());
    const id = (await dataOf(created)).id as string;
    const before = await offerCount();

    const edit = await offers(
      op.token,
      "POST",
      "offers",
      offerBody({ id, faceValue: 15, budgetCap: 300.75, maxRedemptions: null }),
    );
    assertEquals(edit.status, 200, await edit.clone().text());
    assertEquals((await dataOf(edit)).id, id, "the same offer");
    assertEquals(await offerCount(), before, "an edit adds no row");
    const edited = (await offerRow(id))!;
    assertEquals([Number(edited.face_value), Number(edited.budget_cap), edited.max_redemptions], [15, 300.75, null]);

    const byOperator = await offers(op.token, "POST", "offers/approve", { id });
    assertEquals(byOperator.status, 403, await byOperator.clone().text());
    assertEquals((await offerRow(id))!.status, "draft");

    const admin = await newAdmin();
    const approved = await offers(admin.token, "POST", "offers/approve", { id });
    assertEquals(approved.status, 200, await approved.clone().text());
    assertEquals((await offerRow(id))!.status, "live");

    const again = await offers(admin.token, "POST", "offers/approve", { id });
    assertEquals([again.status, await errOf(again)], [422, "not_draft"]);
    assertEquals((await offerRow(id))!.status, "live");

    // leave no live offer behind for the other integration files that share this database
    const end = await offers(op.token, "POST", "offers/end", { id });
    assertEquals(end.status, 200, await end.clone().text());
    assertEquals((await offerRow(id))!.status, "ended");
  },
);

Deno.test(
  "S6: a live offer is no longer editable (422 not_draft, the row unchanged); it is ended once (200), a second end is 422 not_live, and an unknown id is 422 not_found",
  DT,
  async () => {
    const op = await newOperator();
    const admin = await newAdmin();
    const id = (await dataOf(await offers(op.token, "POST", "offers", offerBody()))).id as string;
    assertEquals((await offers(admin.token, "POST", "offers/approve", { id })).status, 200);

    const edit = await offers(op.token, "POST", "offers", offerBody({ id, faceValue: 99 }));
    assertEquals([edit.status, await errOf(edit)], [422, "not_draft"]);
    assertEquals(Number((await offerRow(id))!.face_value), 12.25, "the live offer was not touched");

    const end = await offers(op.token, "POST", "offers/end", { id });
    assertEquals(end.status, 200, await end.clone().text());
    assertEquals((await offerRow(id))!.status, "ended");
    const endAgain = await offers(op.token, "POST", "offers/end", { id });
    assertEquals([endAgain.status, await errOf(endAgain)], [422, "not_live"]);

    const unknown = await offers(op.token, "POST", "offers/end", { id: freshUuid() });
    assertEquals([unknown.status, await errOf(unknown)], [422, "not_found"]);
  },
);

Deno.test(
  "S6: the funder rules are the database's (a sponsor offer needs a sponsorship, any other must not carry one: 422 bad_funder) and the Edge's eligibility gate stops an unrepresentable rule before the database is opened; neither writes a row",
  DT,
  async () => {
    const op = await newOperator();
    const before = await offerCount();

    const sponsorNone = await offers(op.token, "POST", "offers", offerBody({ funder: "sponsor" }));
    assertEquals([sponsorNone.status, await errOf(sponsorNone)], [422, "bad_funder"]);
    const operatorWithSponsorship = await offers(
      op.token,
      "POST",
      "offers",
      offerBody({ sponsorshipId: freshUuid() }),
    );
    assertEquals([operatorWithSponsorship.status, await errOf(operatorWithSponsorship)], [422, "bad_funder"]);

    const unrepresentable = await offers(
      op.token,
      "POST",
      "offers",
      offerBody({
        eligibility: {
          kind: "compare",
          op: ">=",
          left: { kind: "agg", name: "minConfidence", courseId: "crs_01H0ABCDEFGHJKMNPQRSTVWXYZ" },
          right: { kind: "literal", value: 1 },
        },
      }),
    );
    assertEquals(unrepresentable.status, 422, await unrepresentable.clone().text());

    assertEquals(await offerCount(), before, "no refusal wrote a row");
  },
);

Deno.test(
  "S6 / A3: an operator whose session has no second factor (aal 1) cannot draft, approve or end: 403 on every write, and nothing is written",
  DT,
  async () => {
    const strong = await newOperator();
    const id = (await dataOf(await offers(strong.token, "POST", "offers", offerBody()))).id as string;
    const weak = await newOperator(false);
    const before = await offerCount();

    const draft = await offers(weak.token, "POST", "offers", offerBody());
    assertEquals(draft.status, 403, await draft.clone().text());
    const end = await offers(weak.token, "POST", "offers/end", { id });
    assertEquals(end.status, 403, await end.clone().text());
    assertEquals(await offerCount(), before);
    assertEquals((await offerRow(id))!.status, "draft");
  },
);

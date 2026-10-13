// supabase/tests/integration/partner-sponsor-binding.deno.test.ts
//
// Slice S6 / 0059 + 0109 (docs/security/partner-auth-design.md 12, 30, 125, 133, 134, 137): the sponsorship an offer, or a trail's special marker, is funded by must be a sponsorship OF THAT TRAIL. The REAL
// `offers-admin`, `programme-config` and `sponsorships-admin` handlers over the REAL privileged.ts, a REAL operator and a REAL admin session minted by the REAL partner-session mint from the software
// authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. Found by driving the lane: before 0109 the offer upsert checked that a sponsor offer NAMES a sponsorship and nothing else, so an operator of one trail could fund an offer on
// their trail with a sponsorship of another (the settlement export then attributes the redemptions to the other trail's sponsor), and the programme upsert took any sponsorship id for the special marker; an id
// that names no sponsorship at all was a raw foreign-key error. This file drives the whole sponsor-funded life (the sponsorship made and approved through its own route, an offer funded by it, the admin's approve,
// the end) and every refusal, and reads the tables back as the owner / service_role.
//
// Every cell works on its OWN trails (a ledger row and a catalog trail made here): `trail_programme` and `offer` are shared state.
//
// The same shortcut as the other partner integration files: a session's step-up state (aal 2 and a live `mfa_until`, class A3) is written by the OWNER with the guard trigger off for that statement only; TOTP
// itself is proved elsewhere. The admin is the one the harness seeds (helpers.sql), signed in once with a real credential.

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
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
import { handlePartnerSponsorshipsRequest } from "../../functions/_shared/partner/sponsorships-handler.ts";
import { handlePartnerOffersAdminRequest } from "../../functions/_shared/partner/offers-handler.ts";
import { handlePartnerProgrammeRequest } from "../../functions/_shared/partner/programme-handler.ts";
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
/** A run-unique suffix for ids: every integration file shares one database. */
const RUN = freshUuid().slice(0, 8);

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
  const o = await sessionCall("options", {});
  const d = (await o.json()).data as { challengeToken: string };
  const parsed = parseChallengeToken(d.challengeToken)!;
  const cred = await auth.assert({
    rpId: RP.rpId,
    origin: RP.origin,
    challenge: parsed.nonce,
  });
  const res = await sessionCall("verify", {
    challengeToken: d.challengeToken,
    credential: cred,
  });
  assertEquals(res.status, 201, await res.clone().text());
  const token = ((await res.json()).data as { token: string }).token;
  return { uid, token, hash: await sha256Hex(token) };
}

/** A trail of its own: a ledger row and a catalog trail (the programme upsert answers `not_found` for a trail the ledger does not know). */
async function newTrail(): Promise<string> {
  seq += 1;
  const id = `trl_sb_${RUN}_${seq}`;
  await rows(
    "app.catalog_id_ledger",
    (sql) =>
      sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${id}, 'trail', 'verified', 1)`,
  );
  await rows(
    "app.catalog_trail",
    (sql) =>
      sql`insert into app.catalog_trail (id, slug, name, catalog_version) values (${id}, ${id.replaceAll("_", "-")}, ${"Trail " + id}, 1)`,
  );
  return id;
}
/** A member of a fresh org with a real credential and a session from the real mint: an operator of `trailId` (operator org, trail scope), or a manager of fac_x (facility org). */
async function newMember(
  kind: "operator" | "manager",
  trailId?: string,
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `sbd-${kind}-${seq}`);
  const org = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${org}, ${kind === "operator" ? "operator" : "facility"}, ${"programme org " + seq})`,
  );
  if (kind === "operator")
    await rows(
      "app.partner_scope",
      (sql) =>
        sql`insert into app.partner_scope (org_id, trail_id) values (${org}, ${trailId!})`,
    );
  else
    await rows(
      "app.partner_scope",
      (sql) =>
        sql`insert into app.partner_scope (org_id, facility_id) values (${org}, 'fac_x')`,
    );
  await rows(
    "app.partner_member",
    (sql) =>
      sql`insert into app.partner_member (user_id, org_id, role, created_at) values (${uid}, ${org}, ${kind}, now() - interval '60 days')`,
  );
  return await signInAs(uid);
}

/** Step-up state a session cannot be BORN with: the guard trigger is off for this one statement (aal 2 and a live second factor, class A3). */
async function stepUp(m: Member, aal = 2): Promise<void> {
  await rows("app.partner_session", async (sql) => {
    await sql.unsafe(
      "alter table app.partner_session disable trigger partner_session_guard_trg",
    );
    try {
      await sql`update app.partner_session set aal = ${aal}, mfa_until = clock_timestamp() + interval '240 seconds' where token_hash = ${m.hash}`;
    } finally {
      await sql.unsafe(
        "alter table app.partner_session enable trigger partner_session_guard_trg",
      );
    }
  });
}

async function callWith(
  handler: (
    req: Request,
    deps: { db: typeof partnerDb; allowedOrigin: string },
  ) => Promise<Response>,
  fn: string,
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  withStepUp = true,
): Promise<Response> {
  if (m !== null && withStepUp) await stepUp(m);
  const headers = new Headers({ origin: RP.origin });
  if (m !== null) headers.set("authorization", `Bearer ${m.token}`);
  if (body !== undefined) headers.set("content-type", "application/json");
  return await handler(
    new Request(`https://project.example.test/functions/v1/${fn}/${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}
const spCall = (
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
) =>
  callWith(
    handlePartnerSponsorshipsRequest,
    "sponsorships-admin",
    m,
    method,
    path,
    body,
  );
const offCall = (
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
) =>
  callWith(
    handlePartnerOffersAdminRequest,
    "offers-admin",
    m,
    method,
    path,
    body,
  );
const prgCall = (
  m: Member | null,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
) =>
  callWith(
    handlePartnerProgrammeRequest,
    "programme-config",
    m,
    method,
    path,
    body,
  );
const errOf = async (res: Response) => (await res.json()).error?.code as string;
const dataOf = async (res: Response) =>
  (await res.json()).data as Record<string, unknown>;

/** The admin the harness already seeds (helpers.sql puts this uid in app.admin_user), signed in once with a real credential; its step-up state is re-seeded on every call. */
const ADMIN_UID = "00000000-0000-0000-0000-4000000000d0";
let adminSession: Member | null = null;
async function newAdmin(): Promise<Member> {
  adminSession ??= await signInAs(ADMIN_UID);
  await stepUp(adminSession);
  return adminSession;
}

/** A sponsor organisation (kind sponsor): the only kind a sponsorship may name. */
async function newSponsorOrg(): Promise<string> {
  seq += 1;
  const id = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${id}, 'sponsor', ${"sponsor binding org " + seq})`,
  );
  return id;
}
/** A LIVE sponsorship of `trail` with `scope`, made and approved through its own route by `op` (an operator of that trail). */
async function liveSponsorship(
  op: Member,
  trail: string,
  scope = "offers",
): Promise<string> {
  const org = await newSponsorOrg();
  const made = await spCall(op, "POST", "sponsorships", {
    trailId: trail,
    sponsorOrgId: org,
    category: "equipment",
    scope,
    attributionName: "Binding Golf",
    attributionAsset: null,
    placementFee: null,
    startsOn: "2031-01-01",
    endsOn: "2031-12-31",
  });
  assertEquals(made.status, 200, await made.clone().text());
  const id = (await dataOf(made)).id as string;
  const ok = await spCall(op, "POST", "sponsorships/approve", { id });
  assertEquals(ok.status, 200, await ok.clone().text());
  return id;
}

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
const offerBody = (trailId: string, over: Record<string, unknown> = {}) => ({
  trailId,
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
const trailBody = (trailId: string, over: Record<string, unknown> = {}) => ({
  trailId,
  status: "pilot",
  markerSource: "programme_marker",
  markerRequiresCompletion: true,
  specialMarkerFundedBy: "trail",
  specialMarkerLowThreshold: 4,
  webPlayerFlow: false,
  specialMarkerSku: "SKU-1",
  specialMarkerSponsorshipId: null,
  feeModel: "flat",
  feeAmount: 12.5,
  startsOn: "2031-01-01",
  endsOn: "2031-12-31",
  ...over,
});
interface OfferRow {
  status: string;
  funder: string;
  trail_id: string;
  sponsorship_id: string | null;
}
/** The row as the table holds it, read as service_role (not through the code under test). */
async function offerRow(id: string): Promise<OfferRow | undefined> {
  await ensureServiceRole();
  return (
    await adminSql()`select status::text as status, funder::text as funder, trail_id, sponsorship_id::text as sponsorship_id from app.offer where id = ${id}`
  )[0] as OfferRow | undefined;
}
const offerCount = async (trail: string): Promise<number> => {
  await ensureServiceRole();
  return Number(
    (
      await adminSql()`select count(*)::int as n from app.offer where trail_id = ${trail}`
    )[0]!.n,
  );
};
/** The special-marker funding of a trail's programme, as the OWNER reads it. */
const programmeFunding = async (trail: string) =>
  (
    await rows(
      "app.trail_programme",
      (sql) =>
        sql`select special_marker_funded_by::text as funded_by, special_marker_sponsorship_id::text as sponsorship_id, status::text as status from app.trail_programme where trail_id = ${trail}`,
    )
  )[0] as
    | {
        funded_by: string | null;
        sponsorship_id: string | null;
        status: string;
      }
    | undefined;

Deno.test(
  "0109 / S6: a sponsor-funded offer through its whole life: a sponsorship of the trail, made and approved through its own route, funds an offer (the row names it, the list carries it), the admin approves it and the operator ends it",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const sponsorship = await liveSponsorship(op, trail);

    const res = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: sponsorship }),
    );
    assertEquals(res.status, 200, await res.clone().text());
    const id = (await dataOf(res)).id as string;
    assertEquals(await offerRow(id), {
      status: "draft",
      funder: "sponsor",
      trail_id: trail,
      sponsorship_id: sponsorship,
    });

    const list = await offCall(op, "GET", `offers?trailId=${trail}`);
    const mine = (
      (await dataOf(list)).offers as Array<Record<string, unknown>>
    ).find((o) => o.id === id)!;
    assertEquals(
      [mine.funder, mine.sponsorshipId, mine.status],
      ["sponsor", sponsorship, "draft"],
    );

    // editing the draft to a different sponsorship of the same trail is accepted
    const other = await liveSponsorship(op, trail);
    const edit = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { id, funder: "sponsor", sponsorshipId: other }),
    );
    assertEquals(edit.status, 200, await edit.clone().text());
    assertEquals((await offerRow(id))!.sponsorship_id, other);

    const admin = await newAdmin();
    const approved = await offCall(admin, "POST", "offers/approve", { id });
    assertEquals(approved.status, 200, await approved.clone().text());
    assertEquals((await offerRow(id))!.status, "live");
    const end = await offCall(op, "POST", "offers/end", { id });
    assertEquals(end.status, 200, await end.clone().text());
    assertEquals(await offerRow(id), {
      status: "ended",
      funder: "sponsor",
      trail_id: trail,
      sponsorship_id: other,
    });
  },
);

Deno.test(
  "0109 / S6: an offer cannot be funded by ANOTHER trail's sponsorship, nor by an id that names none: each is 422 bad_funder (the same answer, so it says nothing about anyone else's ids), nothing is written, and an edit that tries it leaves the draft as it was; an admin is held to the same rule",
  DT,
  async () => {
    const trail = await newTrail();
    const foreignTrail = await newTrail();
    const op = await newMember("operator", trail);
    const foreignOp = await newMember("operator", foreignTrail);
    const own = await liveSponsorship(op, trail);
    const foreign = await liveSponsorship(foreignOp, foreignTrail);
    const before = await offerCount(trail);

    const viaForeign = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: foreign }),
    );
    assertEquals(
      [viaForeign.status, await errOf(viaForeign)],
      [422, "bad_funder"],
    );
    const viaNone = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: freshUuid() }),
    );
    assertEquals(
      [viaNone.status, await errOf(viaNone)],
      [422, "bad_funder"],
      "an id that names no sponsorship is the same refusal, not a database error",
    );
    assertEquals(await offerCount(trail), before, "nothing was written");

    // an edit of a good draft to the foreign sponsorship is refused and the draft keeps what it had
    const good = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: own }),
    );
    const id = (await dataOf(good)).id as string;
    const edit = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, {
        id,
        funder: "sponsor",
        sponsorshipId: foreign,
        budgetCap: 999,
      }),
    );
    assertEquals([edit.status, await errOf(edit)], [422, "bad_funder"]);
    assertEquals(await offerRow(id), {
      status: "draft",
      funder: "sponsor",
      trail_id: trail,
      sponsorship_id: own,
    });

    // an admin may write on any trail, and is held to the same rule
    const admin = await newAdmin();
    const byAdmin = await offCall(
      admin,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: foreign }),
    );
    assertEquals([byAdmin.status, await errOf(byAdmin)], [422, "bad_funder"]);
    const adminOk = await offCall(
      admin,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: own }),
    );
    assertEquals(adminOk.status, 200, await adminOk.clone().text());
  },
);

Deno.test(
  "0109 / S6: a trail's special marker is funded by a sponsorship of THAT trail: another trail's sponsorship and an id that names none are each 422 invalid_request and the programme keeps what it had; the trail's own sponsorship, and no sponsorship, are accepted",
  DT,
  async () => {
    const trail = await newTrail();
    const foreignTrail = await newTrail();
    const op = await newMember("operator", trail);
    const foreignOp = await newMember("operator", foreignTrail);
    const own = await liveSponsorship(op, trail, "special_marker");
    const foreign = await liveSponsorship(foreignOp, foreignTrail);

    const first = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail),
    );
    assertEquals(first.status, 200, await first.clone().text());
    assertEquals(await programmeFunding(trail), {
      funded_by: "trail",
      sponsorship_id: null,
      status: "pilot",
    });

    const viaForeign = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, {
        specialMarkerFundedBy: "sponsor",
        specialMarkerSponsorshipId: foreign,
      }),
    );
    assertEquals(
      [viaForeign.status, await errOf(viaForeign)],
      [422, "invalid_request"],
    );
    const viaNone = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, {
        specialMarkerFundedBy: "sponsor",
        specialMarkerSponsorshipId: freshUuid(),
      }),
    );
    assertEquals(
      [viaNone.status, await errOf(viaNone)],
      [422, "invalid_request"],
      "an id that names no sponsorship is a refusal, not a database error",
    );
    assertEquals(
      await programmeFunding(trail),
      { funded_by: "trail", sponsorship_id: null, status: "pilot" },
      "neither refusal changed the programme",
    );

    const ok = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, {
        status: "live",
        specialMarkerFundedBy: "sponsor",
        specialMarkerSponsorshipId: own,
      }),
    );
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await programmeFunding(trail), {
      funded_by: "sponsor",
      sponsorship_id: own,
      status: "live",
    });
  },
);

// supabase/tests/integration/partner-sponsorship-rules.deno.test.ts
//
// Slice S6 / 0059 + 0109 + 0112 (docs/security/partner-auth-design.md 12, 137, 143): what a sponsorship has to BE, not only whose it is, before it funds an offer or a trail's special marker. The REAL `offers-admin`,
// `programme-config` and `sponsorships-admin` handlers over the REAL privileged.ts, a REAL operator and a REAL admin session minted by the REAL partner-session mint from the software authenticator's REAL assertion,
// against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner` through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The database decides (matrix 90 proves each rule at the definer); the Edge only maps the outcome. What is new here is the mapping: the offer write refuses a sponsorship of the wrong
// scope as 422 `bad_funder` (an existing status), while the admin's APPROVE and the programme write refuse as SQLSTATE 22023, which the Edge must answer as 422 `invalid_request` and which must roll back with nothing
// written. 0112 adds no new status, so the portal needs no change; this file is the proof that the previous Edge works with the new migration.
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
  await createTestUser(uid, `ssr-${kind}-${seq}`);
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
      sql`insert into app.partner_org (id, kind, name) values (${id}, 'sponsor', ${"sponsorship rules org " + seq})`,
  );
  return id;
}
/** A sponsorship of `trail` with `scope`, made through its own route by `op` (an operator of that trail); live (approved through its own route) unless `approve` is false, in which case it stays a draft. */
async function sponsorship(
  op: Member,
  trail: string,
  scope = "offers",
  approve = true,
): Promise<string> {
  const org = await newSponsorOrg();
  const made = await spCall(
    op,
    "POST",
    "sponsorships",
    sponsorshipBody(trail, org, scope),
  );
  assertEquals(made.status, 200, await made.clone().text());
  const id = (await dataOf(made)).id as string;
  if (approve) {
    const ok = await spCall(op, "POST", "sponsorships/approve", { id });
    assertEquals(ok.status, 200, await ok.clone().text());
  }
  return id;
}
const sponsorshipBody = (
  trail: string,
  org: string,
  scope: string,
  id?: string,
) => ({
  ...(id === undefined ? {} : { id }),
  trailId: trail,
  sponsorOrgId: org,
  category: "equipment",
  scope,
  attributionName: "Rules Golf",
  attributionAsset: null,
  placementFee: null,
  startsOn: "2031-01-01",
  endsOn: "2031-12-31",
});
/** The sponsorship as the table holds it. */
async function sponsorshipRow(id: string) {
  await ensureServiceRole();
  return (
    await adminSql()`select status::text as status, scope::text as scope, sponsor_org_id::text as org from app.sponsorship where id = ${id}`
  )[0] as { status: string; scope: string; org: string };
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

const refused = async (
  res: Response,
  status: number,
  code: string,
  why?: string,
) => assertEquals([res.status, await errOf(res)], [status, code], why);

Deno.test(
  "0112 / S6: the admin's approve reads the sponsorship: an offer written against a sponsorship that is still a DRAFT is refused (422 invalid_request, still a draft) and is approved once the sponsorship is live",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const admin = await newAdmin();
    const sp = await sponsorship(op, trail, "offers", false);
    assertEquals((await sponsorshipRow(sp)).status, "draft");

    // the draft offer may be written against a draft sponsorship (the order of work is the operator's)
    const made = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: sp }),
    );
    assertEquals(made.status, 200, await made.clone().text());
    const id = (await dataOf(made)).id as string;

    // but the human gate does not let it go live on a sponsorship that is not live
    await refused(
      await offCall(admin, "POST", "offers/approve", { id }),
      422,
      "invalid_request",
      "a draft sponsorship does not fund a live offer",
    );
    assertEquals(
      (await offerRow(id))!.status,
      "draft",
      "the refusal changed nothing",
    );

    const live = await spCall(op, "POST", "sponsorships/approve", { id: sp });
    assertEquals(live.status, 200, await live.clone().text());
    const ok = await offCall(admin, "POST", "offers/approve", { id });
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await offerRow(id), {
      status: "live",
      funder: "sponsor",
      trail_id: trail,
      sponsorship_id: sp,
    });

    // the offers that never named a sponsorship are approved exactly as before
    const plain = await offCall(op, "POST", "offers", offerBody(trail));
    const plainId = (await dataOf(plain)).id as string;
    assertEquals(
      (await offCall(admin, "POST", "offers/approve", { id: plainId })).status,
      200,
    );
  },
);

Deno.test(
  "0112 / S6: a sponsorship of the special marker alone does not fund an offer (422 bad_funder, nothing written), and one of offers alone does not fund a trail's special marker (422 invalid_request, the programme keeps what it had)",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const markerOnly = await sponsorship(op, trail, "special_marker");
    const offersOnly = await sponsorship(op, trail, "offers");
    const both = await sponsorship(op, trail, "both");
    const before = await offerCount(trail);

    await refused(
      await offCall(
        op,
        "POST",
        "offers",
        offerBody(trail, { funder: "sponsor", sponsorshipId: markerOnly }),
      ),
      422,
      "bad_funder",
      "a special-marker sponsorship does not fund an offer",
    );
    assertEquals(await offerCount(trail), before, "nothing was written");
    for (const [sp, why] of [
      [offersOnly, "offers"],
      [both, "both"],
    ] as const) {
      const ok = await offCall(
        op,
        "POST",
        "offers",
        offerBody(trail, { funder: "sponsor", sponsorshipId: sp }),
      );
      assertEquals(ok.status, 200, `scope ${why}: ${await ok.clone().text()}`);
    }

    const first = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail),
    );
    assertEquals(first.status, 200, await first.clone().text());
    const keep = { funded_by: "trail", sponsorship_id: null, status: "pilot" };
    assertEquals(await programmeFunding(trail), keep);

    await refused(
      await prgCall(
        op,
        "POST",
        "programme/trail",
        trailBody(trail, {
          specialMarkerFundedBy: "sponsor",
          specialMarkerSponsorshipId: offersOnly,
        }),
      ),
      422,
      "invalid_request",
      "an offers-only sponsorship does not fund the special marker",
    );
    assertEquals(
      await programmeFunding(trail),
      keep,
      "the refusal changed nothing",
    );
    for (const [sp, why] of [
      [markerOnly, "special_marker"],
      [both, "both"],
    ] as const) {
      const ok = await prgCall(
        op,
        "POST",
        "programme/trail",
        trailBody(trail, {
          status: "live",
          specialMarkerFundedBy: "sponsor",
          specialMarkerSponsorshipId: sp,
        }),
      );
      assertEquals(ok.status, 200, `scope ${why}: ${await ok.clone().text()}`);
      assertEquals(await programmeFunding(trail), {
        funded_by: "sponsor",
        sponsorship_id: sp,
        status: "live",
      });
    }
  },
);

Deno.test(
  "0112 / S6: a programme that says the TRAIL pays for the special marker names no sponsorship (422 invalid_request, nothing changes); a programme that says sponsor with no id is accepted, and so is trail with none",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const sp = await sponsorship(op, trail, "special_marker");

    const noId = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, {
        specialMarkerFundedBy: "sponsor",
        specialMarkerSponsorshipId: null,
      }),
    );
    assertEquals(noId.status, 200, await noId.clone().text());
    assertEquals(
      await programmeFunding(trail),
      { funded_by: "sponsor", sponsorship_id: null, status: "pilot" },
      "sponsor with no id is accepted: it may say so before the sponsorship exists",
    );

    await refused(
      await prgCall(
        op,
        "POST",
        "programme/trail",
        trailBody(trail, {
          specialMarkerFundedBy: "trail",
          specialMarkerSponsorshipId: sp,
        }),
      ),
      422,
      "invalid_request",
      "trail with a sponsorship id",
    );
    assertEquals(
      await programmeFunding(trail),
      { funded_by: "sponsor", sponsorship_id: null, status: "pilot" },
      "the refusal changed nothing",
    );

    const named = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, {
        specialMarkerFundedBy: "sponsor",
        specialMarkerSponsorshipId: sp,
      }),
    );
    assertEquals(named.status, 200, await named.clone().text());
    const back = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, {
        specialMarkerFundedBy: "trail",
        specialMarkerSponsorshipId: null,
      }),
    );
    assertEquals(back.status, 200, await back.clone().text());
    assertEquals(await programmeFunding(trail), {
      funded_by: "trail",
      sponsorship_id: null,
      status: "pilot",
    });
  },
);

Deno.test(
  "0112 / S6: the flow the approve rule exists for, through the real routes: a draft offer on a draft sponsorship that is then EDITED to the special marker alone and approved cannot go live (422); repointing the draft at a live offers sponsorship does",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const admin = await newAdmin();
    const org = await newSponsorOrg();
    const draft = await spCall(
      op,
      "POST",
      "sponsorships",
      sponsorshipBody(trail, org, "offers"),
    );
    const sp = (await dataOf(draft)).id as string;
    const offer = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { funder: "sponsor", sponsorshipId: sp }),
    );
    assertEquals(offer.status, 200, await offer.clone().text());
    const id = (await dataOf(offer)).id as string;

    // the operator edits the DRAFT sponsorship to the special marker alone (the offer is not looked at again) and approves it
    const edit = await spCall(
      op,
      "POST",
      "sponsorships",
      sponsorshipBody(trail, org, "special_marker", sp),
    );
    assertEquals(edit.status, 200, await edit.clone().text());
    const live = await spCall(op, "POST", "sponsorships/approve", { id: sp });
    assertEquals(live.status, 200, await live.clone().text());
    assertEquals(await sponsorshipRow(sp), {
      status: "live",
      scope: "special_marker",
      org,
    });

    await refused(
      await offCall(admin, "POST", "offers/approve", { id }),
      422,
      "invalid_request",
      "the sponsorship no longer covers offers",
    );
    assertEquals((await offerRow(id))!.status, "draft");

    const good = await sponsorship(op, trail, "offers");
    const repoint = await offCall(
      op,
      "POST",
      "offers",
      offerBody(trail, { id, funder: "sponsor", sponsorshipId: good }),
    );
    assertEquals(repoint.status, 200, await repoint.clone().text());
    const ok = await offCall(admin, "POST", "offers/approve", { id });
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await offerRow(id), {
      status: "live",
      funder: "sponsor",
      trail_id: trail,
      sponsorship_id: good,
    });
  },
);

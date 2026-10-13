// supabase/tests/integration/partner-sponsorships.deno.test.ts
//
// Slice S6 / 0059 (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30, 134; AT(20)): the REAL `sponsorships-admin` handler over the REAL privileged.ts (`partnerDb.withSponsorships` = `withPartnerSession`, `hitRateLimit`), a REAL
// operator session minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner`
// through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port, and the pgTAP matrix calls the definers directly. Neither runs the Edge's own binding of a sponsorship (`${id}::uuid` that is null for a new
// draft, `${placementFee}::numeric`, `${startsOn}::date`, the category and scope as text for the definer to cast) or the way the rows come back (a numeric as a number, a date as `YYYY-MM-DD`). And the approval has a rule that
// reaches ACROSS lanes: a sponsorship whose scope includes the special marker cannot go live while any facility of the trail's programme with `holds_special_marker IS TRUE` has no stock (AT(20), `stock_short`): `true` blocks,
// `false` and `null` do not. This file drives all of that, with the programme and the stock seeded by the owner.
//
// Every cell works on its OWN trail (a ledger row and a catalog trail made here): `trail_programme`, `facility_programme` and `special_marker_stock` are shared state.
//
// The same shortcut as the other partner integration files: a session's step-up state (aal 2 and a live `mfa_until`, class A3) is written by the OWNER with the guard trigger off for that statement only; TOTP itself is proved elsewhere.

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  createTestUser,
  freshUuid,
  rawOwnerSql,
  withTemporaryOwnerAccess as withOwnerAccess,
} from "./_helpers.ts";
import { SoftwareAuthenticator } from "../deno-unit/software-authenticator.ts";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { handlePartnerSponsorshipsRequest } from "../../functions/_shared/partner/sponsorships-handler.ts";
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
  const id = `trl_pg_${RUN}_${seq}`;
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
  await createTestUser(uid, `spn-${kind}-${seq}`);
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

async function spCall(
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
  return await handlePartnerSponsorshipsRequest(
    new Request(
      `https://project.example.test/functions/v1/sponsorships-admin/${path}`,
      {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      },
    ),
    { db: partnerDb, allowedOrigin: RP.origin },
  );
}
const errOf = async (res: Response) => (await res.json()).error?.code as string;
const dataOf = async (res: Response) =>
  (await res.json()).data as Record<string, unknown>;

/** A sponsor organisation (kind sponsor): the only kind a sponsorship may name. */
async function newSponsorOrg(
  kind: "sponsor" | "facility" = "sponsor",
): Promise<string> {
  seq += 1;
  const id = freshUuid();
  await rows(
    "app.partner_org",
    (sql) =>
      sql`insert into app.partner_org (id, kind, name) values (${id}, ${kind}, ${"sponsor org " + seq})`,
  );
  return id;
}
/** The trail's programme the approval reads: a trail_programme row and a facility_programme row per facility with its `holds_special_marker` (true, false or null) set by the owner. */
async function seedProgramme(
  trail: string,
  holds: Record<string, boolean | null>,
): Promise<void> {
  await rows(
    "app.trail_programme",
    (sql) =>
      sql`insert into app.trail_programme (trail_id, status) values (${trail}, 'live')`,
  );
  for (const [facility, value] of Object.entries(holds)) {
    await rows(
      "app.facility_programme",
      (sql) =>
        sql`insert into app.facility_programme (trail_id, facility_id, participation, holds_special_marker) values (${trail}, ${facility}, 'accepted', ${value})`,
    );
  }
}
const setStockAt = async (
  trail: string,
  facility: string,
  onHand: number,
): Promise<void> => {
  await rows(
    "app.special_marker_stock",
    (sql) =>
      sql`insert into app.special_marker_stock (trail_id, facility_id, on_hand) values (${trail}, ${facility}, ${onHand}) on conflict (trail_id, facility_id) do update set on_hand = excluded.on_hand`,
  );
};

const body = (
  trailId: string,
  sponsorOrgId: string,
  over: Record<string, unknown> = {},
) => ({
  trailId,
  sponsorOrgId,
  category: "equipment",
  scope: "offers",
  attributionName: "Acme Golf",
  attributionAsset: "assets/acme.svg",
  placementFee: 1250.5,
  startsOn: "2031-01-01",
  endsOn: "2031-12-31",
  ...over,
});
interface Row {
  id: string;
  sponsor_org_id: string;
  trail_id: string;
  category: string;
  scope: string;
  attribution_name: string;
  attribution_asset: string | null;
  placement_fee: number | null;
  starts_on: string | null;
  ends_on: string | null;
  operator_approved_at: Date | null;
  status: string;
}
const rowOf = async (id: string): Promise<Row | null> =>
  ((
    await rows(
      "app.sponsorship",
      (sql) =>
        sql`select id::text as id, sponsor_org_id::text as sponsor_org_id, trail_id, category::text as category, scope::text as scope, attribution_name, attribution_asset, placement_fee::float8 as placement_fee, to_char(starts_on, 'YYYY-MM-DD') as starts_on, to_char(ends_on, 'YYYY-MM-DD') as ends_on, operator_approved_at, status::text as status from app.sponsorship where id = ${id}`,
    )
  )[0] ?? null) as unknown as Row | null;
const countFor = async (trail: string): Promise<number> =>
  Number(
    (
      await rows(
        "app.sponsorship",
        (sql) =>
          sql`select count(*)::int as n from app.sponsorship where trail_id = ${trail}`,
      )
    )[0]!.n,
  );
const create = async (
  op: Member,
  b: Record<string, unknown>,
): Promise<string> => {
  const res = await spCall(op, "POST", "sponsorships", b);
  assertEquals(res.status, 200, await res.clone().text());
  return String((await dataOf(res)).id);
};

Deno.test(
  "S6: a draft sponsorship upserted through the handler is stored and listed with every value (a numeric fee as a number, dates as YYYY-MM-DD, nullable fields as null); an edit by id replaces it in place; a sponsor organisation of the wrong kind is 422 bad_sponsor and an unknown id 422 not_found, each writing nothing",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const sponsor = await newSponsorOrg();

    const id = await create(op, body(trail, sponsor));
    const row = await rowOf(id);
    assertEquals(
      [
        row!.sponsor_org_id,
        row!.trail_id,
        row!.category,
        row!.scope,
        row!.attribution_name,
        row!.attribution_asset,
        row!.placement_fee,
        row!.starts_on,
        row!.ends_on,
        row!.operator_approved_at,
        row!.status,
      ],
      [
        sponsor,
        trail,
        "equipment",
        "offers",
        "Acme Golf",
        "assets/acme.svg",
        1250.5,
        "2031-01-01",
        "2031-12-31",
        null,
        "draft",
      ],
    );
    const listed = async () =>
      (await dataOf(await spCall(op, "GET", `sponsorships?trailId=${trail}`)))
        .sponsorships as Array<Record<string, unknown>>;
    assertEquals(await listed(), [
      {
        id,
        sponsorOrgId: sponsor,
        trailId: trail,
        category: "equipment",
        scope: "offers",
        attributionName: "Acme Golf",
        attributionAsset: "assets/acme.svg",
        placementFee: 1250.5,
        startsOn: "2031-01-01",
        endsOn: "2031-12-31",
        operatorApprovedAt: null,
        status: "draft",
      },
    ]);

    // an edit by id replaces the draft in place, including the fields it nulls
    const other = await newSponsorOrg();
    const edited = await spCall(
      op,
      "POST",
      "sponsorships",
      body(trail, other, {
        id,
        category: "tourism",
        scope: "both",
        attributionName: "Acme Tours",
        attributionAsset: null,
        placementFee: null,
        startsOn: null,
        endsOn: null,
      }),
    );
    assertEquals(edited.status, 200, await edited.clone().text());
    assertEquals((await dataOf(edited)).id, id);
    assertEquals((await rowOf(id))!.attribution_name, "Acme Tours");
    assertEquals(await listed(), [
      {
        id,
        sponsorOrgId: other,
        trailId: trail,
        category: "tourism",
        scope: "both",
        attributionName: "Acme Tours",
        attributionAsset: null,
        placementFee: null,
        startsOn: null,
        endsOn: null,
        operatorApprovedAt: null,
        status: "draft",
      },
    ]);
    assertEquals(await countFor(trail), 1, "an edit, not an insert");

    const wrongKind = await spCall(
      op,
      "POST",
      "sponsorships",
      body(trail, await newSponsorOrg("facility")),
    );
    assertEquals(
      [wrongKind.status, await errOf(wrongKind)],
      [422, "bad_sponsor"],
    );
    const unknown = await spCall(
      op,
      "POST",
      "sponsorships",
      body(trail, sponsor, { id: freshUuid() }),
    );
    assertEquals([unknown.status, await errOf(unknown)], [422, "not_found"]);
    assertEquals(await countFor(trail), 1, "neither refusal wrote a row");
  },
);

Deno.test(
  "S6: approving a draft makes it live and stamps the approval; approving it again, or editing it, is 422 not_draft; an unknown id is 422 not_found",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    const id = await create(
      op,
      body(trail, await newSponsorOrg(), { scope: "offers" }),
    );

    const before = Date.now();
    const ok = await spCall(op, "POST", "sponsorships/approve", { id });
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals(await dataOf(ok), { ok: true });
    const live = await rowOf(id);
    assertEquals(live!.status, "live");
    assert(
      live!.operator_approved_at instanceof Date &&
        live!.operator_approved_at.getTime() >= before - 2000,
      "the approval time is stamped",
    );
    const listed = (
      (await dataOf(await spCall(op, "GET", `sponsorships?trailId=${trail}`)))
        .sponsorships as Array<Record<string, unknown>>
    )[0]!;
    assertEquals(
      [listed.status, typeof listed.operatorApprovedAt],
      ["live", "string"],
    );

    const again = await spCall(op, "POST", "sponsorships/approve", { id });
    assertEquals([again.status, await errOf(again)], [422, "not_draft"]);
    const edit = await spCall(
      op,
      "POST",
      "sponsorships",
      body(trail, await newSponsorOrg(), { id, attributionName: "Changed" }),
    );
    assertEquals([edit.status, await errOf(edit)], [422, "not_draft"]);
    assertEquals(
      (await rowOf(id))!.attribution_name,
      "Acme Golf",
      "a live sponsorship was not edited",
    );
    const unknown = await spCall(op, "POST", "sponsorships/approve", {
      id: freshUuid(),
    });
    assertEquals([unknown.status, await errOf(unknown)], [422, "not_found"]);
  },
);

Deno.test(
  "S6 / AT(20): a sponsorship whose scope includes the special marker is 422 stock_short while a facility of the trail's programme that holds the marker (holds_special_marker true) has no stock; a facility with false or null does not block; once it has stock the same approval succeeds; a scope of offers only is never blocked",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);
    // fac_x holds the marker (true); fac_y does not (false). Neither has stock yet.
    await seedProgramme(trail, { fac_x: true, fac_y: false });
    const sponsor = await newSponsorOrg();
    const marker = await create(
      op,
      body(trail, sponsor, { scope: "special_marker" }),
    );
    const both = await create(
      op,
      body(trail, sponsor, { scope: "both", attributionName: "Both" }),
    );
    const offers = await create(
      op,
      body(trail, sponsor, { scope: "offers", attributionName: "Offers" }),
    );

    for (const id of [marker, both]) {
      const short = await spCall(op, "POST", "sponsorships/approve", { id });
      assertEquals([short.status, await errOf(short)], [422, "stock_short"]);
      assertEquals(
        (await rowOf(id))!.status,
        "draft",
        "stock_short changes nothing",
      );
    }
    const unblocked = await spCall(op, "POST", "sponsorships/approve", {
      id: offers,
    });
    assertEquals(
      unblocked.status,
      200,
      "an offers-only sponsorship does not look at stock",
    );

    // the facility that holds the marker gets stock; the one that does not hold it never needed any (false), and a null does not block either
    await setStockAt(trail, "fac_x", 1);
    const ok = await spCall(op, "POST", "sponsorships/approve", { id: marker });
    assertEquals(ok.status, 200, await ok.clone().text());
    assertEquals((await rowOf(marker))!.status, "live");

    await rows(
      "app.facility_programme",
      (sql) =>
        sql`update app.facility_programme set holds_special_marker = null where trail_id = ${trail} and facility_id = 'fac_y'`,
    );
    await setStockAt(trail, "fac_x", 0);
    const nowEmpty = await spCall(op, "POST", "sponsorships/approve", {
      id: both,
    });
    assertEquals(
      [nowEmpty.status, await errOf(nowEmpty)],
      [422, "stock_short"],
      "stock is read at the moment of approval, and fac_y's null did not matter",
    );
    await rows(
      "app.facility_programme",
      (sql) =>
        sql`update app.facility_programme set holds_special_marker = false where trail_id = ${trail} and facility_id = 'fac_x'`,
    );
    const noLongerHolds = await spCall(op, "POST", "sponsorships/approve", {
      id: both,
    });
    assertEquals(
      noLongerHolds.status,
      200,
      "a facility that no longer holds the marker stops blocking",
    );
  },
);

Deno.test(
  "S6 / A3: a write needs an operator of the trail AND aal 2 with a live second factor, and the aal gates reads too: a manager, an operator at aal 1 and an operator of another trail are 403 and write nothing; another trail's sponsorship cannot be approved; malformed bodies are 400",
  DT,
  async () => {
    const trail = await newTrail();
    const otherTrail = await newTrail();
    const op = await newMember("operator", trail);
    const foreign = await newMember("operator", otherTrail);
    const mgr = await newMember("manager");
    const sponsor = await newSponsorOrg();
    const id = await create(op, body(trail, sponsor)); // the control: the operator with the step-up creates

    assertEquals(
      (await spCall(mgr, "POST", "sponsorships", body(trail, sponsor))).status,
      403,
      "a manager",
    );
    await stepUp(op, 1);
    assertEquals(
      (await spCall(op, "POST", "sponsorships", body(trail, sponsor), false))
        .status,
      403,
      "aal 1",
    );
    assertEquals(
      (
        await spCall(
          op,
          "GET",
          `sponsorships?trailId=${trail}`,
          undefined,
          false,
        )
      ).status,
      403,
      "aal 1 cannot read either",
    );
    assertEquals(
      (await spCall(foreign, "POST", "sponsorships", body(trail, sponsor)))
        .status,
      403,
      "an operator of another trail",
    );
    assertEquals(
      (await spCall(foreign, "GET", `sponsorships?trailId=${trail}`)).status,
      403,
    );
    assertEquals(await countFor(trail), 1, "no refusal wrote a row");

    // approving another trail's sponsorship is 403, not a 422: the sponsorship exists, the scope is the trail's. (Observed, not judged, design 134: an id that does not exist is 422 not_found, so an operator can tell the two apart; ids are random UUIDs.)
    const approve = await spCall(foreign, "POST", "sponsorships/approve", {
      id,
    });
    assertEquals(approve.status, 403, await approve.clone().text());
    assertEquals((await rowOf(id))!.status, "draft");
    assertEquals(
      (await spCall(null, "GET", `sponsorships?trailId=${trail}`)).status,
      401,
    );

    for (const bad of [
      body(trail, sponsor, { category: "food" }),
      body(trail, sponsor, { scope: "everything" }),
      body(trail, sponsor, { attributionName: "   " }),
      body(trail, sponsor, { placementFee: -1 }),
      body(trail, sponsor, { startsOn: "01/01/2031" }),
      body(trail, "not-a-uuid"),
      { ...body(trail, sponsor), extra: 1 },
    ])
      assertEquals(
        (await spCall(op, "POST", "sponsorships", bad)).status,
        400,
        JSON.stringify(bad).slice(0, 80),
      );
    assertEquals(
      (await spCall(op, "POST", "sponsorships/approve", { id: "nope" })).status,
      400,
    );
    assertEquals(
      (await spCall(op, "GET", "sponsorships")).status,
      400,
      "a trail is required",
    );
    assertEquals(await countFor(trail), 1);
  },
);

Deno.test(
  "S6 / design 30: 240 requests an hour per member, then 429 with a Retry-After; the cap is the member's own",
  DT,
  async () => {
    const trail = await newTrail();
    const busy = await newMember("operator", trail);
    const calm = await newMember("operator", trail);
    for (let i = 0; i < 240; i++) {
      const res = await spCall(busy, "GET", `sponsorships?trailId=${trail}`);
      if (res.status !== 200)
        assertEquals(
          res.status,
          200,
          `request ${i + 1}: ${await res.clone().text()}`,
        );
      await res.arrayBuffer();
    }
    const over = await spCall(busy, "GET", `sponsorships?trailId=${trail}`);
    assertEquals([over.status, await errOf(over)], [429, "rate_limited"]);
    assert(
      Number(over.headers.get("retry-after")) >= 1,
      "a Retry-After in seconds",
    );
    assertEquals(
      (await spCall(calm, "GET", `sponsorships?trailId=${trail}`)).status,
      200,
      "another member is not slowed",
    );
  },
);

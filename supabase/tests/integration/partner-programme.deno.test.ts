// supabase/tests/integration/partner-programme.deno.test.ts
//
// Slice S6 / 0059 (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30, 133): the REAL `programme-config` handler over the REAL privileged.ts (`partnerDb.withProgramme` = `withPartnerSession`, `hitRateLimit`), a REAL operator
// session minted by the REAL partner-session mint from the software authenticator's REAL assertion, against the REAL database tools/db/test.sh builds (connected as the provisioned `edge_gateway` login, as `edge_partner`
// through SET LOCAL ROLE).
//
// WHAT ONLY THE REAL STACK CAN SHOW. The unit suite hands the handler a MOCKED port, and the pgTAP matrix calls the definers directly. Neither runs the Edge's own binding of the programme's thirteen scalars (`${feeAmount}::numeric`,
// `${startsOn}::date`, `${specialMarkerSponsorshipId}::uuid`, nullable booleans and texts) or the way the rows come back over the wire (a numeric as a number, a date as `YYYY-MM-DD`, an enum as text). This file upserts a trail's
// programme and its facilities through the handler, reads them back through the handler AND as the owner, and checks they are the same thing.
//
// Every cell works on its OWN trail (a ledger row and a catalog trail made here), because `trail_programme` and `facility_programme` are shared state: trl_t's rows belong to the other integration files.
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

/**
 * A trail of its own: a ledger row and a catalog trail (the programme upsert answers `not_found` for a trail the ledger does not know), and, unless `roster` is false, a roster (version 1) that
 * names fac_x and fac_y as facility members: since 0110 (section 140) the facility programme editor refuses a facility that is not on the trail's current roster, so a trail that is going to be
 * given facility programmes needs one.
 */
async function newTrail(roster = true): Promise<string> {
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
  if (roster) await addRoster(id, 1, [{ facility: "fac_x" }, { facility: "fac_y" }]);
  return id;
}
/** A roster version of `trailId` with the given members (a facility, a course, a hole, or an any-of list of courses). */
async function addRoster(
  trailId: string,
  version: number,
  members: ReadonlyArray<{ facility?: string; course?: string; hole?: string; anyOf?: string[] }>,
): Promise<void> {
  await rows(
    "app.catalog_roster_version",
    (sql) =>
      sql`insert into app.catalog_roster_version (trail_id, version, completion_unit, marker_unit, effective_from) values (${trailId}, ${version}, 'facility', 'facility', now())`,
  );
  let order = 0;
  for (const m of members) {
    order += 1;
    const unit = m.facility !== undefined ? "facility" : m.hole !== undefined ? "hole" : "course";
    await rows(
      "app.catalog_roster_member",
      (sql) =>
        sql`insert into app.catalog_roster_member (trail_id, roster_version, unit, course_id, any_of_course_ids, facility_id, hole_id, stop_order)
            values (${trailId}, ${version}, ${unit}::app.roster_unit, ${m.course ?? null}, ${m.anyOf ?? null}::text[], ${m.facility ?? null}, ${m.hole ?? null}, ${order})`,
    );
  }
}
/** A catalogue facility of its own with one course (and one hole on it), on no roster. */
async function newFacility(): Promise<{ facility: string; course: string; hole: string }> {
  seq += 1;
  const facility = `fac_pg_${RUN}_${seq}`;
  const course = `crs_pg_${RUN}_${seq}`;
  const hole = `hol_pg_${RUN}_${seq}`;
  await rows(
    "app.catalog_id_ledger",
    (sql) =>
      sql`insert into app.catalog_id_ledger (id, kind, status, first_catalog_version) values (${facility}, 'facility', 'verified', 1), (${course}, 'course', 'verified', 1), (${hole}, 'hole', 'verified', 1)`,
  );
  await rows(
    "app.catalog_facility",
    (sql) =>
      sql`insert into app.catalog_facility (id, slug, name, region, tz, catalog_version) values (${facility}, ${facility.replaceAll("_", "-")}, ${"Facility " + facility}, 'US-TN', 'America/Chicago', 1)`,
  );
  await rows(
    "app.catalog_course",
    (sql) =>
      sql`insert into app.catalog_course (id, facility_id, name, catalog_version) values (${course}, ${facility}, ${"Course " + course}, 1)`,
  );
  await rows(
    "app.catalog_hole",
    (sql) =>
      sql`insert into app.catalog_hole (id, course_id, number, catalog_version) values (${hole}, ${course}, 1, 1)`,
  );
  return { facility, course, hole };
}
/** A member of a fresh org with a real credential and a session from the real mint: an operator of `trailId` (operator org, trail scope), or a manager of fac_x (facility org). */
async function newMember(
  kind: "operator" | "manager",
  trailId?: string,
): Promise<Member> {
  seq += 1;
  const uid = freshUuid();
  await createTestUser(uid, `prg-${kind}-${seq}`);
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

async function prgCall(
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
  return await handlePartnerProgrammeRequest(
    new Request(
      `https://project.example.test/functions/v1/programme-config/${path}`,
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
const facilityBody = (
  trailId: string,
  facilityId: string,
  over: Record<string, unknown> = {},
) => ({
  trailId,
  facilityId,
  participation: "accepted",
  stocksMarkers: true,
  holdsSpecialMarker: false,
  connectivity: "weak",
  staffNetwork: true,
  wifiNote: "ask at the desk",
  qrMode: "both",
  ...over,
});
/** The trail's programme row as the OWNER reads it, in the shape the handler returns. */
const trailRow = async (trailId: string) => {
  const r = (
    await rows(
      "app.trail_programme",
      (sql) =>
        sql`select status::text as status, marker_source::text as marker_source, marker_requires_completion, special_marker_funded_by::text as funded_by, special_marker_low_threshold::int as low, web_player_flow, special_marker_sku, special_marker_sponsorship_id::text as sponsorship, fee_model::text as fee_model, fee_amount::float8 as fee_amount, to_char(starts_on, 'YYYY-MM-DD') as starts_on, to_char(ends_on, 'YYYY-MM-DD') as ends_on from app.trail_programme where trail_id = ${trailId}`,
    )
  )[0];
  return r === undefined
    ? null
    : {
        trailId,
        status: r.status,
        markerSource: r.marker_source,
        markerRequiresCompletion: r.marker_requires_completion,
        specialMarkerFundedBy: r.funded_by,
        specialMarkerLowThreshold: r.low,
        webPlayerFlow: r.web_player_flow,
        specialMarkerSku: r.special_marker_sku,
        specialMarkerSponsorshipId: r.sponsorship,
        feeModel: r.fee_model,
        feeAmount: r.fee_amount,
        startsOn: r.starts_on,
        endsOn: r.ends_on,
      };
};
const facilityRows = async (trailId: string) =>
  (
    await rows(
      "app.facility_programme",
      (sql) =>
        sql`select facility_id, participation::text as participation, stocks_markers, holds_special_marker, connectivity::text as connectivity, staff_network, wifi_note, qr_mode::text as qr_mode, pin_epoch::int as pin_epoch from app.facility_programme where trail_id = ${trailId} order by facility_id`,
    )
  ).map((r) => ({
    facilityId: r.facility_id,
    participation: r.participation,
    stocksMarkers: r.stocks_markers,
    holdsSpecialMarker: r.holds_special_marker,
    connectivity: r.connectivity,
    staffNetwork: r.staff_network,
    wifiNote: r.wifi_note,
    qrMode: r.qr_mode,
    pinEpoch: r.pin_epoch,
  }));

Deno.test(
  "S6: a trail's programme upserted through the handler is read back, by the handler and by the owner, as the same thirteen values (a numeric fee as a number, dates as YYYY-MM-DD, nullable fields as null); a second upsert replaces them; web_player_flow stays false",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);

    const none = await prgCall(op, "GET", `programme?trailId=${trail}`);
    assertEquals(
      [none.status, await errOf(none)],
      [422, "not_found"],
      "no programme yet",
    );

    const first = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail),
    );
    assertEquals(first.status, 200, await first.clone().text());
    assertEquals(await dataOf(first), { ok: true });
    const read = await dataOf(
      await prgCall(op, "GET", `programme?trailId=${trail}`),
    );
    assertEquals(
      read.trail,
      trailBody(trail),
      "the handler reads back what it was given",
    );
    assertEquals(read.facilities, []);
    assertEquals(
      await trailRow(trail),
      trailBody(trail),
      "and so does the owner",
    );

    // a second upsert replaces every field, including the ones it nulls
    const second = trailBody(trail, {
      status: "live",
      markerSource: "any_purchase",
      markerRequiresCompletion: false,
      specialMarkerFundedBy: null,
      specialMarkerLowThreshold: 0,
      specialMarkerSku: null,
      feeModel: "per_redemption",
      feeAmount: 0.35,
      startsOn: null,
      endsOn: null,
    });
    assertEquals(
      (await prgCall(op, "POST", "programme/trail", second)).status,
      200,
    );
    assertEquals(
      (await dataOf(await prgCall(op, "GET", `programme?trailId=${trail}`)))
        .trail,
      second,
    );
    assertEquals(await trailRow(trail), second);

    // web_player_flow must stay false: true is refused (a database 22023, answered 422) and nothing changes
    const flow = await prgCall(
      op,
      "POST",
      "programme/trail",
      trailBody(trail, { webPlayerFlow: true }),
    );
    assertEquals(flow.status, 422, await flow.clone().text());
    assertEquals(await trailRow(trail), second);
  },
);

Deno.test(
  "S6: a facility's programme needs the trail's first (422 no_trail); upserted through the handler it is listed with every field, a second upsert replaces it, and the list is the owner's rows",
  DT,
  async () => {
    const trail = await newTrail();
    const op = await newMember("operator", trail);

    const early = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, "fac_x"),
    );
    assertEquals([early.status, await errOf(early)], [422, "no_trail"]);
    assertEquals(await facilityRows(trail), [], "no_trail writes nothing");

    assertEquals(
      (await prgCall(op, "POST", "programme/trail", trailBody(trail))).status,
      200,
    );
    const x = facilityBody(trail, "fac_x");
    const y = facilityBody(trail, "fac_y", {
      participation: "invited",
      stocksMarkers: null,
      holdsSpecialMarker: null,
      connectivity: null,
      staffNetwork: null,
      wifiNote: null,
      qrMode: "rotating",
    });
    for (const body of [x, y]) {
      const res = await prgCall(op, "POST", "programme/facility", body);
      assertEquals(res.status, 200, await res.clone().text());
    }
    const expected = [
      {
        facilityId: "fac_x",
        participation: "accepted",
        stocksMarkers: true,
        holdsSpecialMarker: false,
        connectivity: "weak",
        staffNetwork: true,
        wifiNote: "ask at the desk",
        qrMode: "both",
        pinEpoch: 0,
      },
      {
        facilityId: "fac_y",
        participation: "invited",
        stocksMarkers: null,
        holdsSpecialMarker: null,
        connectivity: null,
        staffNetwork: null,
        wifiNote: null,
        qrMode: "rotating",
        pinEpoch: 0,
      },
    ];
    const listed = async () =>
      (
        (await dataOf(await prgCall(op, "GET", `programme?trailId=${trail}`)))
          .facilities as Array<{ facilityId: string }>
      ).sort((a, b) => a.facilityId.localeCompare(b.facilityId));
    assertEquals(
      await listed(),
      expected.map((e) => ({
        ...e,
        stocksMarkers: e.stocksMarkers ?? false,
        holdsSpecialMarker: e.holdsSpecialMarker ?? false,
      })),
      "the handler lists both (nullable booleans that are null read as false in the list)",
    );
    assertEquals(await facilityRows(trail), expected, "the owner's rows");

    // a second upsert replaces the facility's row
    const res = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, "fac_x", {
        participation: "left",
        stocksMarkers: false,
        holdsSpecialMarker: true,
        connectivity: "none",
        staffNetwork: false,
        wifiNote: null,
        qrMode: "static_pin",
      }),
    );
    assertEquals(res.status, 200, await res.clone().text());
    assertEquals((await facilityRows(trail))[0], {
      facilityId: "fac_x",
      participation: "left",
      stocksMarkers: false,
      holdsSpecialMarker: true,
      connectivity: "none",
      staffNetwork: false,
      wifiNote: null,
      qrMode: "static_pin",
      pinEpoch: 0,
    });
    assertEquals(
      (await facilityRows(trail)).length,
      2,
      "an upsert, not an insert",
    );

    for (const bad of [
      { participation: "maybe" },
      { connectivity: "great" },
      { qrMode: "none" },
      { wifiNote: "x".repeat(501) },
      { extra: 1 },
    ]) {
      assertEquals(
        (
          await prgCall(
            op,
            "POST",
            "programme/facility",
            facilityBody(trail, "fac_x", bad),
          )
        ).status,
        400,
        JSON.stringify(bad),
      );
    }
    assertEquals(
      (await facilityRows(trail))[0]!.participation,
      "left",
      "a malformed body changed nothing",
    );
  },
);

Deno.test(
  "S6 / A3 and A0 (aal gates every class): a programme write needs an operator of the trail AND aal 2 with a live second factor (a manager, an operator at aal 1 and an operator of another trail are each 403 and write nothing); a read needs the operator's scope and aal 2 as well; no bearer is 401; a malformed body is 400",
  DT,
  async () => {
    const trail = await newTrail();
    const other = await newTrail();
    const op = await newMember("operator", trail);
    const foreign = await newMember("operator", other);
    const mgr = await newMember("manager");

    // the control: the operator with the step-up writes
    assertEquals(
      (await prgCall(op, "POST", "programme/trail", trailBody(trail))).status,
      200,
    );
    const before = await trailRow(trail);

    assertEquals(
      (
        await prgCall(
          mgr,
          "POST",
          "programme/trail",
          trailBody(trail, { status: "off" }),
        )
      ).status,
      403,
      "a manager",
    );
    await stepUp(op, 1);
    assertEquals(
      (
        await prgCall(
          op,
          "POST",
          "programme/trail",
          trailBody(trail, { status: "off" }),
          false,
        )
      ).status,
      403,
      "aal 1",
    );
    assertEquals(
      (
        await prgCall(
          foreign,
          "POST",
          "programme/trail",
          trailBody(trail, { status: "off" }),
        )
      ).status,
      403,
      "an operator of another trail",
    );
    assertEquals(
      (
        await prgCall(
          foreign,
          "POST",
          "programme/facility",
          facilityBody(trail, "fac_x"),
        )
      ).status,
      403,
      "an operator of another trail, facility route",
    );
    assertEquals(
      await trailRow(trail),
      before,
      "nothing was written by a refusal",
    );
    assertEquals(await facilityRows(trail), []);

    // reads (class A0) need the operator's scope AND aal 2 as well (partner_authorize 4, M2: the assurance level gates every class including A0): an operator at aal 1 cannot even read
    await stepUp(op, 1);
    assertEquals(
      (await prgCall(op, "GET", `programme?trailId=${trail}`, undefined, false))
        .status,
      403,
      "aal 1 cannot read",
    );
    const read = await prgCall(op, "GET", `programme?trailId=${trail}`);
    assertEquals(read.status, 200, await read.clone().text());
    assertEquals(
      (await prgCall(mgr, "GET", `programme?trailId=${trail}`)).status,
      403,
    );
    assertEquals(
      (await prgCall(foreign, "GET", `programme?trailId=${trail}`)).status,
      403,
    );
    assertEquals(
      (await prgCall(null, "GET", `programme?trailId=${trail}`)).status,
      401,
    );

    for (const bad of [
      trailBody(trail, { status: "paused" }),
      trailBody(trail, { feeAmount: "12" }),
      trailBody(trail, { startsOn: "01/01/2031" }),
      trailBody(trail, { specialMarkerLowThreshold: -1 }),
      { ...trailBody(trail), extra: 1 },
    ]) {
      assertEquals(
        (await prgCall(op, "POST", "programme/trail", bad)).status,
        400,
        JSON.stringify(bad).slice(0, 80),
      );
    }
    assertEquals(
      (await prgCall(op, "GET", "programme")).status,
      400,
      "a trail is required",
    );
    assertEquals(await trailRow(trail), before);
  },
);

Deno.test(
  "S6: the operator rollup lists a trail's rows newest month first with the numeric value and the cohort size, and the sponsor rollup lists a sponsorship's; another trail's operator is 403; an unknown sponsorship is an empty list",
  DT,
  async () => {
    const trail = await newTrail();
    const other = await newTrail();
    const op = await newMember("operator", trail);
    const foreign = await newMember("operator", other);
    await rows(
      "app.operator_rollup",
      (sql) =>
        sql`insert into app.operator_rollup (trail_id, month, metric, value, cohort_n) values
            (${trail}, '2031-02-01', 'completions', 12.5, 12), (${trail}, '2031-03-01', 'plays', 7.25, 11), (${trail}, '2031-03-01', 'completions', 30, 15)`,
    );
    const res = await prgCall(op, "GET", `rollups/operator?trailId=${trail}`);
    assertEquals(res.status, 200, await res.clone().text());
    assertEquals((await dataOf(res)).rollups, [
      {
        trailId: trail,
        month: "2031-03-01",
        metric: "completions",
        value: 30,
        cohortN: 15,
      },
      {
        trailId: trail,
        month: "2031-03-01",
        metric: "plays",
        value: 7.25,
        cohortN: 11,
      },
      {
        trailId: trail,
        month: "2031-02-01",
        metric: "completions",
        value: 12.5,
        cohortN: 12,
      },
    ]);
    assertEquals(
      (await prgCall(foreign, "GET", `rollups/operator?trailId=${trail}`))
        .status,
      403,
    );

    // a sponsorship on the trail (its sponsor organisation is a partner org of kind sponsor)
    const sponsorOrg = freshUuid();
    const sponsorship = freshUuid();
    await rows(
      "app.partner_org",
      (sql) =>
        sql`insert into app.partner_org (id, kind, name) values (${sponsorOrg}, 'sponsor', ${"sponsor " + RUN})`,
    );
    await rows(
      "app.sponsorship",
      (sql) =>
        sql`insert into app.sponsorship (id, sponsor_org_id, trail_id, category, scope, attribution_name, status) values (${sponsorship}, ${sponsorOrg}, ${trail}, 'equipment', 'both', 'Acme Golf', 'live')`,
    );
    await rows(
      "app.sponsor_rollup",
      (sql) =>
        sql`insert into app.sponsor_rollup (sponsorship_id, month, metric, value, cohort_n) values (${sponsorship}, '2031-03-01', 'markers_earned', 41, 20), (${sponsorship}, '2031-02-01', 'markers_earned', 9.5, 10)`,
    );
    const sp = await prgCall(
      op,
      "GET",
      `rollups/sponsor?sponsorshipId=${sponsorship}`,
    );
    assertEquals(sp.status, 200, await sp.clone().text());
    assertEquals((await dataOf(sp)).rollups, [
      {
        sponsorshipId: sponsorship,
        month: "2031-03-01",
        metric: "markers_earned",
        value: 41,
        cohortN: 20,
      },
      {
        sponsorshipId: sponsorship,
        month: "2031-02-01",
        metric: "markers_earned",
        value: 9.5,
        cohortN: 10,
      },
    ]);
    assertEquals(
      (
        await prgCall(
          foreign,
          "GET",
          `rollups/sponsor?sponsorshipId=${sponsorship}`,
        )
      ).status,
      403,
      "another trail's operator",
    );
    // observed, not judged (design 133): a sponsorship that does not exist is an empty list while one outside the caller's scope is 403, so an operator can tell the two apart (ids are random UUIDs)
    const unknown = await prgCall(
      op,
      "GET",
      `rollups/sponsor?sponsorshipId=${freshUuid()}`,
    );
    assertEquals([unknown.status, (await dataOf(unknown)).rollups], [200, []]);
    assertEquals(
      (await prgCall(op, "GET", "rollups/sponsor?sponsorshipId=nope")).status,
      400,
    );
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
      const res = await prgCall(
        busy,
        "GET",
        `rollups/operator?trailId=${trail}`,
      );
      if (res.status !== 200)
        assertEquals(
          res.status,
          200,
          `request ${i + 1}: ${await res.clone().text()}`,
        );
      await res.arrayBuffer();
    }
    const over = await prgCall(
      busy,
      "GET",
      `rollups/operator?trailId=${trail}`,
    );
    assertEquals([over.status, await errOf(over)], [429, "rate_limited"]);
    assert(
      Number(over.headers.get("retry-after")) >= 1,
      "a Retry-After in seconds",
    );
    assertEquals(
      (await prgCall(calm, "GET", `rollups/operator?trailId=${trail}`)).status,
      200,
      "another member is not slowed",
    );
  },
);

/** The admin the harness seeds (helpers.sql puts this uid in app.admin_user), signed in once with a real credential; the programme editor holds an admin to the same roster rule. */
const ADMIN_UID = "00000000-0000-0000-0000-4000000000d0";
let adminSession: Member | null = null;
async function adminMember(): Promise<Member> {
  adminSession ??= await signInAs(ADMIN_UID);
  return adminSession;
}

Deno.test(
  "0110 / S6 (section 140): a facility that is not on the trail's current roster is refused through the real handler, 422 invalid_request, and nothing is stored; an unknown facility is the same 422 (it was a 500); each way onto the roster admits it, a later version that drops it refuses a write that would keep it accepted and leaves the stored row, while a demotion to left is allowed and cannot be taken back; a manager is 403 first; an admin is held to the same rule",
  DT,
  async () => {
    const trail = await newTrail(); // roster version 1: fac_x and fac_y
    const op = await newMember("operator", trail);
    assertEquals(
      (await prgCall(op, "POST", "programme/trail", trailBody(trail))).status,
      200,
    );
    const z = await newFacility(); // a real facility on no roster

    // the 138.4 reproduction at the Edge: the operator writes a facility that has nothing to do with its trail
    const off = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, z.facility),
    );
    assertEquals([off.status, await errOf(off)], [422, "invalid_request"]);
    assertEquals(await facilityRows(trail), [], "nothing is stored");
    // an id that names no facility is the SAME answer (before 0110 a raw foreign-key error: HTTP 500 internal_error)
    const none = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, `fac_nope_${RUN}`),
    );
    assertEquals([none.status, await errOf(none)], [422, "invalid_request"]);
    // another trail's roster does not help
    const elsewhere = await newTrail(false);
    await addRoster(elsewhere, 1, [{ facility: z.facility }]);
    const foreign = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, z.facility),
    );
    assertEquals([foreign.status, await errOf(foreign)], [422, "invalid_request"]);
    assertEquals(await facilityRows(trail), []);
    // the control: a facility that IS on the roster (fac_x) is stored
    const ok = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, "fac_x"),
    );
    assertEquals(ok.status, 200, await ok.clone().text());

    // each way onto the roster admits z: before every leg the latest version holds fac_x only (z refused), then a NEW latest version holds the leg (z stored, with that leg's qr mode)
    const legs: ReadonlyArray<[string, { facility?: string; course?: string; hole?: string; anyOf?: string[] }, string]> = [
      ["a facility member", { facility: z.facility }, "static_pin"],
      ["a course member", { course: z.course }, "both"],
      ["a hole member (no course)", { hole: z.hole }, "rotating"],
      ["an any_of_course_ids member", { anyOf: [z.course] }, "static_pin"],
    ];
    let version = 1;
    for (const [name, member, qrMode] of legs) {
      version += 1;
      await addRoster(trail, version, [{ facility: "fac_x" }]);
      const before = await prgCall(
        op,
        "POST",
        "programme/facility",
        facilityBody(trail, z.facility, { qrMode }),
      );
      assertEquals([name, before.status, await errOf(before)], [name, 422, "invalid_request"]);
      version += 1;
      await addRoster(trail, version, [member]);
      const admitted = await prgCall(
        op,
        "POST",
        "programme/facility",
        facilityBody(trail, z.facility, { qrMode }),
      );
      assertEquals([name, admitted.status], [name, 200]);
      const stored = (await facilityRows(trail)).find((r) => r.facilityId === z.facility);
      assertEquals([name, stored?.qrMode], [name, qrMode]);
    }

    // a later version drops z: a write that would leave it ACCEPTED is refused and the stored row is left exactly as it was (and the list still shows it)
    version += 1;
    await addRoster(trail, version, [{ facility: "fac_x" }]);
    const rowBefore = (await facilityRows(trail)).find((r) => r.facilityId === z.facility);
    const dropped = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, z.facility, { qrMode: "rotating" }),
    );
    assertEquals([dropped.status, await errOf(dropped)], [422, "invalid_request"]);
    assertEquals((await facilityRows(trail)).find((r) => r.facilityId === z.facility), rowBefore);
    const listed = await prgCall(op, "GET", `programme?trailId=${trail}`);
    assertEquals(listed.status, 200);
    assert(
      ((await dataOf(listed)).facilities as Array<{ facilityId: string }>).some((f) => f.facilityId === z.facility),
      "a row written while z was on the roster is still listed after the roster dropped it",
    );
    // the operator's off-switch: the EXISTING row may be demoted (and edited in the same call) although z is off the roster; the player-lane gate (accepted) then no longer holds
    const demoted = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, z.facility, { participation: "left", qrMode: "both" }),
    );
    assertEquals(demoted.status, 200, await demoted.clone().text());
    const rowDemoted = (await facilityRows(trail)).find((r) => r.facilityId === z.facility);
    assertEquals([rowDemoted?.participation, rowDemoted?.qrMode], ["left", "both"]);
    // ... but not taken back, not left invited, and no NEW off-roster row is created, whatever its participation
    for (const participation of ["accepted", "invited"]) {
      const back = await prgCall(
        op,
        "POST",
        "programme/facility",
        facilityBody(trail, z.facility, { participation }),
      );
      assertEquals([participation, back.status, await errOf(back)], [participation, 422, "invalid_request"]);
    }
    assertEquals((await facilityRows(trail)).find((r) => r.facilityId === z.facility)?.participation, "left");
    const fresh = await newFacility();
    const newLeft = await prgCall(
      op,
      "POST",
      "programme/facility",
      facilityBody(trail, fresh.facility, { participation: "left" }),
    );
    assertEquals([newLeft.status, await errOf(newLeft)], [422, "invalid_request"]);
    assertEquals((await facilityRows(trail)).some((r) => r.facilityId === fresh.facility), false);

    // a manager is refused on authority first (403), whatever the facility
    const manager = await newMember("manager");
    const mgr = await prgCall(
      manager,
      "POST",
      "programme/facility",
      facilityBody(trail, z.facility),
    );
    assertEquals(mgr.status, 403);
    const mgr2 = await prgCall(
      manager,
      "POST",
      "programme/facility",
      facilityBody(trail, "fac_x"),
    );
    assertEquals(mgr2.status, 403);

    // an admin may write on any trail, and is held to the same rule
    const admin = await adminMember();
    const adminTrail = await newTrail();
    assertEquals(
      (await prgCall(admin, "POST", "programme/trail", trailBody(adminTrail))).status,
      200,
    );
    const adminOff = await prgCall(
      admin,
      "POST",
      "programme/facility",
      facilityBody(adminTrail, z.facility),
    );
    assertEquals([adminOff.status, await errOf(adminOff)], [422, "invalid_request"]);
    assertEquals(await facilityRows(adminTrail), []);
    const adminOn = await prgCall(
      admin,
      "POST",
      "programme/facility",
      facilityBody(adminTrail, "fac_y"),
    );
    assertEquals(adminOn.status, 200, await adminOn.clone().text());
    // the admin is held to the demotion rule too: an off-roster row the owner planted can be demoted but not kept accepted
    await rows(
      "app.facility_programme",
      (sql) =>
        sql`insert into app.facility_programme (trail_id, facility_id, participation) values (${adminTrail}, ${z.facility}, 'accepted')`,
    );
    const keep = await prgCall(
      admin,
      "POST",
      "programme/facility",
      facilityBody(adminTrail, z.facility, { qrMode: "static_pin" }),
    );
    assertEquals([keep.status, await errOf(keep)], [422, "invalid_request"]);
    const adminDemote = await prgCall(
      admin,
      "POST",
      "programme/facility",
      facilityBody(adminTrail, z.facility, { participation: "declined" }),
    );
    assertEquals(adminDemote.status, 200, await adminDemote.clone().text());
    assertEquals(
      (await facilityRows(adminTrail)).find((r) => r.facilityId === z.facility)?.participation,
      "declined",
    );
  },
);

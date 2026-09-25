// supabase/functions/_shared/me/export-handler.ts
//
// Pure, DI'd core of the `me-export` Edge Function (`GET /v1/me/export`,
// build plan §4.7.1a inventory: "me-export"). Task instruction: "Return
// all of the caller's personal data as JSON: the same row set
// delete_my_data treats as personal, discovered from the same
// pii_retention_policy registry or catalog where possible, so the two
// can't drift."
//
// How export and delete stay in sync (see this round's report for the
// same explanation, restated here at the point of use): `private.
// export_my_data` (0021) is the READ-ONLY twin of `private.delete_my_data`
// (0015) — it walks the EXACT SAME `pg_constraint`-driven loop over
// `private.pii_retention_policy` (0014_hardening.sql), so a table added
// to that registry is picked up by BOTH functions automatically, and a
// table classified for one is classified for the other (there is only
// ONE registry). This handler never re-derives that row set itself — it
// calls `Repo#me.exportMyData()`, which calls `private.export_my_data`
// through the established privileged path, the same pattern `Repo#me.
// deleteMyData()` already uses for `private.delete_my_data`.
//
// Actor-scoped only (task instruction): every row `private.export_my_data`
// returns is looked up `WHERE <column> = p_user_id` — see 0021's own body
// — and the ONLY id this handler (or its Edge Function entrypoint) ever
// passes is `actor.uid`, resolved from the caller's own verified JWT
// (`getActorFromRequest`), never a client-supplied id. There is no path
// by which this endpoint can return another account's data.
//
// Size bound (task instruction: "Document the size bound"): see
// `EXPORT_SIZE_BOUND_BYTES`'s own doc below.

import type { Repo } from "../types.ts";

/** Documented response-size bound for `GET /v1/me/export`. `[inference]`
 * — there is no plan-stated number for this (the build plan names the
 * endpoint, AT 6/§4.7.1a, but not a size limit for it), and this
 * environment has no live account to measure a REAL export's size
 * against. Chosen as a generous, round bound relative to this round's
 * OTHER, plan-stated per-account limits that indirectly cap how much
 * data one account can accumulate: `MAX_DEVICES_PER_USER` (20, the same
 * accepted-follow-up constant `evidence/handler.ts` uses), the evidence
 * rate limits (60/user/h live, 2,000/user/day batch — §4.7 item 8), and
 * `ABSOLUTE_ROW_CAP` (10,000, `packages/rules`' own raw-query DoS bound,
 * re-used by `privileged.ts`). 8 MiB is not derived from any of these by
 * a stated formula — it is a conservative ceiling this handler LOGS a
 * breach of (never silently truncates: a partial export must never look
 * like a complete one) rather than a hard 413 on the response, since
 * refusing to serve a legitimate access request just for being large
 * would itself be the wrong failure mode for a privacy endpoint. Revisit
 * once a real account's export size can be measured against it. */
export const EXPORT_SIZE_BOUND_BYTES = 8 * 1024 * 1024; // 8 MiB

export interface MeExportEnvelope {
  generatedAt: string;
  userId: string;
  data: Record<string, unknown>;
}

export async function handleMeExport(repo: Repo, actorUid: string): Promise<MeExportEnvelope> {
  const data = await repo.me.exportMyData();
  return { generatedAt: repo.now().toISOString(), userId: actorUid, data };
}

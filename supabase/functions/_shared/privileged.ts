// supabase/functions/_shared/privileged.ts
// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1183-1205): "Every
// write runs as service_role, which bypasses RLS. The authorization
// boundary on writes is therefore each Edge Function's own ownership and
// scope check... Writes and privileged reads go only through
// supabase/functions/_shared/privileged.ts -> withOwnership(actor, op)."
//
// TODO(build plan §4.7.1a, lines 1189-1196; out of this stage's scope —
// task instruction excludes "Edge Functions (Deno)"): this is a STUB. The
// real implementation loads the target row by id, asserts
// `row.user_id = actor.uid` (or the partner has_facility_scope /
// has_trail_scope check for partner routes), and only then returns a
// narrow repository object with named methods over fixed tables (e.g.
// `evidenceRepo.insertForActor`) — never the raw supabase-js client
// (A2-10: "It never returns the supabase-js client, because a client
// cannot be scoped to one operation"). It exists here, in real shape but
// with no real body, ONLY so supabase/functions/**/*.ts fixtures have a
// real `withOwnership` symbol to import and so
// @golfraven/service-role-lint has a real "allow-listed file" to exempt —
// the lint's own rule (b) is "any call on a privileged handle outside a
// withOwnership callback", so this file's import shape has to be genuine.
//
// This file is the SOLE allow-listed construction site for a service-role
// client (§4.7.1a rule (a)) and the sole allow-listed place raw
// `.from()`/`.rpc()`/Storage calls or a Postgres driver / SUPABASE_DB_URL
// reference may appear (rules (b), (c)).

// [unverified — training knowledge: the supabase-js import path and
// createClient signature] Real Edge Function code imports the Supabase
// JS client from a Deno-compatible URL import (e.g.
// "https://esm.sh/@supabase/supabase-js@2"); we reference the bare
// package specifier here since this stub is never actually run.
import { createClient } from "@supabase/supabase-js";

export interface Actor {
  uid: string;
  role: "authenticated" | "staff" | "manager" | "operator" | "admin";
}

export interface Op<T> {
  (repo: unknown): Promise<T>;
}

const serviceRoleClient = createClient(
  // [unverified — training knowledge on the env var name] Deno.env.get is
  // the Deno runtime's env accessor; real Edge Functions run on Deno.
  (globalThis as { Deno?: { env: { get(name: string): string | undefined } } }).Deno?.env.get(
    "SUPABASE_URL",
  ) ?? "",
  (globalThis as { Deno?: { env: { get(name: string): string | undefined } } }).Deno?.env.get(
    "SUPABASE_SERVICE_ROLE_KEY",
  ) ?? "",
);

/**
 * The ONLY sanctioned way an Edge Function touches a privileged
 * (service-role) operation. Loads the target row, asserts ownership/scope,
 * then hands the callback a narrow repository object — never the raw
 * client. TODO: the ownership/scope check and the repository object are
 * real Edge Function business logic, out of this stage's scope.
 */
export async function withOwnership<T>(actor: Actor, op: Op<T>): Promise<T> {
  // TODO(out of scope this stage): assert ownership/scope against `actor`
  // before ever touching serviceRoleClient.
  return op(serviceRoleClient as unknown);
}

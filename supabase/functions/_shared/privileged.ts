// supabase/functions/_shared/privileged.ts
// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1183-1205): "Every
// write runs as service_role, which bypasses RLS. The authorization
// boundary on writes is therefore each Edge Function's own ownership and
// scope check... Writes and privileged reads go only through
// supabase/functions/_shared/privileged.ts -> withOwnership(actor, op)."
//
// TODO(build plan §4.7.1a, lines 1189-1196; out of this stage's scope —
// task instruction excludes "Edge Functions (Deno)"): the real
// implementation loads the target row by id, asserts
// `row.user_id = actor.uid` (or the partner has_facility_scope /
// has_trail_scope check for partner routes), and only then returns a
// narrow repository object with named methods over fixed tables (e.g.
// `evidenceRepo.insertForActor`) — never the raw supabase-js client
// (A2-10: "It never returns the supabase-js client, because a client
// cannot be scoped to one operation").
//
// ⛔ FAIL-CLOSED (B6, gate round 2): until that real implementation lands,
// `withOwnership` THROWS — unconditionally, before constructing any
// client and before calling `op` at all. The previous version constructed
// a real service-role `createClient(...)` at MODULE LOAD TIME (so simply
// importing this file, even for its types, created a live privileged
// client sitting in memory) and then handed that same raw client straight
// to the caller's callback with no ownership check — i.e. exactly the
// unscoped, un-narrowed access A2-10 forbids, and worse than doing
// nothing: a caller could plausibly believe `withOwnership` was already
// enforcing something. A stub that throws cannot be mistaken for a
// working authorization boundary, and cannot leak a privileged client
// before real ownership-checking code replaces this function outright.
//
// This file is the SOLE allow-listed construction site for a service-role
// client (§4.7.1a rule (a)) and the sole allow-listed place raw
// `.from()`/`.rpc()`/Storage calls or a Postgres driver / SUPABASE_DB_URL
// reference may appear (rules (b), (c)) — once the real implementation
// exists here. It exists in this throwing shape only so
// `supabase/functions/**/*.ts` fixtures have a real `withOwnership` symbol
// to import and so `@golfraven/service-role-lint` has a real allow-listed
// file to exempt.

export interface Actor {
  uid: string;
  role: "authenticated" | "staff" | "manager" | "operator" | "admin";
}

export interface Op<T> {
  (repo: unknown): Promise<T>;
}

/**
 * The ONLY sanctioned way an Edge Function would touch a privileged
 * (service-role) operation, once implemented. Until the real
 * ownership/scope check and narrow repository object exist, this THROWS —
 * it never constructs a service-role client, and never calls `op`.
 */
export function withOwnership<T>(_actor: Actor, _op: Op<T>): Promise<T> {
  throw new Error(
    "withOwnership() is not implemented yet (build plan §4.7.1a; out of P3 stage a's scope — " +
      "Edge Function business logic). It fails closed: no service-role client is constructed " +
      "and the callback is never invoked. Do not work around this by constructing a client " +
      "directly — see tools/service-role-lint/test/with-ownership.test.ts (asserts this fails " +
      "closed) and tools/service-role-lint generally (blocks a direct service-role client " +
      "outside this file).",
  );
}

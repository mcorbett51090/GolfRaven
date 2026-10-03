// MUST-PASS: every shape the real privileged.ts legitimately uses, so the pass is not simply rejecting everything.
import postgres from "postgres";

declare const Deno: { env: { get(name: string): string | undefined } };

// the self-check's list of roles the edge login must NOT belong to (it names service_role in order to refuse it)
const EDGE_FORBIDDEN_MEMBERSHIPS = ["service_role", "authenticated", "anon"];

// takes NO argument: the one URL is read here, from the one variable
function openPool() {
  const dbUrl = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  if (!dbUrl) throw new Error("not set");
  return postgres(dbUrl, { max: 5 });
}

export async function openScopedTx(db: ReturnType<typeof postgres>, kind: "actor" | "system") {
  return db.begin(async (trx) => {
    if (kind === "actor") await trx`set local role edge_actor`;
    else await trx`SET LOCAL ROLE edge_system`;
    return 1;
  });
}

export async function withOwnershipBatch(trx: { savepoint<T>(cb: (sp: unknown) => Promise<T>): Promise<T> }) {
  return trx.savepoint(async () => 1);
}

function adminClient() {
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
}

export function isServiceRoleBearer(header: string): boolean {
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  return key !== "" && header === key;
}

export function edgeUrl(): string | undefined {
  return Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
}

export async function serverVersion(db: ReturnType<typeof postgres>) {
  return db`select setting from pg_catalog.pg_settings where name = 'server_version_num'`;
}

// ... and the pool's one input is never passed in: `openPool()`
export const pool = (): ReturnType<typeof postgres> => openPool();
export type Tx = postgres.TransactionSql;

// the closed-socket containment hook: the one member of globalThis the real file touches (it only registers a listener)
if (typeof globalThis.addEventListener === "function") {
  globalThis.addEventListener("error", () => undefined);
}

// a numeric / string-literal index is not a computed key: rows[0], row["n"]
export const firstCount = (rows: ReadonlyArray<Record<string, unknown>>) => Number(rows[0]?.["n"] ?? 0);

// a literal-argument .unsafe( is allowed (a fixed statement)
export const rawFixed = (t: { unsafe(sql: string): Promise<unknown> }) => t.unsafe("select 1");

// a message that merely mentions the statement is not a role switch: no role name follows
export const MSG = "expected current_user = 'edge_actor' after SET LOCAL ROLE, got 'x'";
export { EDGE_FORBIDDEN_MEMBERSHIPS, openPool, adminClient };

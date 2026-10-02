// MUST-PASS: every shape the real privileged.ts legitimately uses, so the pass is not simply rejecting everything.
import postgres from "postgres";

declare const Deno: { env: { get(name: string): string | undefined } };

// the self-check's list of roles the edge login must NOT belong to (it names service_role in order to refuse it)
const EDGE_FORBIDDEN_MEMBERSHIPS = ["service_role", "authenticated", "anon"];

function openPool(dbUrl: string) {
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

// a message that merely mentions the statement is not a role switch: no role name follows
export const MSG = "expected current_user = 'edge_actor' after SET LOCAL ROLE, got 'x'";
export { EDGE_FORBIDDEN_MEMBERSHIPS, openPool, adminClient };

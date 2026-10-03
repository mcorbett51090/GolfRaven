// MUST-FAIL (privileged-unsafe-sql, and privileged-forbidden-role on the folded text): raw SQL assembled from two literals so that no single literal reads `SET LOCAL ROLE postgres`.
export async function escalate(t: { unsafe(sql: string): Promise<unknown> }) {
  return t.unsafe("SET LOCAL " + "ROLE postgres");
}

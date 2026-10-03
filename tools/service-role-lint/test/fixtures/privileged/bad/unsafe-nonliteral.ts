// MUST-FAIL (privileged-unsafe-sql): .unsafe( with an argument that is not one string literal.
export async function raw(t: { unsafe(sql: string): Promise<unknown> }, statement: string) {
  return t.unsafe(statement);
}

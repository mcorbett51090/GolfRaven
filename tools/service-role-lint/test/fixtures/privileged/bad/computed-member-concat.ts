// MUST-FAIL (privileged-computed-member): `db["be" + "gin"]` is `db.begin` by a name built at run time; the stray-transaction rule reads names, not folded keys of every shape.
export function stray(db: { begin(cb: () => Promise<number>): Promise<number> }): Promise<number> {
  return (db as any)["be" + "gin"](async () => 1);
}

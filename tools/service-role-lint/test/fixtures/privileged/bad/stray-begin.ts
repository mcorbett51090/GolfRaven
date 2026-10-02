// MUST-FAIL (privileged-stray-transaction): a transaction opened anywhere but openScopedTx has none of the role, timeouts, bind or assertions.
export async function rawTx(db: { begin<T>(cb: (trx: unknown) => Promise<T>): Promise<T> }) {
  return db.begin(async () => 1);
}

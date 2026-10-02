// MUST-FAIL (privileged-stray-transaction): a savepoint outside withOwnershipBatch.
export async function rawSavepoint(trx: { savepoint<T>(cb: (sp: unknown) => Promise<T>): Promise<T> }) {
  return trx.savepoint(async () => 1);
}

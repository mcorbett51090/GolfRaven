// MUST-FAIL (privileged-stray-transaction): `begin` pulled off a connection by destructuring is the same thing, un-greppable as `.begin(`.
export async function sneakyBegin(db: { begin<T>(cb: (trx: unknown) => Promise<T>): Promise<T> }) {
  const { begin } = db;
  return begin(async () => 1);
}

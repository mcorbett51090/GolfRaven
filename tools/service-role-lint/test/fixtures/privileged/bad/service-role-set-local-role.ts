// MUST-FAIL (privileged-forbidden-role): a transaction that switches to the BYPASSRLS role. This is the exact statement edge role PR4b deleted
// from privileged.ts (`set local role service_role`).
export async function withLegacyPath(db: { begin: never }, trx: (s: TemplateStringsArray) => Promise<unknown>) {
  await trx`set local role service_role`;
}

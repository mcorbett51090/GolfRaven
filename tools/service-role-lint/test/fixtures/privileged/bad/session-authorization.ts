// MUST-FAIL (privileged-forbidden-role): SET SESSION AUTHORIZATION is a role switch the allow-list does not name.
export async function auth(trx: (s: TemplateStringsArray) => Promise<unknown>) {
  await trx`set session authorization postgres`;
}

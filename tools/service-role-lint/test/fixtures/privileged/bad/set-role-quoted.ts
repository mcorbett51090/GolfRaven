// MUST-FAIL (privileged-forbidden-role): a quoted role name (here a role that is not an edge role) is read through its quotes.
export async function quoted(trx: (s: TemplateStringsArray) => Promise<unknown>) {
  await trx`set role "authenticator"`;
}

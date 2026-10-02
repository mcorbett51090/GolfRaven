// MUST-FAIL (privileged-guc-in-ts): identity (or anything) read back from a session variable in TypeScript.
export async function whoAmI(trx: (s: TemplateStringsArray) => Promise<unknown>) {
  return trx`select current_setting('request.jwt.claims', true)`;
}

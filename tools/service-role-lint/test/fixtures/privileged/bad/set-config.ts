// MUST-FAIL (privileged-guc-in-ts): identity (or anything) set through a session variable from TypeScript.
export async function guc(trx: (s: TemplateStringsArray, ...v: unknown[]) => Promise<unknown>, uid: string) {
  await trx`select set_config('app.actor', ${uid}, true)`;
}

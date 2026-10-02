// MUST-FAIL (privileged-forbidden-role): the role is not spelled out, so it could be anything at run time.
export async function dynamicRole(trx: (s: TemplateStringsArray, ...v: unknown[]) => Promise<unknown>, role: string) {
  await trx`set local role ${role}`;
}

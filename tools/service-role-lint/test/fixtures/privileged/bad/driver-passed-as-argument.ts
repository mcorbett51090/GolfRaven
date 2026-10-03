// MUST-FAIL (privileged-stray-pool): the driver passed along as a value (any non-call reference is a way to build a pool the call-site rule cannot see).
import postgres from "postgres";

function build(open: (url: string) => unknown) {
  return open("postgres://u@h/db");
}
export const pool = build(postgres as any);

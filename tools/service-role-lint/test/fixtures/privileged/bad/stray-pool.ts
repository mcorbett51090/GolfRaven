// MUST-FAIL (privileged-stray-pool): a second connection pool, opened anywhere but openPool.
import postgres from "postgres";

export function secondPool(url: string) {
  return postgres(url, { max: 1 });
}

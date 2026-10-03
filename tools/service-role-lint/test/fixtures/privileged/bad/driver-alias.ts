// MUST-FAIL (privileged-stray-pool): aliasing the driver. `pg(url)` is a call of `pg`, which the call-site rule does not know is the driver; the alias itself is the finding.
import postgres from "postgres";

const pg = postgres;
export const second = pg("postgres://u@h/db");

// MUST-FAIL (privileged-driver-import): the exact URL the import map resolves `postgres` to, imported by its URL, is a second handle on the driver
// (it is in the lock, so it loads). The driver is imported once, as "postgres".
import pg3 from "https://deno.land/x/postgresjs@v3.4.5/mod.js";

export const n = 1;
void pg3;

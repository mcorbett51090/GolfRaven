// MUST-FAIL (privileged-driver-import): createRequire builds a require() that loads the driver by a name no scan sees.
import { createRequire } from "node:module";

export const pg = createRequire(import.meta.url)("postgres");

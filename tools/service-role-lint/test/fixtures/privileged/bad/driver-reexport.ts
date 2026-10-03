// MUST-FAIL (privileged-driver-import): re-exporting the driver from its URL hands every importer a second, unchecked handle.
export { default as pg } from "https://deno.land/x/postgresjs@v3.4.5/mod.js";

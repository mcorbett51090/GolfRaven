// Vitest config for `record-edge-contract.rec.ts`: the server's own test config (path aliases for the vendored scorer's bare imports) with the
// test root / include pointed at the recorder. See the recorder's header for the command.
import base from "../../../supabase/tests/vitest.config.ts";

const here = new URL(".", import.meta.url).pathname;

export default {
  ...base,
  root: here,
  server: { fs: { allow: [new URL("../../..", import.meta.url).pathname] } },
  test: { include: ["record-edge-contract.rec.ts"] },
};

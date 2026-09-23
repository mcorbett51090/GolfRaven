// Ambient declaration for Vite/Vitest's `?raw` import suffix (imports a
// file's contents as a plain string at test-transform time). Used by
// k2-count-cli.test.ts to read the REAL docs/p0/K2.md without needing
// Node's `fs` module types, which this Worker-scoped tsconfig deliberately
// doesn't include (see tsconfig.json's `types: ["@cloudflare/workers-types"]`).
declare module "*?raw" {
  const content: string;
  export default content;
}

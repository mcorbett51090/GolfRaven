// tools/db/rotate-course-pin-pepper.test.mjs
// Arg/mode surface for the pepper-rotation CLI. No secret assertions: Node
// never holds pepper bytes (the SQL only names the definer call).

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { renderSql, resolveMode } from "./rotate-course-pin-pepper.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, "rotate-course-pin-pepper.mjs");

describe("resolveMode", () => {
  it("maps hyphen CLI aliases to SQL underscore modes", () => {
    assert.equal(resolveMode("non-compromise"), "non_compromise");
    assert.equal(resolveMode("compromise"), "compromise");
    assert.equal(resolveMode("retire-previous"), "retire_previous");
  });

  it("accepts underscore forms too", () => {
    assert.equal(resolveMode("non_compromise"), "non_compromise");
    assert.equal(resolveMode("retire_previous"), "retire_previous");
  });

  it("rejects unknown or missing args", () => {
    assert.equal(resolveMode("rotate"), null);
    assert.equal(resolveMode(""), null);
    assert.equal(resolveMode(undefined), null);
  });
});

describe("renderSql", () => {
  it("prints one-txn SQL calling the definer (no pepper literals)", () => {
    const sql = renderSql("non_compromise");
    assert.match(sql, /^BEGIN;\nSET LOCAL ROLE private_definer;\nSELECT private\.course_pin_pepper_rotate\('non_compromise'\);\nCOMMIT;\n$/);
    assert.doesNotMatch(sql, /gen_random_bytes|course_pin_pepper_previous|encode\(/);
    assert.equal(sql.includes("vault."), false);
  });

  it("embeds compromise and retire_previous modes", () => {
    assert.match(renderSql("compromise"), /course_pin_pepper_rotate\('compromise'\)/);
    assert.match(renderSql("retire_previous"), /course_pin_pepper_rotate\('retire_previous'\)/);
  });
});

describe("CLI entry", () => {
  it("exits 2 and prints usage on bad args", () => {
    const r = spawnSync(process.execPath, [cli, "nope"], { encoding: "utf8" });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /usage:.*non-compromise\|compromise\|retire-previous/);
    assert.equal(r.stdout, "");
  });

  it("prints SQL for non-compromise on stdout", () => {
    const r = spawnSync(process.execPath, [cli, "non-compromise"], { encoding: "utf8" });
    assert.equal(r.status, 0);
    assert.equal(r.stdout, renderSql("non_compromise"));
  });
});

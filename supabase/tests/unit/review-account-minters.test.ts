// supabase/tests/unit/review-account-minters.test.ts
//
// The app-review account can receive no reward, offer, entitlement or marker credit (plan line 1871; AT 14). Migration 0051 makes the four edge_actor-executable definers that create a purchase / credit
// or hand a reward to its holder refuse it. This file pins that, and PINS THE REQUIREMENT ON EVERY FUTURE MINTER:
//
//   1. FIDELITY: each of the four redefinitions in 0051 is its source definition (0046 / 0032) with exactly ONE block added after the delegate check, character for character. (The migration asserts the
//      same thing in the catalogue when it runs; this is the review-time twin, so a hand edit of either side is caught without a database.)
//   2. THE RATCHET: any migration AFTER 0051 that INSERTs into app.offer_code, app.entitlement, app.marker_credit, app.purchase_evidence or app.device_reward_ledger from a function must mention
//      `is_demo_account` in that function's body, or the function must be named in EXEMPT with a reason. This is the S3 / S5 / S6 condition (docs/security/review-account-design.md section 8): the
//      offline-code staff lane (S3), the sponsor / offer minters (S5, S6) and any entitlement minter must refuse the review account IN THE DATABASE, as a returned status or a 42501.
// KNOWN LIMITS of the ratchet (a source scan, not a parser; the catalogue-level proof for the four current definers is the DO block in 0051 itself):
//   - it finds a function body only through `AS <dollar-quote>` (any tag, but not an `AS '...'` single-quoted body or a `BEGIN ATOMIC` SQL-standard body);
//   - it recognises the writers by the literal text `INSERT INTO app.<table>`: a quoted identifier (`"app"."offer_code"`), dynamic SQL (`EXECUTE format(...)`) or a write made through a view
//     or by another function would not be seen;
//   - the refusal is recognised by a CALL to `is_demo_account(` that survives comment stripping: it does not prove the call guards the INSERT (a call in a branch that never runs would pass).
// Review of any new minter must still read the function; the ratchet is the floor that catches the forgetful case, and EXEMPT is where a reviewed exception is written down.
//
//   3. The refusal exists where the writers are TODAY: every function in migrations up to 0051 that INSERTs into those tables is either one of the four, or listed in KNOWN with why it is not an
//      edge_actor entry point.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const MIG = join(import.meta.dirname, "..", "..", "migrations");
const read = (f: string) => readFileSync(join(MIG, f), "utf8");
const files = readdirSync(MIG).filter((f) => /^\d{4}_.*\.sql$/.test(f)).sort();

/** Every CREATE [OR REPLACE] FUNCTION in `sql`, with ANY dollar-quote tag (`$$`, `$fn$`, `$body$`, ...): the body runs from the opening tag to the next occurrence of the SAME tag. */
function functionsOf(sql: string): Array<{ name: string; text: string }> {
  const out: Array<{ name: string; text: string }> = [];
  const re = /CREATE (?:OR REPLACE )?FUNCTION ([a-z_]+\.[a-z_0-9]+)\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sql))) {
    const open = /\bAS\s+(\$[A-Za-z_0-9]*\$)/.exec(sql.slice(m.index));
    if (!open) continue;
    const tag = open[1]!;
    const bodyStart = m.index + open.index + open[0].length;
    const close = sql.indexOf(tag, bodyStart);
    if (close === -1) continue;
    let end = close + tag.length;
    if (sql[end] === ";") end += 1;
    out.push({ name: m[1]!, text: sql.slice(m.index, end) });
  }
  return out;
}

/** The text with SQL comments (`-- ...` and block comments) removed: a MENTION in a comment is not a refusal. */
function withoutSqlComments(sql: string): string {
  return sql.replace(/\/\*[\s\S]*?\*\//g, "").replace(/--[^\n]*/g, "");
}
/** Does the function CALL private.is_demo_account (outside comments)? */
function refusesReviewAccount(fnText: string): boolean {
  return /\bis_demo_account\s*\(/.test(withoutSqlComments(fnText));
}

// CREATION of a row (an INSERT): the point where a reward, credit or purchase comes into being. (Updates move or void an existing row; delete_my_data and the activation helpers do, and are not minters.)
const WRITES = /INSERT INTO\s+app\.(?:offer_code|entitlement|marker_credit|purchase_evidence|device_reward_ledger)\b/;

describe("0051 redefines the four definers as their sources plus ONE block", () => {
  const m51 = functionsOf(read("0051_review_account_window.sql"));
  const cases: Array<[string, string, string]> = [
    ["private.marker_scan_for_actor", "0046_course_qr_marker_scan.sql", "marker_scan_for_actor: a system delegate may not record a marker purchase"],
    ["private.marker_cosignal_attach_for_actor", "0046_course_qr_marker_scan.sql", "marker_cosignal_attach_for_actor: a system delegate may not attach a co-signal"],
    ["private.activate_offer_code_for_actor", "0032_edge_role_hardening.sql", "activate_offer_code_for_actor: a system delegate may not activate a reward"],
    ["private.activate_entitlement_for_actor", "0032_edge_role_hardening.sql", "activate_entitlement_for_actor: a system delegate may not activate a reward"],
  ];
  it.each(cases)("%s", (name, srcFile, anchorMsg) => {
    const src = functionsOf(read(srcFile)).filter((f) => f.name === name);
    expect(src).toHaveLength(1);
    const redefs = m51.filter((f) => f.name === name);
    expect(redefs, "0051 redefines it exactly once").toHaveLength(1);
    const mine = redefs[0]!.text;
    expect(mine.startsWith("CREATE OR REPLACE FUNCTION")).toBe(true);
    // no LATER migration (between the source and 0051) redefines it: the source IS the current definition
    for (const f of files) {
      if (f <= srcFile || f >= "0051") continue;
      expect(functionsOf(read(f)).filter((x) => x.name === name), `${f} redefines ${name}: 0051 must be rebuilt on top of it`).toHaveLength(0);
    }
    const anchor = `  IF v_kind <> 'user' THEN\n    RAISE EXCEPTION '${anchorMsg}' USING ERRCODE = '42501';\n  END IF;\n`;
    const at = mine.indexOf(anchor);
    expect(at, "the block sits right after the delegate check").toBeGreaterThan(-1);
    const after = mine.slice(at + anchor.length);
    expect(after.startsWith("  -- 0051:"), "the added block starts with its 0051 comment").toBe(true);
    const blockEnd = after.indexOf("  END IF;\n") + "  END IF;\n".length;
    const block = after.slice(0, blockEnd);
    expect(block).toContain("private.is_demo_account(v_uid)");
    // removing the block gives the source, with only CREATE -> CREATE OR REPLACE changed
    const rebuilt = (mine.slice(0, at + anchor.length) + after.slice(blockEnd)).replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION");
    expect(rebuilt).toBe(src[0]!.text);
  });

  it("the marker functions RETURN the status review_account; the activations raise 42501 (each function's own refusal style)", () => {
    const sc = m51.find((f) => f.name === "private.marker_scan_for_actor")!.text;
    const ca = m51.find((f) => f.name === "private.marker_cosignal_attach_for_actor")!.text;
    for (const t of [sc, ca]) expect(t).toMatch(/IF private\.is_demo_account\(v_uid\) THEN\n    o_result := 'review_account';\n    RETURN NEXT;\n    RETURN;\n  END IF;/);
    for (const n of ["private.activate_offer_code_for_actor", "private.activate_entitlement_for_actor"]) {
      expect(m51.find((f) => f.name === n)!.text).toMatch(/IF private\.is_demo_account\(v_uid\) THEN\n    RAISE EXCEPTION '[a-z_]+: the review account may not activate a reward' USING ERRCODE = '42501';/);
    }
  });

  it("the migration itself asserts, in the catalogue, that nothing else changed", () => {
    const sql = read("0051_review_account_window.sql");
    expect(sql).toContain("replace(v_src, $blk$");
    expect(sql).toContain("changed an attribute (owner, ACL, search_path");
    expect(sql).toContain("IF v_n <> 4 THEN");
  });
});

describe("every writer of rewards, offers, entitlements and credits refuses the review account", () => {
  // Functions that write those tables up to 0051 and are not (or no longer) edge_actor entry points, with why.
  const KNOWN: Record<string, string> = {
    "app.activate_offer_code": "called only by private.activate_offer_code_for_actor (which refuses) and service_role; its first argument is the bound actor's uid",
    "app.activate_entitlement": "same, via private.activate_entitlement_for_actor",
    "app.resolve_held_offer_code": "an admin / service_role resolution of a code that is already held (0027); no edge role holds EXECUTE (0031 / 0032 grant list), and it only writes the ledger row of that existing code",
    "app.resolve_held_entitlement": "same, for an entitlement",
  };
  const BEFORE = files.filter((f) => f < "0051");
  it("each function up to 0051 that writes the five tables is one of the four, or is named in KNOWN with a reason", () => {
    const four = new Set(["private.marker_scan_for_actor", "private.marker_cosignal_attach_for_actor", "private.activate_offer_code_for_actor", "private.activate_entitlement_for_actor"]);
    const seen = new Set<string>();
    for (const f of BEFORE) {
      for (const fn of functionsOf(read(f))) {
        if (!WRITES.test(fn.text)) continue;
        seen.add(fn.name);
        if (four.has(fn.name)) continue;
        // a trigger function or a helper under another definer: must be listed or must itself be unreachable from edge_actor (not granted in this repo): list it
        expect(Object.keys(KNOWN), `${fn.name} (${f}) writes a reward / credit table and is neither one of the four nor in KNOWN`).toContain(fn.name);
      }
    }
    // the two marker writers are really among the writers (the scan is not vacuous)
    expect(seen.has("private.marker_scan_for_actor")).toBe(true);
    expect(seen.has("private.marker_cosignal_attach_for_actor")).toBe(true);
  });

  // The functions AFTER 0051: the ratchet. Empty today, and that is the point: the day a migration adds a minter it must carry the refusal.
  const EXEMPT: Record<string, string> = {};
  it("a migration after 0051 that writes those tables from a function CALLS is_demo_account in that function (a mention in a comment does not count), or is exempted here with a reason", () => {
    const after = files.filter((f) => f > "0051_review_account_window.sql" && !f.startsWith("0051"));
    const offenders: string[] = [];
    for (const f of after) {
      for (const fn of functionsOf(read(f))) {
        if (!WRITES.test(fn.text)) continue;
        if (refusesReviewAccount(fn.text) || fn.name in EXEMPT) continue;
        offenders.push(`${f}: ${fn.name}`);
      }
    }
    expect(offenders, "S3 / S5 / S6 condition: a minter of offers, entitlements, credits or purchases must refuse private.is_demo_account(<the bound uid>) in the database").toEqual([]);
  });

  it("the detector is not vacuous: it flags a writer without the refusal and passes one with it, for any dollar-quote tag, and a comment-only mention is NOT a refusal", () => {
    const flagged = (sql: string) => functionsOf(sql).filter((f) => WRITES.test(f.text) && !refusesReviewAccount(f.text)).length;
    for (const tag of ["$$", "$fn$", "$body$", "$_x1$"]) {
      const bad = `CREATE FUNCTION private.mint_x(p uuid)\nRETURNS void AS ${tag}\nBEGIN\n  INSERT INTO app.offer_code (id) VALUES (p);\nEND;\n${tag} LANGUAGE plpgsql;`;
      expect(functionsOf(bad), tag).toHaveLength(1);
      expect(flagged(bad), `${tag}: a writer with no refusal is flagged`).toBe(1);
      expect(flagged(bad.replace("BEGIN\n", "BEGIN\n  IF private.is_demo_account(p) THEN RETURN; END IF;\n")), `${tag}: with the refusal it passes`).toBe(0);
      expect(flagged(bad.replace("BEGIN\n", "BEGIN\n  -- must call private.is_demo_account(p) one day\n")), `${tag}: a line-comment mention is not a refusal`).toBe(1);
      expect(flagged(bad.replace("BEGIN\n", "BEGIN\n  /* IF private.is_demo_account(p) THEN RETURN; END IF; */\n")), `${tag}: a block-comment mention is not a refusal`).toBe(1);
    }
    // a body that contains a different dollar-quote tag inside does not end early
    const nested = "CREATE FUNCTION private.mint_y(p uuid)\nRETURNS void AS $outer$\nBEGIN\n  EXECUTE $inner$ select 1 $inner$;\n  INSERT INTO app.entitlement (id) VALUES (p);\nEND;\n$outer$;";
    expect(flagged(nested)).toBe(1);
  });
});

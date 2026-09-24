# Gate (close) — P0 desk tools: re-check of `gate-desk-tools.md` findings

**Branch:** `claude/golf-trails-golfnow-app-lumnqo` at `4c9fa76` ("p0 tools: close desk-tools gate findings").
**Reviewed against:** decision 0001 Addenda F, G and **H**. Addendum H was committed in `6014254`, before the fix
commit and before any X4 fetch. **Scope:** only the BLOCKING and SHOULD-FIX items in `gate-desk-tools.md`, plus any
risk the new code (`pdf-extract`, `evidence-extract`, `slate`, `run-dir`) adds to an X2 or X4 verdict. I wrote none
of the code. **Gate date:** 2026-09-24.

## Verdict

**PR: PASS.**

- No BLOCKING findings are open.
- All 9 original SHOULD-FIX items are closed in code.
- The two new SHOULD-FIX items below do not risk the correctness of an X2 or X4 verdict. C1 fails closed. C2 is
  a stale description in a doc.
- **C2 must land before the first X2 fetch.** It is the documentation step of S3's own fix.

## Build, typecheck, test

| Step | Result |
|---|---|
| `pnpm install --frozen-lockfile --config.engine-strict=false` | OK. "Lockfile is up to date". |
| `pnpm --config.engine-strict=false -r typecheck` | OK, all projects. |
| `pnpm --config.engine-strict=false -r build` | OK. |
| `pnpm --config.engine-strict=false -r test` | OK. tools/p0: 13 files, 241 tests. signup-worker: 205. mobile: 8. catalog: 3. matching: 1. rules: 1. |
| `git status --short` afterwards (also after every probe) | Empty. All probe output went to the scratchpad or to the OS temp dir. |

## Closure table

| id | Original finding | Status | Evidence (file:line, then the probe that shows it) |
|---|---|---|---|
| B1 | A failed fetch counted as "not covered" and led to KILL with exit 0 | **CLOSED** | `x4-verify.ts:97-111` gives three outcomes (404/410 not live; 403/429/5xx/other indeterminate). `:305-321` classes blocked/error as indeterminate. `:334-346` classes a failed body read as indeterminate. `:196-206` sets the trail to `not-run`. `:416`, `:511-513` exit 1. `p0-desk.ts:259-269` gives `partial-blocked`. Probes B1a–e: one of two RTJ courses blocked (thrown tunnel-403 and proxy `x-deny-reason`), site 403/429/500/503, timeout, DNS. Each gave `RTJ: not run — indeterminate (1)` and **exit 1**. Control B1f (404) gave a definitive `1/2 KILL`, exit 0. p0-desk with one of two blocked, and with a 429: `[PARTIAL-BLOCKED]`, exit 1. |
| B2 | "Live" did not check the id, the host, or path vs query | **CLOSED** | `x4-verify.ts:65-82` parses `<id>` from an exact configured-URL regex (https, `www.golfnow.com`, numeric id) and otherwise refuses. `:118-132` requires the final `hostname === "www.golfnow.com"` and the `pathname` to contain `/tee-times/facility/${id}-`. Probes: redirect to a different facility naming the course → not live. Pattern only in the query → not live. Foreign host → not live. Lookalike `www.golfnow.com.evil.example` → not live. Id-prefix trick `22220-` → not live. An `http://` configured URL → refused, exit 1. |
| S1 | Evidence not bound to its SHA | **CLOSED** | `x2-verdict.ts:128-136` recomputes the SHA-256 from the raw bytes and refuses on mismatch. `:145` re-derives the text with the same extractor used at fetch time; the stored text file is never read. Probes: an edited `text/<sha>.txt` (quote only in the edit) → quote not verbatim, TN unconfirmed. Raw bytes with appended text → refusal, exit 1. A PDF's manifest edited to `"manual"` with a typed text file → the typed text was ignored and the quote failed. |
| S2 | Evidence not bound to its trail; foreign final host accepted | **CLOSED** | `x2-verdict.ts:109-151` builds the map per trail. `:137-144` excludes an entry whose final hostname differs from the configured hostname. `:196-205` refuses a citation outside the trail. Probes: TN citing VI's SHA → refusal, exit 1. RTJ evidence that redirected to `parked-domains.example` → excluded, and citing it → refusal, exit 1. |
| S3 | The VI terms PDF could never be read | **CLOSED (code)** / doc step open, see C2 | `package.json` pins `"unpdf": "1.8.1"` exactly. The lockfile resolves `unpdf@1.8.1` with an integrity hash and no dependencies; its only peer is `@napi-rs/canvas`, which is optional and not installed. `pdf-extract.ts:317,337-346`. `evidence-extract.ts:418-436` runs the same function at fetch time and at verdict time. Probe: a real 124 KB, 10-page PDF with embedded DejaVu fonts, served as `application/pdf`, was stored as `auto-pdf` with `extractor: unpdf@1.8.1`. Two verbatim quotes from it confirmed VI. A quote not in the PDF left VI unconfirmed. Extraction is deterministic (two runs gave identical 4295-char text). A real LibreOffice-produced PDF also extracted. |
| S4 | Inline tags inserted spaces | **CLOSED** | `text-extract.ts:72-110,151`: inline boundaries become `""`, and block or unknown tags become `" "`. Probe: `<a>Bear Trace</a>, <a>Fall Creek Falls</a>.` and `Sea<b>son</b>` with quotes copied from a browser ("The trail: Bear Trace, Fall Creek Falls.", "Season runs March through November.") → TN confirmed. |
| S5 | A partial X2 block read as a clean result with exit 0 | **CLOSED** | `x2-verdict.ts:118-125,309-313` lists every failed or blocked source in `reasons`. `:329-331`, `:430-432` exit 1. `p0-desk.ts:188-199` adds `partial-blocked`, and `:321-325` exits 1. Probes: RTJ blocked and the VI PDF returning 503 → both listed ("Source BLOCKED …", "Source failed … HTTP 503"), plus a "Refusing a clean pass/kill read" line, **exit 1**. p0-desk with 5 of 7 fetched → `[PARTIAL-BLOCKED]`, both URLs named, exit 1. |
| S6 | No timeout or size cap on the body read | **CLOSED** | `net.ts:198-245` races the abort signal and enforces the byte cap while streaming. `x2-fetch.ts:141-142,207-221,260-264` and `x4-verify.ts:282-283,329-346,353-355` keep the timer running through the body read. Probes against a real local HTTP server: headers followed by a stall → x2 `FAILED … body read aborted (timeout)` at 30.1 s and x4 `indeterminate` at 30.2 s (default 30 s timeout), with no hang. A 12 MB body → `exceeds 10485760 bytes (stopped mid-stream)`, a clean failure in x2 and indeterminate in x4. Control: a 9 MB body fetched OK. |
| S7 | Outputs landed inside the repo; a run dir was committed | **CLOSED** (see C1 for a regression in x2-verdict) | `run-dir.ts:275-301` defaults to `os.tmpdir()` and refuses an implicit in-repo path. `.gitignore` adds the four patterns. `git ls-files` shows no committed run dir. Probes run from `cwd=tools/p0` with no output flag: p0-desk → `/tmp/p0-desk-run-…`; x2-fetch → `/tmp/x2-evidence-…`; x4-verify → `/tmp/x4-verify-result-…`. The tree was clean afterwards. |
| S8 | Verdict did not echo the facts checked | CLOSED (not re-probed beyond the output) | `x2-verdict.ts:158-171,315-325,352-369` echo each fact and the roster size. |
| S9 | The config lists homepages only | Unchanged (operator step) | `config/x2-sources.json` is unchanged. This does not risk a verdict. The README asks the operator to add rules pages. Out of scope for this close. |

## New-code risk questions (scope item 2)

1. **Could the X2 "same-site redirect" rule let another organisation's page count as a trail's official
   source?** No. The rule is exact hostname equality (`x2-verdict.ts:140-144`), not "same site" or same
   registrable domain. A redirect to any other hostname is excluded, and citing it is refused (probe S2b). The
   rule errs the other way: a same-organisation redirect from the bare domain to `www.` is also excluded
   (probe S2c: `tngolftrail.net` → `www.tngolftrail.net`, then a refusal). That fails closed and loud; see NIT C3.
   (Known limit, not a finding: the manifest's `trails` grouping and `url` field are trusted. Moving an entry
   between trails by hand-editing the manifest is deliberate tampering, not the accidental misuse that S2
   covered.)
2. **Does the N7 slate-completeness refusal block a legitimate 2-of-3 X2 pass?** No.
   - N7 exists only in `x4-verify` (`:389-397`). `x2-verdict` has no such refusal. A missing third trail gives
     `No confirmation entry`, the trail is unconfirmed, and the result is **PASS (2 of 3), exit 0** (probe
     "2-of-3, third trail missing").
   - For X4, the refusal can be overridden with `--slate` (probe N7b: `--slate TN,RTJ` ran, exit 0), and
     `p0-desk` passes the trails that are present (`p0-desk.ts:235-236`).
   - One edge remains: if the unconfirmed third trail also had a failed or blocked source, `x2-verdict` still
     computes `overallVerdict: "pass"`, but it exits 1 with a "refusing" line (probe S5b), even though no retry
     could change a PASS. That is over-conservative, not wrong; see NIT C4.
3. **Is unpdf pinned exactly and used without network access?** Yes.
   - The version is exactly `1.8.1` in both `package.json` and the lockfile, and `PDF_EXTRACTOR_ID` matches.
   - The unpdf build bundles pdf.js. In Node, `standardFontDataUrl` and `cMapUrl` would be local `file:` URLs,
     taken from `pdfjs-dist` only if that package resolves. It does not resolve here (`ERR_MODULE_NOT_FOUND`),
     so those defaults are not set.
   - Probe `nonet.mjs` stubbed `fetch`, `net.Socket.connect`, `http(s).request` and `dns.lookup`, then extracted
     text from three PDFs (embedded fonts, LibreOffice output, and a non-embedded Helvetica PDF). It recorded
     **0 network attempts**.

## Findings

| id | severity | file:line | finding | fix |
|---|---|---|---|---|
| C1 | SHOULD-FIX (no verdict risk; fails closed) | `tools/p0/src/x2-verdict.ts:420-428` | The S7 default `--out` is `path.join(defaultOutsideRepoDir(...), "result")`, but that directory is never created. `x2-verdict` run without `--out` crashes: `ENOENT … /tmp/x2-verdict-result-…/result.json`, exit 1, and no verdict is written or printed. The README example passes `--out`, which avoids it. No test covers the default path. | Add `await mkdir(path.dirname(outPrefix), { recursive: true })` before the first `writeFile`, plus a test of the CLI default. |
| C2 | SHOULD-FIX (pre-registration record; must land before the first X2 fetch) | `docs/p0/X2.md:46-48` | The X2 METHOD still says a PDF is stored as `"manual"` and that "no PDF-parsing dependency is added, so a PDF's text is never pretended to have been read". The code now extracts PDF text with `unpdf@1.8.1` (`auto-pdf`). The original S3 fix asked for the method to be noted in X2.md before the first successful fetch; that step was not done. The verdict computation is not affected, but the pre-registered method text contradicts what the tool does. | Replace that sentence: HTML is tag-stripped with inline elements joined; PDF text is derived from the stored bytes with `unpdf@1.8.1` at fetch time and again at verdict time; quotes are copied from `text/<sha>.txt`. |
| C3 | NIT | `tools/p0/src/x2-verdict.ts:140-144`; `tools/p0/src/x2-fetch.ts:314-334` | Evidence excluded as a cross-host redirect is dropped **silently**. `x2-fetch` still prints it as `OK`. It is not added to `failedSources`, so `hasFailedSource` stays false. A same-organisation bare-domain → `www.` redirect falls in this class. Today a citation to it is refused loudly. If a human instead removes that citation, the trail reads as a genuine KILL. Whether the configured hosts redirect to another hostname could not be checked: every host returned `CONNECT tunnel failed, response 403` from this session's proxy (class I, indeterminate). | Record an excluded entry in the trail's `failedSources` (reason "final host X ≠ configured host Y"), flag it in the `x2-fetch` summary, or allow listed hosts per trail in `x2-sources.json`. Alternatively, have operators configure the canonical URL after redirects. |
| C4 | NIT | `tools/p0/src/x2-verdict.ts:329-338,374-380,430-432` | The S5 refusal ignores the outcome. (a) With 2 trails confirmed, a third trail's failed source still exits 1, although a retry cannot change PASS (probe S5b). (b) When the refusal does matter (1 confirmed plus failed sources), the JSON still says `overallVerdict: "kill"`; only `anyUnconfirmedWithFailedSource: true` and the markdown line show the refusal. | Optional: refuse only when `confirmed < 2` and `confirmed + unconfirmedWithFailed ≥ 2`, and in that case set `overallVerdict` to `"indeterminate"`, mirroring Addendum H for X4. Otherwise report failed sources as warnings. Owner's call. |

The following was observed and is not a finding. Addendum H's "path contains `/tee-times/facility/<id>-`" is
implemented as a substring check on `pathname`. So a made-up path
`/tee-times/facility/9999-x/tee-times/facility/2222-y/search` counts as live (probe B2f). That matches the
addendum's literal wording, and GolfNow does not produce URLs of this shape.

## Probe scripts

All probes are in `/tmp/claude-0/-home-user/e882a8e1-fdd5-58a6-905a-398cd619db83/scratchpad/close/`.

- `shim.mjs` is a `--import` fetch shim that routes requests to canned responses or to the local server.
- `server.mjs` is a real HTTP server serving the stall, 12 MB and 9 MB bodies.
- `x4probe.mjs` covers B1, B2, S6 (x4) and N7.
- `x2probe.mjs` covers S1–S6 (x2) and the 2-of-3 cases.
- `deskprobe.mjs` covers p0-desk S5/B1 and S7.
- `nonet.mjs` covers unpdf with no network access.

Every probe ran against the built `tools/p0/dist/` CLIs at `4c9fa76`.

# @golfraven/import

On-device file import for a played round (build plan §7.3 lane 2, "Import
a round (FIT/GPX/CSV), parsed on device"). Each parser turns raw file
bytes into a normalized `ImportedRound`; `toMatcherInput` adapts that into
`@golfraven/matching`'s `matchRoute()` input; `correlationKey` gives the
`health_route` ↔ `file_import` correlation buckets (build plan §4.5).

Parsing is pure: bytes in, a result out, no filesystem or network access.
The same code runs on device (Expo) and in tests.

## Security hardening (Opus security gate, commit `6cddec0` follow-up)

A 19 MB crafted FIT file drove `fit-file-parser` to 2–3.4 GB peak RSS and
up to 30 s wall time before this pass. The fixes, in order of how a
hostile file meets them:

1. **`MAX_FIT_INPUT_BYTES` (5 MB, down from the general 20 MB cap).** A
   cheap, first-line refusal for the common case.
2. **`fit-prescan.ts`** walks the FIT record/definition headers itself —
   no field values, no per-message allocation — before `fit-file-parser`
   ever sees the bytes. It refuses a file with over 250k messages or over
   250k cumulative definition-field entries (catching both "millions of
   tiny messages" and "a few enormous definitions" flood shapes), and it
   replaces `fit-file-parser`'s `includeUnmappedMessages` option (which
   retains full raw field data per unmapped message) by tallying which
   global message numbers occur itself.
3. **`csv-rows.ts`'s row cap** (`MAX_CSV_ROWS`, checked *during*
   tokenization) stops a CSV file of millions of tiny rows early — a
   19.9 MB file of ~9.9M empty rows took 17.8 s to tokenize before this;
   0.3 s after.
4. **Bounded warnings/errors.** `finalizeWarnings` caps any result at 50
   warnings plus one "N more" entry; `truncateEcho`/`finalizeError` cap
   any file-derived string embedded in a warning or error at 64
   characters, so a crafted field can't turn the diagnostic output itself
   into an unbounded-memory vector.
5. **`parseRound(bytes, {format, signal, tz})`** threads an optional
   `AbortSignal` through to the parsers. Honest limit, stated once here
   rather than everywhere it applies: a synchronous CPU-bound walk in JS
   can only be interrupted between iterations it chooses to check at,
   never truly preempted, and `fit-file-parser`'s own decode isn't
   abortable at all once started. **The app is expected to run parsing
   inside a worker with its own hard wall-clock timeout** — that outer
   boundary is what actually guarantees a stuck parse can't hang
   anything; `signal` support here is a cooperative fast-exit for the
   common case, not a replacement for it.

None of this reached `matchRoute()` or `@golfraven/matching` — the bug
and the fix are entirely on this package's untrusted-input boundary.

## Modules

| File | What it does |
|---|---|
| `types.ts` | `ImportedRound` and the `ImportResult` discriminated union every parser returns. |
| `safety.ts` | Size caps (general 20 MB, FIT 5 MB), the CSV row cap, the fix cap, warning/echo bounding, strict-decimal parsing, accuracy/text sanitization. |
| `timestamps.ts` | Strict ISO 8601 (`Z`/offset required, year ≥ 2000) timestamp parsing shared by GPX and CSV — never `Date.parse`. |
| `fit-prescan.ts` | The header-only FIT walker: message/field-count caps, CRC verification, unmapped-message tallying — all before the real decode. |
| `csv-rows.ts` | A minimal RFC 4180 CSV tokenizer (no external dependency), with an early-exit row cap. |
| `parse-csv.ts` | The minimal CSV format: `timestamp,lat,lon[,accuracy]` or `date,course,holes,score`, detected from the header, not guessed. |
| `parse-gpx.ts` | GPX 1.0/1.1 `trkpt`/`rtept` import via `sax` (strict mode), with a pre-parse `<!DOCTYPE`/`<!ENTITY` refusal (XXE policy). |
| `parse-fit.ts` | FIT import via `fit-file-parser`, gated by `fit-prescan.ts`. |
| `parse-fit-scorecard.ts` | The isolated, currently-`[unverified]` Garmin golf-scorecard extraction hook — see its doc comment. |
| `parse-round.ts` | `parseRound`: a single dispatch entry point over the three parsers, carrying `tz`/`signal` through. |
| `to-matcher-input.ts` | `toMatcherInput`: adapts an `ImportedRound` into `@golfraven/matching`'s `MatchRouteInput`. |
| `correlation.ts` | `correlationKey`: the ±15 min / same-facility bucket *set* for the `health_route` × `file_import` `max`-combination pair (§4.5). |

## Why `fit-file-parser`

Two options were evaluated for decoding FIT files:

- **Garmin's own `@garmin/fitsdk`.** Its `package.json` license field says
  only `"SEE LICENSE IN LICENSE.txt"`. Reading that file from the
  published npm tarball: it is Garmin's own "Flexible and Interoperable
  Data Transfer (FIT) Protocol License Agreement", not an OSI license.
  Section 2(c) forbids sublicensing, redistributing or otherwise making
  the Licensed Technology available to third parties, and 2(d) forbids
  distributing it (or a derivative) under any license that would require
  source disclosure. That's a real constraint on shipping it inside an
  npm dependency tree of an app this repo distributes — not a blocker
  worth fighting through for a build-plan task that explicitly asks for
  an MIT/BSD/Apache package.
- **`fit-file-parser` (MIT, `jimmykane/fit-parser`).** Chosen. Confirmed
  MIT via `npm view fit-file-parser license` and the package's own
  `LICENSE` file. It also happens to be a better fit mechanically: it
  ships both a full profile-aware parser (`FitParser`/`parseAsync`) *and*
  a standalone binary `FitEncoder` (`fit-file-parser` re-exports both from
  its main entry), which is what `test/fixtures/fit-helpers.ts` uses to
  build synthetic FIT files for the tests — no separate hand-written
  encoder was needed.

Pinned at an exact version (`6.1.2`, `save-exact=true` per the repo's
`.npmrc`) like every other dependency in this monorepo.

## Ambiguities and design decisions

Recorded here for the same reason `@golfraven/matching`'s README records
its own list: the build plan under-specifies these, and a silent choice
is worse than a documented one.

1. **Golf's FIT sport id.** The build plan flagged "golf may be sport 25
   `[unverified — check the decoder's profile]`". Checked: `25` maps to
   `'golf'` in `fit-file-parser`'s bundled profile table
   (`profile-lookup-data.js`), which is the same public FIT SDK profile
   table every FIT decoder ships — not a guess specific to this library.
   What's still genuinely unverified is only that this was never
   confirmed against a real device capture (no S62/Approach file was
   available). `parse-fit.ts` imports anyway when `session.sport` isn't
   `'golf'` — it warns rather than refuses, since a device or app that
   mis-tags the sport (or a user importing a non-golf FIT by mistake)
   shouldn't lose an otherwise-usable route; downstream scoring, not this
   package, is where a mismatched sport should matter.
2. **The Garmin golf-scorecard FIT layout is unverified and unextracted
   today.** `fit-file-parser`'s profile has no scorecard message
   definitions at all — nothing in the public FIT SDK profile documents
   `GARMIN/SCORE/SCORECARD`. `parse-fit-scorecard.ts` is deliberately a
   small, isolated function (per the build plan's own instruction) that
   today does the one honest thing possible without a real sample:
   reports every FIT message number the decoder's profile didn't
   recognize as a warning, rather than silently dropping it. It's the
   only place that needs to change once real S62 files arrive
   (`test/fixtures/real/README.md`).
3. **`totalScore` is a separate field from `scores`.** The minimal CSV
   scorecard format (`date,course,holes,score`) carries only a
   round-total stroke count, never per-hole strokes. Rather than stuff a
   single-hole-shaped entry into `scores: ImportedScoreHole[]` to
   represent a total (which would make "one entry" ambiguous between "one
   hole played" and "the total"), `ImportedRound` carries `totalScore` as
   its own optional field. `scores` stays reserved for a source that
   genuinely has per-hole data (a future real scorecard FIT).
4. **`correlationKey` returns a 3-key neighbor set, not one bucket.**
   The build plan's original text asked for "the ±15-minute correlation
   bucket" (singular); a security-review follow-up asked specifically for
   the neighbor-bucket fix after the original single-nearest-bucket
   version was shown to miss a boundary-straddling pair. It now returns
   `{floor(t/15min) - 1, floor, floor + 1}` as three keys — see the doc
   comment in `correlation.ts` for the short proof that any two
   timestamps within 15 minutes of each other always share at least one
   of the two 3-key sets. **Routeless-only invariant:** it returns
   `undefined` whenever `round.fixes.length === 0`, not just when
   `startedAt` is absent — a routeless import is `localDate`-only
   evidence (A2-17) and must never be correlatable by start time, even if
   some `startedAt` value happened to be present on the object.
5. **GPX course-name priority.** `<trk><name>` wins over `<metadata><name>`
   (GPX 1.1) or the top-level `<name>` (GPX 1.0), on the theory that a
   track's own name is more likely to be the specific round/course name a
   watch or app assigned, while metadata/top-level `<name>` is more often
   the file or device's generic label.
6. **Routeless `localDate` sourcing, and the `tz` option.** A routeless
   import (`fixes.length === 0`) never sets `startedAt`/`endedAt` — only
   `localDate`, and only from a source that's genuinely local:
   - FIT: `activity.local_timestamp` (the FIT-native local-wall-time
     field) if present.
   - GPX: a file-level `<metadata><time>`/top-level `<time>` *if it
     carries its own explicit numeric offset* (its literal written date is
     used as-is, per the instruction that an offset-bearing source
     timestamp is authoritative for its own date) — a bare `Z` timestamp
     is *not* trusted as "local" on its own, since `Z` only means
     "normalized to UTC", not "known to be facility-local".
   - Otherwise, an optional caller-supplied `tz` (IANA timezone, the
     facility's own `tz`, build plan §4.1) converts whatever UTC instant
     is available.
   - With none of the above, `localDate` is left undefined and a warning
     says so. CSV's fixes-format header has no separate date field at all
     to fall back to in this case (only the scorecard header does, and
     that's already an explicit local date with nothing to derive).
7. **A dropped invalid fix never fails the whole parse.** One
   out-of-range coordinate, an unparseable strict-ISO timestamp, or a
   truncated CSV row is dropped with a warning; the rest of the file is
   still imported. The one exception is the CSV scorecard's
   `date`/`holes`/`score` fields, which are refused outright when
   malformed — a scorecard round is one row, so there's no "rest of the
   file" to salvage.
8. **XXE policy.** `sax` never performs any I/O of its own (it's a pure
   string tokenizer — there is no DTD-fetch code path to disable), but a
   `<!DOCTYPE`/`<!ENTITY` declaration is refused outright before the text
   is even handed to the parser, and again if `sax` itself reports a
   doctype. Belt and suspenders, and it means "no external entities, no
   DTD fetch" is true by construction rather than by trusting a specific
   library's internals.
9. **A file-imported fix's `simulated` is left unset, never asserted
   `false`.** `@golfraven/matching`'s `RouteFix.simulated` models a
   live-location mock-provider signal; a file this package imports isn't
   a live capture, so it genuinely doesn't know whether the *original*
   device's GPS was mocked at capture time, and asserting `false` would
   overclaim that it checked. `matchCheckIn`'s foreground check-in path
   specifically requires `simulated === false` to accept a fix as a
   co-signal — a file-imported fix should never be mistakable for that
   kind of live-verified evidence.
10. **CSV/GPX timestamps require a strict ISO 8601 `Z`/offset, reject a
    year before 2000, and lat/lon/accuracy go through a decimal-only
    regex before `Number()` is ever called** — `Number("")` is `0`, which
    would otherwise silently turn a missing coordinate into "null
    island". `timestamps.ts` and `safety.ts`'s `parseStrictDecimal` are
    the shared implementations.
11. **`ImportedRound`'s free-text fields (`courseNameHint`, `device`) are
    control-character-stripped and capped at 120 characters**
    (`safety.ts`'s `sanitizeText`). This is a safety cap on what this
    package stores, not a full sanitizer for any particular downstream
    sink — a spreadsheet export still needs its own formula-injection
    guard (a leading `=`/`+`/`-`/`@`) at the point it writes a cell; that
    guard depends on the destination format, so it's the exporter's job,
    not this parser's. (Confirmed against the security probe: a course
    name of `=HYPERLINK(...)` passes through unchanged today, by design.)

## Not this package's job

Deciding rewards (`@golfraven/rules` `scorePlay`), the actual `matchRoute`
call (the app/server wires `toMatcherInput`'s output into
`@golfraven/matching` with real candidate courses), and the server-side
`health_route` × `file_import` `max`-combination logic that
`correlationKey` feeds are all out of scope here.

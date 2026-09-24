# @golfraven/import

On-device file import for a played round (build plan §7.3 lane 2, "Import
a round (FIT/GPX/CSV), parsed on device"). Each parser turns raw file
bytes into a normalized `ImportedRound`; `toMatcherInput` adapts that into
`@golfraven/matching`'s `matchRoute()` input; `correlationKey` gives the
`health_route` ↔ `file_import` correlation bucket (build plan §4.5).

Parsing is pure: bytes in, a result out, no filesystem or network access.
The same code runs on device (Expo) and in tests.

## Modules

| File | What it does |
|---|---|
| `types.ts` | `ImportedRound` and the `ImportResult` discriminated union every parser returns. |
| `safety.ts` | The shared 20 MB size cap, 200k fix cap, and lat/lon/timestamp validation every parser applies. |
| `csv-rows.ts` | A minimal RFC 4180 CSV tokenizer (no external dependency). |
| `parse-csv.ts` | The minimal CSV format: `timestamp,lat,lon[,accuracy]` or `date,course,holes,score`, detected from the header, not guessed. |
| `parse-gpx.ts` | GPX 1.0/1.1 `trkpt`/`rtept` import via `sax` (strict mode), with a pre-parse `<!DOCTYPE`/`<!ENTITY` refusal (XXE policy). |
| `parse-fit.ts` | FIT import via `fit-file-parser`. |
| `parse-fit-scorecard.ts` | The isolated, currently-`[unverified]` Garmin golf-scorecard extraction hook — see its doc comment. |
| `to-matcher-input.ts` | `toMatcherInput`: adapts an `ImportedRound` into `@golfraven/matching`'s `MatchRouteInput`. |
| `correlation.ts` | `correlationKey`: the ±15 min / same-facility bucket for the `health_route` × `file_import` `max`-combination pair (§4.5). |

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
4. **`correlationKey` returns one bucket, not a set.** The build plan asks
   for "the ±15-minute correlation bucket" (singular). This buckets by
   rounding `startedAt` to the nearest 15-minute mark. That's a known,
   documented approximation (see the doc comment in `correlation.ts`): two
   evidence rows that straddle a rounding boundary but are still within
   the nominal ±15 min window can round to different buckets and miss.
   P3's own correlation logic (out of this package's scope) isn't
   required to trust only this key — it can fall back to a direct
   timestamp comparison when the bucket alone doesn't produce a match.
5. **GPX course-name priority.** `<trk><name>` wins over `<metadata><name>`
   (GPX 1.1) or the top-level `<name>` (GPX 1.0), on the theory that a
   track's own name is more likely to be the specific round/course name a
   watch or app assigned, while metadata/top-level `<name>` is more often
   the file or device's generic label.
6. **A GPX file with no per-point `<time>` falls back to a file-level
   timestamp for `localDate`** (`<metadata><time>` or GPX 1.0's top-level
   `<time>`), rather than leaving the round entirely undated. If neither
   exists either, the round genuinely has no date and a warning says so —
   `ImportedRound.startedAt`/`endedAt`/`localDate` can all be absent for a
   route-less, dateless file, and callers should treat that as unusable
   evidence.
7. **A dropped invalid fix never fails the whole parse.** One
   out-of-range coordinate or a truncated CSV row is dropped with a
   warning; the rest of the file is still imported. The one exception is
   the CSV scorecard's `date`/`holes`/`score` fields, which are refused
   outright when malformed — a scorecard round is one row, so there's no
   "rest of the file" to salvage.
8. **XXE policy.** `sax` never performs any I/O of its own (it's a pure
   string tokenizer — there is no DTD-fetch code path to disable), but a
   `<!DOCTYPE`/`<!ENTITY` declaration is refused outright before the text
   is even handed to the parser, and again if `sax` itself reports a
   doctype. Belt and suspenders, and it means "no external entities, no
   DTD fetch" is true by construction rather than by trusting a specific
   library's internals.

## Not this package's job

Deciding rewards (`@golfraven/rules` `scorePlay`), the actual `matchRoute`
call (the app/server wires `toMatcherInput`'s output into
`@golfraven/matching` with real candidate courses), and the server-side
`health_route` × `file_import` `max`-combination logic that
`correlationKey` feeds are all out of scope here.

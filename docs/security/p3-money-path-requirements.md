# P3 money path — requirements for the API / Edge Function layer

Source: the money-path security review of `packages/rules`, 2026-09-24.

`scorePlay` is a pure function, and it is only as trustworthy as its input. The package now fixes what a pure
function can fix: allow-list checks, a strict input parser, a course anchor, and caps. Everything below can only
be enforced where the input is built. Each item must be satisfied, and tested, before the P3 Edge Functions ship.
The DB-side items are tracked in the P3a queue.

## 1. Build every `Evidence` / `AppFix` on the server — never pass client JSON through

| Field | Must come from |
|---|---|
| `token.grade`, `hardwareSupportsAttestation` | Server verification of App Attest / Play Integrity, and the verified device model |
| `challenge` | The `checkin_challenge` row: single-use, `used_at` set atomically |
| `facilityId`, `verificationTier`, `geometryKind`, `insideBuffer`, `accuracyMeters` | Re-running the matcher (`packages/matching`) on the raw coordinates against the signed catalog |
| `capturedAt` | For live challenges, clamped to `[challenge.issued_at, issued_at + TTL]`. Otherwise a skew check against server `now`, with a `fraud_signal` above 24 h |
| `localDate` | Derived from the server-trusted `capturedAt` and the facility `tz` |
| `fixId` | The challenge id, or a hash of the attestation assertion. **Item 3 of the ninth gate: PINNED to unpadded base64url (RFC 4648 §5) — `[A-Za-z0-9_-]`, no `+`/`/`/`=`.** |

**Why base64url, not hex, for `fixId` (item 3, ninth gate).** `packages/rules` already uses hex
elsewhere (`inputDigest`, a SHA-256 digest) but `fixId` is not always a digest — the trust table above
allows it to be either a raw challenge-nonce id OR a hash of the attestation assertion, and the mobile
attestation ecosystems this system integrates with (App Attest, Play Integrity) already emit base64
tokens natively. Re-encoding that output as UNPADDED base64url — swap `+`/`/` for `-`/`_`, drop `=`
padding — is the standard "make an opaque server token URL- and JSON-safe" step, and it covers a raw
random nonce and a hash digest equally well; hex would be an awkward re-encoding of a base64 SDK
output for no benefit. **This is a hard requirement on whichever Edge Function issues/derives `fixId`:
never emit standard, padded base64 (`+`, `/`, or `=` will be rejected and the row quarantined — see
`packages/rules`' `FixIdSchema`), and never emit a raw hex string with unnecessary padding either —
base64url, unpadded, is the one accepted encoding.**

## 2. Each row type comes only from its own server path

| Row / field | Only from |
|---|---|
| `staff_presence` (`scanAt` = server time) | `/v1/partner/attest`, with an `attestation` row carrying a unique `token_jti` |
| `booking`, `paymentRef` | The P7 provider webhook |
| `arccos` / `garmin` (`vendorCourseMapped`, `sensorProvenance`) | The P8 connector |
| Receipt `status` | The review queue |
| `courseDisambiguatedBy` | The matcher or the portal |

`POST /v1/evidence` rejects every field in these two tables.

**A SQL `NULL` maps to an OMITTED JSON field, never to a literal `null` (item 2, ninth gate).**
`packages/rules`' parser treats an omitted `courseId` and a present `courseId: null` as two
COMPLETELY DIFFERENT things on purpose: omitted means "no course anchor at all — facility-level
evidence, always allowed" (the seventh gate's H3 residual rule); a present `null` is a MALFORMED
value (not a string), which the parser can only treat as ambiguous and quarantine. Any endpoint or
ORM layer that serializes a DB row to JSON MUST drop a `NULL` column from the payload entirely rather
than emitting it as `null` — this applies to `courseId` specifically (the anchor field this gate's
own finding concerns) and, as a general rule, to every OPTIONAL field `packages/rules`' schema
declares with `.optional()` (never `.nullable()`) for exactly this reason. A framework/ORM default
that emits `null` for every absent column (a common Postgres-client default) will silently turn every
facility-level evidence row into an unnecessary quarantine candidate — this is a real, addressable
integration bug class, not merely a theoretical one, and must be checked explicitly wherever
`app.evidence` rows are serialized for `scorePlay`'s input.

## 3. Per-play limits and fraud signals

- Cap evidence rows matching a play at 1,000 (`packages/rules`' `EVIDENCE_ROW_CAP`, raised from 200 in the
  seventh gate, item 9 — the cap now counts only rows the parser's loose facility/date/course filter kept, not
  every row a raw, unfiltered query happened to return). Keep a much larger raw-query DoS cap (10,000,
  `ABSOLUTE_ROW_CAP`) on the unfiltered result set itself. `scorePlay` scores one play per call — the caller
  does not need to pre-filter before calling it.
- Catch scorer exceptions per play, so one bad row cannot block a re-score batch. **This is now largely
  superseded by `packages/rules`' own quarantine (seventh gate, item/finding F3): a single malformed
  on-play row no longer fails `scorePlay` at all — it is excluded (`excludedRows`, `kind: "quarantined"`) and
  the play still scores on its remaining evidence.** The DB/Edge-Function layer must still catch exceptions
  defensively (a bug in the caller's own row assembly is not itself a `packages/rules` concern), but should not
  rely on a single bad row as the reason a re-score batch would stall.
- **Every ON-PLAY quarantine (item 2, seventh gate) must raise a `fraud_signal` or create a `review_item`.**
  `packages/rules` already forces `heldReview: true` (and populates `heldReviewReasons: ["quarantined"]`)
  whenever `money` is true and `excludedRows` contains a `kind: "quarantined"` entry — but `heldReview` alone
  only stops AUTO-issuance; it does not itself create a durable, actionable record. The DB-side consumer of a
  `scorePlay` result MUST, on every on-play quarantine (regardless of whether `money` ended up true — a
  malformed on-play row is worth recording even on a play that doesn't qualify for money, since the SAME
  malformed-row shape recurring across many plays is itself a fraud signal), raise a `fraud_signal` row or
  create a `review_item` naming the play, the quarantined row's original index, and its (already
  truncated/escaped — see the note below) reasons.
- Event-time velocity check: a play is disputed above 200 km/h between consecutive fixes.
- Clock skew over 24 h → `fraud_signal`. `packages/rules` now also rejects `capturedAt`/`scanAt` outside
  `[2020-01-01, 2100-01-01)` outright at the parser (seventh gate, item 6) — a plausibility floor/ceiling, not a
  substitute for this DB-side skew-against-`now()` check, which is tighter and time-varying.
- **A fix that grades `failed` MUST raise `fraud_signal(attestation_failed)` AT INTAKE** (item 2, seventh
  gate) — i.e. at `POST /v1/evidence` / whatever server path first receives the row, not merely observed
  later by a batch re-score. `packages/rules`' own scorer only ZEROES a `failed`-grade fix's contribution
  (§4.5 G3-08: "nothing can be earned on it") — it is a pure function with no DB access, so it cannot itself
  raise the signal; this has always been a DB-side obligation, restated here because the seventh gate's
  quarantine work made it easy to lose sight of which layer owns it.
- **`excludedRows` and `reasons` (both `packages/rules`' own types) are SERVER-SIDE DIAGNOSTIC DATA
  ONLY** (item 5, seventh gate). Every value they embed is already truncated (128 chars) and
  `JSON.stringify`-escaped before it reaches these arrays, but they still exist to help an operator or an
  internal dashboard understand why a row didn't score — never echo them into a player-facing UI, even
  escaped; a quarantine reason restates exactly which shape check rejected the input, which is more detail
  than an end user needs and more than an adversary probing the validator should get back.

## 4. Persisting and issuing

- Store the scorer's own `money`, `heldReview`, `hardSignal`, `policyVersion` and `inputDigest`.
- Never recompute money from the rounded `numeric(3,2)` score.
- Reserve offer budget atomically (row lock). Validate eligibility at save, approval and issuance with
  `validateOfferEligibility`. That validator rejects rules that are true on an empty play set. Treat a thrown
  validator error as invalid.

## 5. Receipts and fingerprints

Item 1 of the eighth gate: `packages/rules`' own fingerprint-dedup logic (`voidDuplicateFingerprints`,
`score-play.ts`) now trusts `voidReason` (`"duplicate" | "reviewer" | "fraud"`) to tell an honest intake-side
dedup apart from a real fraud/reviewer flag — a `"duplicate"`-void row is simply ignored (never poisons its
fingerprint group); a `"reviewer"`/`"fraud"`-void row (or a `status: "void"` row with NO `voidReason` at all —
defaults to `"reviewer"`, fails safe) poisons the whole group. This is a pure function; it can only act
correctly on what the DB/intake layer hands it. That layer MUST:

- **Never attach a dedup-voided duplicate to `play_evidence` in the first place.** `voidDuplicateFingerprints`
  ignoring a `"duplicate"`-void row is a *second* layer of defence, not a substitute for intake not creating
  the row as scoreable evidence at all — a receipt intake already recognizes as a re-upload of an existing one
  should either not be inserted into `app.evidence` as a distinct row, or should be inserted already `void` /
  `voidReason: 'duplicate'` and never linked into `play_evidence` for a DIFFERENT play than the original.
- **`voidReason` MUST be set at intake or at review — never left implicit.** A void row with no `voidReason`
  is treated as `"reviewer"` by `packages/rules` (the safe default), but that is a *fallback*, not a licence to
  skip setting it: an intake dedup step that voids a row without recording WHY loses the distinction this
  whole mechanism exists to preserve, and every such row will poison its group even when the intake step
  itself knew it was a harmless duplicate.
- **A fingerprint match against ANOTHER user's receipt goes to human review and is NEVER auto-voided.**
  This is the grief-vector this section exists to name: a shared or public receipt (a group green-fee slip, a
  clubhouse photo op) can be fingerprinted and uploaded by more than one legitimate player. If intake
  auto-voids "the second submission of a fingerprint," WHOEVER UPLOADS FIRST can silently void the
  RIGHTFUL owner's receipt just by getting there first with the same photo — the fingerprint match alone
  says two receipts look identical, not which uploader (if either) actually owns the underlying green fee. A
  cross-user fingerprint match must route to a human reviewer (who can ask for the original file, check
  payment records, etc.) — it is exactly the `"reviewer"` (or, if the review substantiates it, `"fraud"`)
  `voidReason` case, never `"duplicate"`, which is reserved for a SAME-USER re-upload intake can safely
  recognize on its own.

## Status

| Item | Where | Status |
|---|---|---|
| 1, 2, 3, 4 | P3 Edge Functions | Not started (P3 Edge Functions are not built yet) |
| `play_evidence UNIQUE(evidence_id)`, grade column, budget CHECKs, decision columns, receipt dedupe, global nonces | P3a migrations | Done — `supabase/migrations/0017_money_path_hardening.sql` |
| Allow-lists, parser, trust table, course anchor, caps, tautology rejection | `packages/rules` | In progress |

## Addendum (post-P3a gate): `evidence.attestation_grade` — "never graded" vs "unattestable"

`app.evidence.attestation_grade app.attestation_grade NOT NULL DEFAULT 'unattestable'`
(0017) reuses the existing three-value enum from 0003 (`'attested'`, `'unattestable'`,
`'failed'`). That enum has no fourth, "not yet graded" value, so every row defaults to
`'unattestable'` at INSERT time whether it was genuinely graded unattestable by server
verification (§1 above — the matcher/scorer ran and found no attestable signal) or has
simply never been graded at all (the P3 Edge Functions that would grade it don't exist
yet, per the Status table above).

**Decision (documented here per the gate's own instruction — "if adding it is
disruptive, document it" — rather than widening the enum now):** adding a fourth enum
value (`'pending'` or similar) is deferred to when the scoring Edge Function is actually
built, for two reasons:

1. `ALTER TYPE ... ADD VALUE` cannot run inside the same transaction as other DDL that
   uses the new value (a hard Postgres restriction, not a style choice), so it would
   force `0017_money_path_hardening.sql` to split into two migrations for one column —
   disproportionate for a value nothing yet reads or writes.
2. Nothing in this stage (P3a: schema + RLS only, no Edge Functions) actually
   DISTINGUISHES "never graded" from "graded unattestable" — the distinction only
   matters once a grading process exists to eventually revisit "never graded" rows and
   promote them, which is exactly the P3 Edge Function work the Status table already
   marks "Not started".

**Requirement carried forward, not dropped:** `attestation_grade` MUST be written from
server-side verification only (never client-supplied) — this is now stated on the
column itself (`COMMENT ON COLUMN`, 0017) so it survives independently of this doc. When
the P3 scoring Edge Function is built, add the enum's fourth value in its own migration,
backfill existing `'unattestable'` rows only where they are KNOWN never-graded (not
by assumption), and update `packages/rules`' consumers of this column accordingly.

## `[unverified]` — H2 approximation mode's vault grants (post-P3a re-gate)

`tools/db/test-migrations-no-migration-owner.sh`'s `H2_MODE=approximation` run grants
its freshly-created, NOSUPERUSER-but-database-owning role (`h2_approx_postgres`)
`GRANT ALL ON SCHEMA vault ... WITH GRANT OPTION`, `GRANT ALL ON vault.secrets ... WITH
GRANT OPTION`, and `GRANT ALL ON vault.decrypted_secrets ... WITH GRANT OPTION`, done as
the cluster bootstrap superuser (mirroring what `supabase/tests/shim.sql` already grants
`migration_owner`, both by fiat, in a local Postgres cluster this harness controls
completely).

**`[unverified]`:** this local grant shape is an assumption about what a real Supabase
project's own non-superuser `postgres` role actually holds on `vault.secrets`/`vault.
decrypted_secrets` — it has NOT been confirmed against a real Supabase project or
branch. If the real role's grants on Vault are narrower (e.g. SELECT only, no `WITH
GRANT OPTION`, or scoped differently), then `0018_pseudonym_vault.sql`'s own `GRANT
USAGE ON SCHEMA vault TO private_definer` / `GRANT SELECT (...) ON vault.
decrypted_secrets TO private_definer` step — which needs the connecting migration role
to itself hold grantable privilege on those objects — could fail on a real deploy even
though it passes in both harness modes locally. **Must be verified on a real Supabase
branch (or an equivalent hosted staging project) before this migration set is deployed
for real** — check what `GRANT`s the project's own `postgres` role actually holds on
`vault.secrets`/`vault.decrypted_secrets` (e.g. `\dp vault.secrets` connected as that
role, or `information_schema.role_table_grants`), and narrow both `shim.sql` and
`test-migrations-no-migration-owner.sh` to match reality once confirmed, rather than
leaving the WITH-GRANT-OPTION-by-fiat assumption as the only evidence this path works.

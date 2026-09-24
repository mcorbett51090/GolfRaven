# @golfraven/ciq

Placeholder. `apps/ciq` will hold the Garmin Connect IQ (Monkey C) "Trail
Check-in" component (build plan §3.1 row I, §7.3):

- **Recorder shape**, only if **P0-K4b** passes: samples fixes during a round
  while Garmin's native Golf activity is running, and sends them to the phone
  app over companion messaging.
- **Check-in shape**, if K4b fails: a one-tap glance/widget used before the
  round, never marketed as sync.

K4b's pass bar (build plan §10 P0, row K4): on ≥ 2 current Garmin golf watch
models, the component records ≥ 1 fix inside a course polygon while the
user runs Garmin's native Golf activity, and those fixes reach the phone app
with the phone app backgrounded, on both iOS and Android.

This is a Monkey C project built with Garmin's Connect IQ SDK, not a
TypeScript package — it will not join the workspace's `pnpm -r` type graph.
Nothing is built here in P0 beyond this placeholder and the K4b feasibility
spike tracked in `docs/p0/`.

## Sampling constraint (recorder shape only)

`@golfraven/matching` (`packages/matching`) — the package that turns a
recorded fix trace into a course match — caps how much a single gap
between fixes can count toward a match, and requires a minimum fraction
of the round to actually be observed. Both apply to **any** recorder, but
this component is the one most likely to sample sparsely (a watch,
batching fixes to the phone over companion messaging rather than
streaming continuously), so the constraint is restated here in concrete
terms rather than left implicit:

- **Sample at least every 5 minutes.** `MAX_GAP_SECONDS = 300` in
  `packages/matching` means any gap up to 5 minutes counts in full toward
  the match; nothing is lost by sampling this often or more.
- **Never less often than every 10 minutes, on the longest matchable
  round (6 h).** `MIN_OBSERVED_COVERAGE = 0.5` means at least half of the
  round's wall-clock span must be covered by fixes (after the 5-minute
  cap above), or the route can never be matched — only handed to
  typeahead for the player to pick the course manually. At exactly
  10-minute sampling over 4 hours, coverage lands **exactly** on that 0.5
  floor; one minute sparser (11 minutes) already falls short and the
  round fails to match, however clean the on-course ratio looked over the
  fixes that were actually recorded. A shorter round has less margin, not
  more.
- See `packages/matching/README.md` ("Round 4") for the full worked math,
  and `packages/matching/test/gate-fixes-3.test.ts` for a runnable
  example of a trace too sparse to match (8 fixes over 3 hours, ~25.7 min
  apart).

This is a constraint on the recorder's **sampling interval**, not on fix
count or battery budget directly — a recorder free to sample every few
minutes for a whole round has comfortable margin; one that only wakes up
occasionally (e.g. once per hole, ~13 minutes on an 18-hole round) does
not.

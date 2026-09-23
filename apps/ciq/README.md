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

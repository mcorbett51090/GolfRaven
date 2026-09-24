# Real device fixtures

This directory is where real Garmin Approach S62 golf-scorecard FIT files
go once the owner supplies them (build plan §7.3 lane 2: the exact
scorecard message layout is `[unverified]` — see `src/parse-fit-scorecard.ts`).

**Before a file lands here it must be trimmed:**

- Clipped to the course — GPS records outside the course polygon removed,
  not just cropped in time.
- Times shifted by a fixed random offset, so the file no longer dates a
  real round.
- No home-area fixes — drop any record near wherever the device usually
  starts/ends its day (a driveway, a house), not only the course.
- Strip `file_id.serial_number` (a persistent per-device identifier),
  `user_profile` (the owner's own profile data — name, weight, etc., if
  present), and `device_info` (further serial numbers/device identifiers)
  from the FIT file.
- For a GPX file specifically, strip any `<author>`/`<email>` element —
  GPX 1.1's `<metadata><author>` can carry a name and email address that
  has nothing to do with the round itself.

None of that trimming is automated here; do it before committing the
file. This directory holds no real, untrimmed device data today — see
`test/parse-fit.test.ts`'s skipped placeholder, which is the test to fill
in once a trimmed file exists.

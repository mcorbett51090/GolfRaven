#!/usr/bin/env bash
# tools/db/tap-verdict.sh — judge ONE pgTAP file's output (read from stdin) the way pg_prove does. Used by tools/db/test.sh's psql fallback (the path taken when pg_prove is not installed).
#
#   exit 0  the file is good: no `not ok` line, no ERROR line, a `1..N` plan, and exactly N `ok` / `not ok` lines
#   exit 1  it is not; the reason is printed on stdout
#
# Why not "grep for the failure text" (design 124):
#   * `echo "$OUTPUT" | grep -q …` under `set -o pipefail` lets an early match end the reader while the writer is still writing; the writer takes SIGPIPE and the pipeline reports 141, so a MATCH reads as no
#     match (design 119, 120). awk reads ALL of its input, so the writer never takes the signal.
#   * pgTAP's own `# Looks like you planned N tests but ran M` diagnostic is NOT a verdict: a file whose groups are each their own BEGIN … ROLLBACK (52_partner_auth_alarm_purge.sql,
#     67_partner_credential_list_reach.sql) rolls pgTAP's counter back, so finish() reports a count lower than the ok lines that were printed. pg_prove ignores that comment and compares the
#     ok lines with the plan; so does this.
set -euo pipefail

awk '
  /^not ok/ && bad == "" { bad = "a `not ok` line: " $0 }
  /ERROR/ && bad == "" { bad = "an ERROR line: " $0 }
  /^1\.\.[0-9]+$/ && planned == "" { planned = substr($0, 4) }
  /^(not )?ok [0-9]+/ { ran++ }
  END {
    if (bad != "") { print bad; exit 1 }
    if (planned == "") { print "no `1..N` plan line"; exit 1 }
    if (planned + 0 != ran + 0) { print "planned " planned " but printed " ran + 0 " ok / not ok line(s)"; exit 1 }
  }'

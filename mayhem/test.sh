#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# guacamole-server's own unit suites are CUnit programs printing TAP ("1..N", "ok N - ...",
# "not ok N - ..."). build.sh built them (make check TESTS=) in mayhem/build-test with the project's
# normal flags. Each suite's TAP lines are counted; a suite whose output has no plan line, or whose
# ok+not-ok count differs from its plan, counts as a failure — so a neutered binary fails loudly.
BT="$SRC/mayhem/build-test/src"
SUITES=(libguac/tests/test_libguac common/tests/test_common terminal/tests/test_terminal
        common-ssh/tests/test_common_ssh protocols/rdp/tests/test_rdp
        protocols/kubernetes/tests/test_kubernetes)
passed=0 failed=0
for s in "${SUITES[@]}"; do
  bin="$BT/$s"
  if [ ! -x "$bin" ]; then
    echo "MISSING test runner $bin (build.sh should have built it)" >&2; failed=$((failed + 1)); continue
  fi
  out="$(cd "$(dirname "$bin")" && "./$(basename "$bin")" 2>&1)"
  rc=$?
  plan="$(printf '%s\n' "$out" | sed -n 's/^1\.\.\([0-9][0-9]*\)$/\1/p' | head -1)"
  ok="$(printf '%s\n' "$out" | grep -c '^ok [0-9]')"
  nok="$(printf '%s\n' "$out" | grep -c '^not ok [0-9]')"
  passed=$((passed + ok)); failed=$((failed + nok))
  incomplete=0
  if [ -z "$plan" ] || [ $((ok + nok)) -ne "$plan" ]; then incomplete=1; fi
  if [ "$rc" -ne 0 ] && [ "$nok" -eq 0 ]; then incomplete=1; fi   # crashed/failed without a TAP failure
  if [ "$incomplete" -eq 1 ]; then
    echo "SUITE $s: plan='${plan}' ok=$ok not_ok=$nok rc=$rc — incomplete run" >&2
    failed=$((failed + 1))
  fi
  printf '%s\n' "$out" | grep '^not ok' >&2 || true
  echo "suite $s: $ok ok, $nok not ok (plan ${plan:-none})"
done

# Known-answer probe through the guaclog tool: interpreting a fixed recording of key events must
# reproduce the committed text exactly (key names, modifiers, Unicode keysyms, Enter/Backspace).
kat_dir="$(mktemp -d "${TMPDIR:-/tmp}/guaclog-kat.XXXXXX")"
cp "$SRC/mayhem/kat/keys.guac" "$kat_dir/keys.guac"
if "$SRC/mayhem/build-test/src/guaclog/guaclog" "$kat_dir/keys.guac" >/dev/null 2>&1 \
   && cmp -s "$kat_dir/keys.guac.txt" "$SRC/mayhem/kat/keys.expected.txt"; then
  passed=$((passed + 1)); echo "kat guaclog keys: ok"
else
  failed=$((failed + 1)); echo "kat guaclog keys: FAILED (output differs from mayhem/kat/keys.expected.txt)" >&2
fi
rm -rf "$kat_dir"

emit_ctrf "cunit-tap" "$passed" "$failed" 0

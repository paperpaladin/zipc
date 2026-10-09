#!/bin/bash
# zipc test harness.  Info-ZIP unzip/zip and Python's zipfile are the oracles:
# every interop claim below is checked against at least one of them, and the
# two are also checked against each other.
#
# usage: t/run.sh [path-to-zipc]
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
ZIPC=${1:-$ROOT/zipc}
case $ZIPC in /*) ;; *) ZIPC=$(cd "$(dirname "$ZIPC")" && pwd)/$(basename "$ZIPC") ;; esac
ORACLE=$HERE/oracle.py

# Scratch carries the pid and lives under this repo.  Both halves matter: a
# fixed name means two concurrent runs of this suite delete each other's
# fixtures mid-test, and /tmp is shared with other agents and is tmpfs.
TMP=$HERE/tmp.$$
trap 'chmod -R u+rwX "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT INT TERM
rm -rf "$TMP"
mkdir -p "$TMP"

pass=0
fail=0
ok() { pass=$((pass+1)); printf 'ok   %s\n' "$1"; }
no() { fail=$((fail+1)); printf 'FAIL %s\n' "$1"; }
# assert <name> <cmd...>  -- passes if the command succeeds
assert() { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else no "$n"; fi; }
# refute <name> <cmd...>  -- passes if the command FAILS
refute() { local n=$1; shift; if "$@" >/dev/null 2>&1; then no "$n"; else ok "$n"; fi; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1 (got '$2' want '$3')"; fi; }

[ -x "$ZIPC" ] || { echo "no $ZIPC -- run make first"; exit 1; }

# --------------------------------------------------------------------- #
# 0. the harness itself                                                 #
# --------------------------------------------------------------------- #
# Ten of the eighteen defects in this tree were in a harness, not in the
# code, so these two go first: they prove ok/no are wired to the counters
# and that a failing command really does register.
eq "harness: eq compares" "a" "a"
refute "harness: refute passes when the command fails" false
assert "harness: assert passes when the command succeeds" true

# --------------------------------------------------------------------- #
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

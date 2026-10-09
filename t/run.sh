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
# 1. finding the end-of-central-directory record                        #
# --------------------------------------------------------------------- #
# -v on a read mode prints the located EOCD, which is the only way to test
# the backwards scan on its own, before anything parses the directory.
mkdir -p "$TMP/s/sub"
echo hi >"$TMP/s/a.txt"
echo there >"$TMP/s/sub/b.txt"
(cd "$TMP" && zip -q -r plain.zip s)

nent() { "$ZIPC" -tf "$1" 2>/dev/null | wc -l; }

assert "zip wrote something unzip likes" unzip -t "$TMP/plain.zip"
eq "EOCD: entry count matches unzip" "$(nent "$TMP/plain.zip")" \
	"$(unzip -l "$TMP/plain.zip" | tail -1 | awk '{print $2}')"

# A comment pushes the EOCD away from the end of the file.
(cd "$TMP" && cp plain.zip commented.zip && \
	printf 'a comment with some length to it' | zip -q -z commented.zip)
eq "EOCD: found behind a comment" "$(nent "$TMP/commented.zip")" "$(nent "$TMP/plain.zip")"
assert "EOCD: unzip agrees the commented archive is fine" unzip -t "$TMP/commented.zip"

# The signature appearing inside the comment.  Two versions: one where the
# comment-length filter alone settles it, and one crafted so that only the
# "does this offset point at a central directory header" filter does.
python3 "$ORACLE" craft eocd-in-comment-mild "$TMP/decoy-mild.zip" >/dev/null
eq "EOCD: signature inside a comment, mild -- right member count" \
	"$(nent "$TMP/decoy-mild.zip")" 1
# Both oracles lose here, and it took building the archive to find out:
# Info-ZIP scans backwards for the signature and then simply believes the
# twenty-two bytes that follow, and zipfile does the same, so *any* EOCD
# signature anywhere in a comment defeats both of them.  zipc requires the
# comment length to account for the rest of the file and the directory offset
# to land on a central header, and so reads the archive its author meant.
# Asserted as a divergence rather than skipped, so that the day Info-ZIP
# fixes this, the suite says so instead of quietly agreeing.
refute "EOCD: unzip cannot read the mild decoy (known divergence)" \
	unzip -t "$TMP/decoy-mild.zip"
refute "EOCD: zipfile cannot read the mild decoy either (known divergence)" \
	python3 "$ORACLE" testzip "$TMP/decoy-mild.zip"

python3 "$ORACLE" craft eocd-in-comment "$TMP/decoy.zip" >/dev/null
eq "EOCD: decoy as the final 22 bytes -- right member count" \
	"$(nent "$TMP/decoy.zip")" 1
refute "EOCD: unzip cannot read the adversarial decoy (known divergence)" \
	unzip -t "$TMP/decoy.zip"
refute "EOCD: zipfile cannot read it either (known divergence)" \
	python3 "$ORACLE" testzip "$TMP/decoy.zip"

# Not an archive at all, and an archive too short to hold an EOCD.
head -c 100 /dev/urandom >"$TMP/noise.bin"
"$ZIPC" -tf "$TMP/noise.bin" >/dev/null 2>&1
eq "EOCD: random bytes exit 2" "$?" 2
: >"$TMP/zero.bin"
"$ZIPC" -tf "$TMP/zero.bin" >/dev/null 2>&1
eq "EOCD: empty file exits 2" "$?" 2
printf 'PK\005\006' >"$TMP/sigonly.bin"
"$ZIPC" -tf "$TMP/sigonly.bin" >/dev/null 2>&1
eq "EOCD: a bare signature exits 2" "$?" 2

# --------------------------------------------------------------------- #
# 2. the central directory, three implementations compared               #
# --------------------------------------------------------------------- #
# zipc -tvv, zipfile and zipinfo -v all print name/method/crc/csize/usize/
# local-header-offset.  Diffing all three against each other is the point:
# any two agreeing could be two readings of the same wrong idea.
zi_info() { zipinfo -v "$1" | python3 "$ORACLE" parse-zipinfo; }
zc_info() { "$ZIPC" -tvvf "$1" | LC_ALL=C sort; }
py_info() { python3 "$ORACLE" info "$1" | LC_ALL=C sort; }

cd_agree() {
	local tag=$1 z=$2
	zc_info "$z" >"$TMP/zc.txt" 2>"$TMP/zc.err"
	py_info "$z" >"$TMP/py.txt" 2>/dev/null
	zi_info "$z" >"$TMP/zi.txt" 2>/dev/null
	assert "$tag: central directory, zipc == zipfile" \
		diff -u "$TMP/py.txt" "$TMP/zc.txt"
	assert "$tag: central directory, zipc == zipinfo -v" \
		diff -u "$TMP/zi.txt" "$TMP/zc.txt"
}

for how in 0 1 9; do
	(cd "$TMP" && rm -f "cd$how.zip" && zip -q "-$how" -r "cd$how.zip" s)
	cd_agree "zip -$how" "$TMP/cd$how.zip"
done
(cd "$TMP" && rm -f cdX.zip && zip -q -X -r cdX.zip s)
cd_agree "zip -X" "$TMP/cdX.zip"

# -t with no -v is just names, and must equal zipfile's.
"$ZIPC" -tf "$TMP/cd9.zip" | LC_ALL=C sort >"$TMP/zc.names"
python3 "$ORACLE" names "$TMP/cd9.zip" | LC_ALL=C sort >"$TMP/py.names"
assert "names: zipc == zipfile" diff -u "$TMP/py.names" "$TMP/zc.names"
eq "names: member count" "$(wc -l <"$TMP/zc.names")" 4

# An entry whose signature is wrong: the directory is not optional structure,
# so this is exit 2 and not a skipped member.
python3 "$ORACLE" corrupt-cd-sig "$TMP/cd9.zip" "$TMP/cdsig.zip" >/dev/null
"$ZIPC" -tf "$TMP/cdsig.zip" >/dev/null 2>&1
eq "central dir: a wrong entry signature exits 2" "$?" 2

# --------------------------------------------------------------------- #
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

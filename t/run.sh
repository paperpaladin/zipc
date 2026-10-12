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
# 3. local file headers, checked against the central directory          #
# --------------------------------------------------------------------- #
# -T locates each member's data through its local header and checks that the
# header agrees with the directory.  It does not yet decompress anything.
for how in 0 9 X; do
	assert "zip -$how: every local header agrees" "$ZIPC" -Tf "$TMP/cd$how.zip"
done

# The disagreement cases.  Info-ZIP detects the size one too (it warns and
# exits 1), which is the agreement worth having: zipc is not inventing a
# stricter rule than the format's own tool applies.
python3 "$ORACLE" craft local-disagrees "$TMP/ld.zip" >/dev/null
"$ZIPC" -Tf "$TMP/ld.zip" >/dev/null 2>"$TMP/ld.err"
eq "local header: a size disagreement exits 1" "$?" 1
assert "local header: ... and says which numbers disagree" \
	grep -q 'local header says crc .* central directory says' "$TMP/ld.err"
assert "local header: ... and says it used the central directory" \
	grep -q 'using the central directory' "$TMP/ld.err"
refute "local header: unzip -t also rejects the size disagreement" \
	unzip -t "$TMP/ld.zip"

python3 "$ORACLE" craft local-name-differs "$TMP/ln.zip" >/dev/null
"$ZIPC" -Tf "$TMP/ln.zip" >/dev/null 2>"$TMP/ln.err"
eq "local header: a name disagreement exits 1" "$?" 1
assert "local header: ... and is reported as a refusal" \
	grep -q 'REFUSING.*names a different member' "$TMP/ln.err"

# A local header offset pointing outside the archive, and one pointing at
# the wrong signature: structural, so exit 2 rather than a skipped member.
python3 "$ORACLE" corrupt-local-off "$TMP/cd9.zip" "$TMP/loff.zip" >/dev/null
"$ZIPC" -Tf "$TMP/loff.zip" >/dev/null 2>&1
eq "local header: an offset outside the archive exits 2" "$?" 2
python3 "$ORACLE" corrupt-local-sig "$TMP/cd9.zip" "$TMP/lsig.zip" >/dev/null
"$ZIPC" -Tf "$TMP/lsig.zip" >/dev/null 2>&1
eq "local header: a wrong signature exits 2" "$?" 2

# --------------------------------------------------------------------- #
# 4. STORE: the bytes come out, and the CRC we compute is the CRC in    #
#    the directory -- which Info-ZIP wrote and we did not               #
# --------------------------------------------------------------------- #
# -Tv prints name, the CRC-32 zipc computed over the decompressed bytes, and
# the length.  Compared against zipinfo -v's declared CRC and size, so the
# number zipc computes is checked against a number Info-ZIP put there.
crc_agree() {
	local tag=$1 z=$2
	"$ZIPC" -Tvf "$z" | LC_ALL=C sort >"$TMP/crc.zc"
	# Directories, and only directories, are dropped: zipc does not
	# decompress them.  Filtering on "size is zero" instead would also
	# drop the empty-file member, which is exactly the case most likely
	# to be wrong.
	zi_info "$z" | awk -F'\t' '$1 !~ /\/$/ {
		printf "%s\t%08x\t%d\n", $1, $3, $5 }' | LC_ALL=C sort >"$TMP/crc.zi"
	assert "$tag: computed CRC and size == zipinfo's declared" \
		diff -u "$TMP/crc.zi" "$TMP/crc.zc"
}
crc_agree "zip -0" "$TMP/cd0.zip"

# Bytes, not just checksums: a stored member's data must be exactly the file.
# (The full tree round-trip is section 8; this is the one-member version, so
# that STORE is proven byte-exact before DEFLATE is added on top of it.)
(cd "$TMP" && rm -f one.zip && zip -q -0 one.zip s/a.txt)
mkdir -p "$TMP/onex"
assert "STORE: unzip extracts the one stored member" \
	unzip -q -o -d "$TMP/onex" "$TMP/one.zip"
assert "STORE: ... byte-identical" cmp "$TMP/s/a.txt" "$TMP/onex/s/a.txt"

# A stored member whose two sizes differ is refused rather than copied.
python3 "$ORACLE" craft store-size-mismatch "$TMP/ssm.zip" >/dev/null
"$ZIPC" -Tf "$TMP/ssm.zip" >/dev/null 2>"$TMP/ssm.err"
eq "STORE: differing compressed/uncompressed sizes exit 1" "$?" 1
assert "STORE: ... and say so" \
	grep -q 'different compressed and uncompressed sizes' "$TMP/ssm.err"

# An encrypted member is refused, not silently extracted as garbage.
python3 "$ORACLE" craft encrypted "$TMP/enc.zip" >/dev/null
"$ZIPC" -Tf "$TMP/enc.zip" >/dev/null 2>"$TMP/enc.err"
eq "encrypted member exits 1" "$?" 1
assert "encrypted member says it is unsupported" \
	grep -q 'encrypted' "$TMP/enc.err"

# A method we do not implement is refused by name, not guessed at.
python3 "$ORACLE" craft method99 "$TMP/m99.zip" >/dev/null
"$ZIPC" -Tf "$TMP/m99.zip" >/dev/null 2>"$TMP/m99.err"
eq "unknown compression method exits 1" "$?" 1
assert "unknown compression method says so" \
	grep -q 'unsupported compression method' "$TMP/m99.err"

# --------------------------------------------------------------------- #
# 5. DEFLATE, decoder vendored from ../inflate                          #
# --------------------------------------------------------------------- #
# The tree for this section has one member of each awkward kind: a file that
# compresses badly (urandom, so DEFLATE falls back to stored blocks), one
# that compresses extremely well, an empty file, and a nested path.
mkdir -p "$TMP/d/sub"
head -c 200000 /dev/urandom >"$TMP/d/random.bin"
python3 -c "import sys; open(sys.argv[1],'w').write('hello world, text\n'*9000)" \
	"$TMP/d/squishy.txt"
: >"$TMP/d/empty"
printf 'nested\n' >"$TMP/d/sub/deep.txt"
printf 'bin\000\001\377\000data' >"$TMP/d/binary.dat"

for how in 1 6 9; do
	(cd "$TMP" && rm -f "d$how.zip" && zip -q "-$how" -r "d$how.zip" d)
	crc_agree "zip -$how deflate" "$TMP/d$how.zip"
done

# Every level of zip, and zipfile's deflate too, must inflate to the right
# CRC.  The CRC comes out of the archive, so this is checked against a
# number Info-ZIP and zlib computed, not one zipc chose.
python3 "$ORACLE" write "$TMP/pyd.zip" "$TMP/d" deflate >/dev/null
crc_agree "zipfile deflate" "$TMP/pyd.zip"
python3 "$ORACLE" write "$TMP/pys.zip" "$TMP/d" store >/dev/null
crc_agree "zipfile store" "$TMP/pys.zip"

# A DEFLATE stream cut short.  Deterministic, unlike a byte flip -- the
# stream genuinely ends mid-block, so the decoder has to say so rather than
# read past the member into the next one or into the central directory.
python3 "$ORACLE" cut-deflate "$TMP/d9.zip" "$TMP/dcut.zip" >/dev/null
"$ZIPC" -Tf "$TMP/dcut.zip" >/dev/null 2>"$TMP/dcut.err"
eq "DEFLATE: a stream cut short exits 1, not 0" "$?" 1
assert "DEFLATE: ... and says it was truncated" grep -q truncated "$TMP/dcut.err"
refute "DEFLATE: unzip -t rejects it too" unzip -t "$TMP/dcut.zip"

# --------------------------------------------------------------------- #
# The modes that are not written yet have to refuse, not pretend.
#
# -x used to be accepted, read the archive, match no branch, and return 0 --
# extracting nothing while reporting success. A caller in a shell script
# cannot tell that from a complete extraction, and this suite did not look.
# -c used to slurp the archive it had been asked to create and fail with a
# diagnostic about the *input* being unreadable.
#
# Each unimplemented mode is checked for its own exit status (3, distinct from
# 1 "refused a member" and 2 "unparseable") and for naming itself, so neither
# can quietly become an exit 0 again.
for m in c x; do
	"$ZIPC" "-$m" -f "$TMP/d9.zip" a >/dev/null 2>"$TMP/ni.err"
	eq "-$m is not implemented and exits 3, not 0" "$?" 3
	assert "-$m says which flag is missing" grep -q -- "-$m is not implemented" "$TMP/ni.err"
done

# A flag the parser does not handle must be refused, and the usage text must
# not be advertising it. -C, -0, -D and -Z were all listed as if they worked.
for m in C 0 D Z; do
	"$ZIPC" "-$m" -tf "$TMP/d9.zip" >/dev/null 2>"$TMP/uf.err"
	eq "-$m is refused rather than ignored" "$?" 2
	refute "usage does not offer -$m as working" \
		sh -c "sed -n '1p' '$TMP/uf.err' | grep -q -- '-$m'"
done

# -t and -T are the two that do work, and must keep working.
"$ZIPC" -tf "$TMP/d9.zip" >/dev/null 2>&1
eq "-t still exits 0" "$?" 0
"$ZIPC" -Tf "$TMP/d9.zip" >/dev/null 2>&1
eq "-T still exits 0" "$?" 0

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

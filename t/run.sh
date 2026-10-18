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
# Member names, sorted, from each reader.  Comparing names and not counts
# matters: two readers that both fail print nothing, and nothing equals
# nothing.  The count form of the comment test below passed with find_end
# deleted, because the plain archive it was compared against went to zero
# at the same time.
zc_names() { "$ZIPC" -tf "$1" 2>/dev/null | LC_ALL=C sort; }
uz_names() { unzip -Z1 "$1" 2>/dev/null | LC_ALL=C sort; }

assert "zip wrote something unzip likes" unzip -t "$TMP/plain.zip"
eq "EOCD: entry count matches unzip" "$(nent "$TMP/plain.zip")" \
	"$(unzip -l "$TMP/plain.zip" | tail -1 | awk '{print $2}')"
eq "EOCD: member names match unzip" "$(zc_names "$TMP/plain.zip")" \
	"$(uz_names "$TMP/plain.zip")"

# A comment pushes the EOCD away from the end of the file.
(cd "$TMP" && cp plain.zip commented.zip && \
	printf 'a comment with some length to it' | zip -q -z commented.zip)
eq "EOCD: found behind a comment" "$(zc_names "$TMP/commented.zip")" \
	"$(uz_names "$TMP/plain.zip")"
assert "EOCD: unzip agrees the commented archive is fine" unzip -t "$TMP/commented.zip"

# The signature inside the comment, written by Info-ZIP's own zip -z, so the
# archive is one the format's own tool produces rather than one only a forge
# can make.  Where the signature sits decides whether unzip survives it:
# unzip takes the last occurrence that has 22 bytes of file after it, so a
# decoy nearer the end than that is skipped and the real record is found.
(cd "$TMP" && cp plain.zip near.zip && \
	printf 'decoy PK\005\006 tail' | zip -q -z near.zip)
assert "EOCD: zip -z wrote a signature-bearing comment unzip still reads" \
	unzip -t "$TMP/near.zip"
eq "EOCD: signature in the comment, near the end: names match unzip" \
	"$(zc_names "$TMP/near.zip")" "$(uz_names "$TMP/near.zip")"
eq "EOCD: ... and match the same archive without the comment" \
	"$(zc_names "$TMP/near.zip")" "$(uz_names "$TMP/plain.zip")"
# zipfile does not survive it.  _EndRecData takes the last occurrence of the
# signature with rfind(), finds 12 bytes of record where it wants 22, and
# gives up instead of scanning on, so it refuses an archive Info-ZIP wrote
# and Info-ZIP reads.
refute "EOCD: zipfile refuses it (known divergence)" \
	python3 "$ORACLE" testzip "$TMP/near.zip"

# Same writer, same comment, signature moved further from the end: now unzip
# itself latches onto the decoy.  Info-ZIP writes an archive Info-ZIP cannot
# read.  zipc requires the comment length to account for exactly the bytes
# after the record, which the decoy's does not, so it reads the archive its
# author meant.  Asserted as a divergence rather than skipped, so the day
# Info-ZIP fixes this the suite says so instead of quietly agreeing.
(cd "$TMP" && cp plain.zip far.zip && \
	printf 'decoy PK\005\006 and a tail long enough to keep going' | \
	zip -q -z far.zip)
refute "EOCD: unzip cannot read its own far decoy (known divergence)" \
	unzip -t "$TMP/far.zip"
refute "EOCD: zipfile cannot read it either (known divergence)" \
	python3 "$ORACLE" testzip "$TMP/far.zip"
# Compared against unzip's reading of the same archive without the comment,
# not against zipc's own: two readers that both fail print nothing, and the
# first version of this line passed with find_end deleted.
eq "EOCD: zipc reads the far decoy, names as unzip reads them uncommented" \
	"$(zc_names "$TMP/far.zip")" "$(uz_names "$TMP/plain.zip")"

# The decoy as the final 22 bytes of the file: its own comment-length field
# is 0, which is correct for where it sits, so the length filter passes it
# and only "does this offset point at a central directory header" rejects it.
python3 "$ORACLE" craft eocd-in-comment "$TMP/decoy.zip" >/dev/null
eq "EOCD: decoy as the final 22 bytes: right member" \
	"$(zc_names "$TMP/decoy.zip")" "real.txt"
refute "EOCD: unzip cannot read the adversarial decoy (known divergence)" \
	unzip -t "$TMP/decoy.zip"
refute "EOCD: zipfile cannot read it either (known divergence)" \
	python3 "$ORACLE" testzip "$TMP/decoy.zip"

# Same position, but with counts saturated the way Zip64 spells them, so the
# plausibility filter has nothing to judge and the comment length is the only
# thing left that is wrong.  Without this archive, deleting the length check
# passed all 74 of the other assertions.
python3 "$ORACLE" craft eocd-in-comment-saturated "$TMP/sat.zip" >/dev/null
eq "EOCD: a saturated decoy is rejected on its comment length" \
	"$(zc_names "$TMP/sat.zip")" "real.txt"
refute "EOCD: unzip cannot read the saturated decoy (known divergence)" \
	unzip -t "$TMP/sat.zip"

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
# 6. writing: -c -0, stored members                                     #
# --------------------------------------------------------------------- #
# The point of this section is that the archive is graded by programs that
# did not write it.  zipc reading its own output proves only that one
# program agrees with itself, so that check is last and is labelled as what
# it is; everything above it is unzip, zipinfo and zipfile.
#
# oracle.py's `tree` is the corpus: an empty file, an empty directory, a
# 200-character path, a file with spaces, a file of every byte value, a
# 300 KB file that compresses badly, a 1.6 MB one that compresses extremely
# well, a 5 MB one in between, and a name with a diaeresis in it.  A round
# trip over an empty archive, or one file of no bytes, would pass against
# almost any defect.
mkdir -p "$TMP/wt"
# Checked, not just run: cmd_tree had a wrong length assertion in it and
# died half way through building the tree, leaving the three largest files
# out.  Nothing noticed, because the exit status of the forge was thrown
# away and every assertion below still passed over the smaller corpus.
assert "write: the round-trip tree was built" \
	python3 "$ORACLE" tree "$TMP/wt/w"
eq "write: ... with all ten files in it" \
	"$(find "$TMP/wt/w" -type f | wc -l)" 10
(cd "$TMP/wt" && "$ZIPC" -c0 -f ../w.zip w) 2>"$TMP/w.err"
eq "write: -c0 exits 0" "$?" 0
eq "write: ... and says nothing on stderr" "$(cat "$TMP/w.err")" ""

assert "write: unzip -t accepts the archive" unzip -tqq "$TMP/w.zip"
eq "write: zipfile testzip finds no bad member" \
	"$(python3 "$ORACLE" testzip "$TMP/w.zip")" OK

# The central directory we wrote, read back by both oracles and by zipc, all
# three compared field for field.
cd_agree "write" "$TMP/w.zip"

# Content, not just structure.  Two independent extractors, each diffed
# against the tree that went in: this is the round trip.
mkdir -p "$TMP/ux"
assert "write: unzip extracts it" unzip -qq -o -d "$TMP/ux" "$TMP/w.zip"
assert "write: ... to a tree identical to the input" diff -r "$TMP/wt" "$TMP/ux"
python3 "$ORACLE" extract "$TMP/w.zip" "$TMP/px" >/dev/null
assert "write: zipfile extracts to an identical tree too" \
	diff -r "$TMP/wt" "$TMP/px"
assert "write: zipfile read() equals the file on disk, member by member" \
	python3 "$ORACLE" verify "$TMP/w.zip" "$TMP/wt"

# Every CRC and size we wrote, against the ones Info-ZIP computes for the
# same tree.  zip -0 stores too, so the member set and every content-derived
# number must match exactly; only the offsets and the extra fields differ.
# This is the check that the CRC in our directory is the file's CRC and not
# merely a number our own reader agrees with.
(cd "$TMP/wt" && rm -f ../iz.zip && zip -q -0 -X -r ../iz.zip w)
crcsize() { zi_info "$1" | awk -F'\t' '{printf "%s\t%s\t%s\n",$1,$3,$5}' |
	LC_ALL=C sort; }
crcsize "$TMP/w.zip" >"$TMP/w.crc"
crcsize "$TMP/iz.zip" >"$TMP/iz.crc"
assert "write: every name, CRC and size matches Info-ZIP's own zip -0" \
	diff -u "$TMP/iz.crc" "$TMP/w.crc"

# Member order.  PLAN.md says directories are recursed in sorted order, and
# the archive has to say so too: readdir order is the filesystem's business
# and an archive of the same tree that comes out in a different order on
# another machine cannot be compared with anything.  Info-ZIP is no oracle
# for this -- zip -r writes files before subdirectories, in neither sorted
# nor readdir order -- so this is our contract, read back by zipfile.
python3 "$ORACLE" names "$TMP/w.zip" >"$TMP/w.order"
assert "write: members are in sorted order, not readdir order" \
	diff -u <(LC_ALL=C sort "$TMP/w.order") "$TMP/w.order"

# The empty file has to survive: it is the member a writer most easily
# drops, and a suite that only counts members would not see it.
eq "write: the empty member is present and zero length" \
	"$("$ZIPC" -tvvf "$TMP/w.zip" | awk -F'\t' '$1=="w/empty"{print $4" "$5}')" \
	"0 0"
eq "write: the empty directory is present, with a trailing slash" \
	"$(unzip -Z1 "$TMP/w.zip" | grep -c '^w/emptydir/$')" 1

# The non-ASCII name.  Without general-purpose bit 11 zipfile decodes the
# name as cp437 and extracts a file called something else, so the diff above
# would fail -- but only on that one member, which is why the flag is also
# asserted directly.
eq "write: bit 11 is set on the UTF-8 name" \
	"$(python3 "$ORACLE" flags "$TMP/w.zip" | awk -F'\t' '/n..n-ascii/{print $2}')" \
	"0x0800"
eq "write: bit 11 is not set on the ASCII names" \
	"$(python3 "$ORACLE" flags "$TMP/w.zip" | awk -F'\t' '$2!="0x0000"' | wc -l)" 1
eq "write: unzip lists the non-ASCII name too" \
	"$(unzip -Z1 "$TMP/w.zip" | LC_ALL=C grep -c 'n..n-ascii.txt')" 1

# A name that is NOT valid UTF-8.  The filesystem will hold one, and the
# format says a name is bytes, so zipc stores the bytes and leaves bit 11
# clear.  unzip writes those bytes back out.  zipfile cannot: it decodes an
# unflagged name as cp437, so Python's idea of the name differs from the
# bytes in the file.  Asserted as a divergence rather than avoided.
mkdir -p "$TMP/wl"
printf 'latin-1, not utf-8\n' >"$TMP/wl/$(printf 'l\344tin1.txt')"
(cd "$TMP" && "$ZIPC" -c0 -f l.zip wl) 2>/dev/null
eq "latin1: zipc writes the name as bytes" \
	"$(python3 "$ORACLE" rawnames "$TMP/l.zip" | grep -cF 'l\xe4tin1.txt')" 1
eq "latin1: ... with bit 11 clear" \
	"$(python3 "$ORACLE" flags "$TMP/l.zip" | awk -F'\t' '$2!="0x0000"' | wc -l)" 0
assert "latin1: unzip -t accepts it" unzip -tqq "$TMP/l.zip"
# zipfile opening it at all is the assertion that bit 11 was not set on a
# name that is not UTF-8: with the flag on, zipfile raises decoding the
# central directory and every check below it goes quietly vacuous.
eq "latin1: zipfile can still open the archive" \
	"$(python3 "$ORACLE" names "$TMP/l.zip" | wc -l)" 2
mkdir -p "$TMP/lx"
unzip -qq -o -d "$TMP/lx" "$TMP/l.zip"
assert "latin1: unzip extracts the name byte for byte" diff -r "$TMP/wl" "$TMP/lx/wl"
python3 "$ORACLE" extract "$TMP/l.zip" "$TMP/lp" >/dev/null
refute "latin1: zipfile decodes it as cp437 instead, so its tree differs" \
	diff -r "$TMP/wl" "$TMP/lp/wl"

# DOS date and time.  Two fields, five bit-packed numbers, and a range that
# starts in 1980, so the clamp is a branch that a tree of files created
# today never reaches.
touch -d '2001-02-03 04:05:06' "$TMP/wt/w/a/hello.txt"
touch -d '@0' "$TMP/wt/w/empty"		# 1970, before the epoch of the field
(cd "$TMP/wt" && "$ZIPC" -c0 -f ../wd.zip w)
eq "write: the mtime is written as a DOS date and time" \
	"$("$ZIPC" -tvf "$TMP/wd.zip" | awk '$NF=="w/a/hello.txt"{print $6" "$7}')" \
	"2001-02-03 04:05:06"
eq "write: a pre-1980 mtime is clamped to 1980-01-01, not wrapped" \
	"$("$ZIPC" -tvf "$TMP/wd.zip" | awk '$NF=="w/empty"{print $6" "$7}')" \
	"1980-01-01 00:00:00"
eq "write: ... and unzip reads the same clamped date" \
	"$(unzip -l "$TMP/wd.zip" | awk '$NF=="w/empty"{print $2}')" "1980-01-01"

# Two runs over the same tree have to produce the same bytes, or nothing
# downstream can be compared against anything.  readdir order is the
# filesystem's business, which is why add_path sorts.
(cd "$TMP/wt" && "$ZIPC" -c0 -f ../w2.zip w)
assert "write: the same tree twice gives byte-identical archives" \
	cmp "$TMP/wd.zip" "$TMP/w2.zip"
# ... and the archive on stdout is the same archive.
(cd "$TMP/wt" && "$ZIPC" -c0 w >../w3.zip)
assert "write: -f FILE and stdout agree byte for byte" \
	cmp "$TMP/wd.zip" "$TMP/w3.zip"

# What -c refuses.  Invariant 2 in PLAN.md is about extraction, but an
# archive full of names that climb out of the destination is one this tool
# is not going to produce either.
ln -sf /etc/hostname "$TMP/wt/w/link"
for case in "abs:/etc/hostname:an absolute path" \
	    "dotdot:../wt:a \"..\" component" \
	    "link:w/link:a symbolic link"; do
	tag=${case%%:*}; rest=${case#*:}; arg=${rest%%:*}; want=${rest#*:}
	(cd "$TMP/wt" && "$ZIPC" -c0 -f "../ref.$tag.zip" "$arg") 2>"$TMP/ref.err"
	eq "write: $tag is refused, exit 1" "$?" 1
	assert "write: ... and says why: $want" \
		grep -qF "REFUSING unsafe member" "$TMP/ref.err"
	assert "write: ... naming the reason" grep -qF "$want" "$TMP/ref.err"
done
rm -f "$TMP/wt/w/link"
# A refused member must not be in the archive either: the refusal is not
# just a message printed beside the file being added anyway.
eq "write: the refused symlink is not in the archive" \
	"$(python3 "$ORACLE" names "$TMP/ref.link.zip" | wc -l)" 0

(cd "$TMP/wt" && "$ZIPC" -c0 -f ../missing.zip w/nosuchfile) 2>"$TMP/ms.err"
eq "write: an unreadable path exits 1" "$?" 1
assert "write: ... and says it was skipped" grep -q skipped "$TMP/ms.err"

# zipc reading its own output.  Last, and worth little on its own: it is
# here so that a change that breaks both halves in the same direction still
# has to get past the eleven oracle checks above.
assert "write: zipc -T accepts its own archive (self-agreement only)" \
	"$ZIPC" -Tf "$TMP/w.zip"

# --------------------------------------------------------------------- #
# The modes that are not written yet have to refuse, not pretend.
#
# -x used to be accepted, read the archive, match no branch, and return 0 --
# extracting nothing while reporting success. A caller in a shell script
# cannot tell that from a complete extraction, and this suite did not look.
#
# -c now works, but only with -0: the contract says it deflates and falls
# back to stored per member, and the deflater is the next item. Writing
# stored data under a flag that promises deflate would hand the caller an
# archive several times the size they asked for and call it success, so -c
# without -0 is exit 3 as well.
"$ZIPC" -x -f "$TMP/d9.zip" a >/dev/null 2>"$TMP/ni.err"
eq "-x is not implemented and exits 3, not 0" "$?" 3
assert "-x says which flag is missing" grep -q -- "-x is not implemented" "$TMP/ni.err"
(cd "$TMP/wt" && "$ZIPC" -c -f ../nodefl.zip w) >/dev/null 2>"$TMP/nd.err"
eq "-c without -0 exits 3 rather than storing silently" "$?" 3
assert "-c without -0 says the deflater is missing" \
	grep -q "deflating is not implemented" "$TMP/nd.err"
refute "-c without -0 writes no archive at all" test -f "$TMP/nodefl.zip"
"$ZIPC" -c0 -f "$TMP/noargs.zip" >/dev/null 2>"$TMP/na.err"
eq "-c with no paths exits 2" "$?" 2
"$ZIPC" -0 -tf "$TMP/d9.zip" >/dev/null 2>"$TMP/z0.err"
eq "-0 on a read mode is an error, not a no-op" "$?" 2

# A flag the parser does not handle must be refused, and the usage text must
# not be advertising it. -C, -D and -Z were all listed as if they worked.
for m in C D Z; do
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

# zipc

A ZIP archive reader, and a writer that can only store, in one C11 file.
No libraries, no shelling out.

```
zipc -c0 [-f ARCHIVE] PATH...   write an archive of PATH..., stored
zipc -t|-T [-v] [-f ARCHIVE]
  -c  create; directories are recursed in sorted order
  -0  store, do not deflate; -c requires it until the deflater exists
  -t  list the central directory; -tv long-form
  -T  test: decompress every member and check its CRC-32, write nothing
  -f  archive file; '-' or omitted means stdin for -t/-T, stdout for -c
```

Exit status: 0 success, 1 a member was refused or skipped, 2 the archive is
not parseable or the command line is wrong, 3 the mode asked for is not
implemented.

## What does not work

- **Deflating.** `-c` without `-0` exits 3 and says so. The contract is
  that `-c` deflates and falls back to stored per member; only the stored
  half exists, and writing a 5 MB archive where the caller asked for a 1 MB
  one is a wrong answer, not a slow one.
- **Extracting.** `-x` and `-C DIR` exit 3. `-T` decompresses every member
  in memory and checks its CRC, so reading is tested; nothing is written to
  disk yet. `-x` used to read the archive, extract nothing, and exit 0.
- **Data descriptors on write** (`-D`) and **Zip64 on write** (`-Z`) exit 2.
  Both are read unconditionally. Writing anything that would need Zip64 --
  a member or an archive over 4 GB, or more than 65534 members -- exits 3
  before a byte is written, rather than truncating a size field and
  producing an archive that decodes to the wrong length.
- **Appending, updating, deleting, member selection, junking paths.** None
  of it. An archive is written once from a list of paths.
- **Member order is ours, not an oracle's.** Directories are recursed in
  sorted order so that two runs over the same tree give byte-identical
  archives. Info-ZIP cannot confirm that choice: `zip -r` writes files
  before subdirectories, in neither sorted nor readdir order.
- **Nothing we write is deflated**, so the stored path is the only one the
  round trip exercises. The 300 KB of urandom and the 1.6 MB of repeating
  text in the corpus are there for the deflater that is next.

## The oracle

Nothing here is graded against zipc's own reader. An archive zipc writes
that only zipc can read proves one program agrees with itself.

Reading, over archives written by Info-ZIP's `zip` at every compression
level and by Python's `zipfile`:

- `unzip -t`: against `zipc -T`, member by member, CRC by CRC.
- `zipinfo -v`: against `zipc -tv`, and that is why the long form prints
  method, sizes, ratio, CRC-32, DOS date/time and local-header offset in a
  diffable layout.
- Python's `zipfile`: a second independent implementation, in case
  `zipc` and Info-ZIP were wrong in the same direction.

Writing, over `t/oracle.py`'s round-trip tree -- a 5 MB file, a 1.6 MB file
that compresses to almost nothing, 300 KB of urandom that does not compress
at all, a file holding every byte value, an empty file, an empty directory,
a 200-character path, a name with a space and a name with a diaeresis:

- `unzip -t` accepts the archive, and `unzip` extracts it to a tree
  `diff -r` says is identical to the one that went in.
- `zipfile.testzip()` returns None, `extractall()` gives an identical tree
  as well, and `read()` is compared against the file on disk member by
  member.
- Every name, CRC-32 and uncompressed size in our central directory is
  diffed against the one Info-ZIP's own `zip -0 -X -r` computes for the
  same tree. The CRC in our directory is therefore checked against a
  number Info-ZIP computed, not one our own reader agrees with.

`make test`: **120 passed, 0 failed.** `make test-asan` rebuilds the same
suite under ASan and UBSan and must also be green.

13 mutations were planted in the write side and all 13 turned the suite
red: a zeroed CRC, a directory member without its trailing slash, an EOCD
count one short, bit 11 never set and always set, a local-header offset
off by one, the pre-1980 clamp removed, a short name length, the sort
removed, empty members dropped, a central-directory size that disagrees
with the local header, the unsafe-name check removed, and the symlink
refusal removed. The sort was the one that needed a new assertion written
for it: readdir order is stable within a run, so the "same tree twice gives
identical bytes" check could not see it.

UBSan found `qsort(NULL, 0, ...)` on the empty directory, which the -O2
build sorts without complaint. ASan is still able to see a read past the
end of the archive: moving the backwards EOCD scan 21 bytes past where it
belongs turns 52 assertions red with a heap-buffer-overflow, which is only
true because `slurp()` reallocs the buffer down to the archive length (see
below). Moving it 3 bytes survives, and is equivalent: the record is 22
bytes long, so a scan starting that far in still reads only inside the
file.

## Where the oracles are wrong

An archive comment holding the four bytes `PK\x05\x06` is the one place the
three readers disagree, and `zip -z` writes it, so this is not a forgery.

Info-ZIP's `unzip` takes the last occurrence of the signature that has 22
bytes of file after it and believes the record there, without checking that
its comment-length field accounts for the rest of the file. Put the decoy
near the end of the comment and unzip skips it and reads the archive
correctly, which zipc matches member for member. Move it further from the
end and `unzip -t` exits 3 on an archive Info-ZIP's own `zip` produced.

Python's `zipfile` fails earlier. `_EndRecData` calls `rfind`, gets one
candidate, finds fewer than 22 bytes of record there and returns None rather
than continuing the scan, so it refuses even the near-end archive that unzip
reads.

zipc requires the comment length to account for exactly the bytes that
follow the record, and the directory offset to land on a central directory
header. The suite asserts both divergences rather than skipping them, so if
either tool is fixed the suite says so instead of quietly agreeing. An
attacker who controls the whole comment can still build a decoy that passes
both filters and carries a second complete central directory; the file then
has two readings, and zipc takes the last one in the file, which is
Info-ZIP's choice.

The DEFLATE decoder is the one from `inflate`, a sibling in this collection,
vendored, not linked.

## What it writes

- local file headers, member data, the central directory and the EOCD
- method 0 (STORE) only, with the CRC-32 and both sizes in every header
- the mtime as a DOS date and time, clamped at both ends: a pre-1980 mtime
  is written as 1980-01-01 rather than wrapped into the 2060s
- general-purpose bit 11 on a member name that is valid UTF-8 and not
  ASCII. This is not optional on the write side even though PLAN.md lists
  Unicode path flags as a non-goal: without it `zipfile` decodes the name
  as cp437 and extracts a file called something else, so the round trip
  produces a different tree.
- an external attributes field holding the st_mode, with "made by Unix 3.0"
  so that unzip believes it

An absolute path, a path with a `..` component, a symbolic link and
anything that is not a regular file or directory are refused with a
`REFUSING` line and exit 1, and do not appear in the archive. Invariant 2
in `PLAN.md` is about extraction, but an archive full of names that climb
out of the destination is not one this tool is going to produce either.
`zip` strips the leading slash and warns; that leaves the caller with an
archive whose contents are not what they asked for.

## Where the oracles disagree about what we wrote

A member name that is not valid UTF-8 -- a Latin-1 filename, which the
filesystem will happily hold -- is stored as the bytes it is, with bit 11
clear, because the format says a name is bytes. `unzip` writes those bytes
back out and `diff -r` is clean. `zipfile` cannot: an unflagged name is
decoded as cp437, so Python's idea of the name differs from what is in the
file, and it extracts to a different filename. The suite asserts that
divergence in both directions rather than avoiding the case.

Info-ZIP's `unzip -t` does not compare the central directory's compressed
size against the local file header's. An archive whose directory says
`csize+1` while the data and the local header are correct is accepted by
`unzip -t` and by `zipfile`, and refused by `zipc -T`. That is invariant 1:
zipc extracts using the directory, so a directory that disagrees with the
member is a refusal and not a warning.

## What it refuses, deliberately

Each of these is a refusal, not a best effort, because a wrong answer
about an archive is worse than no answer:

- Encryption. Neither the traditional PKWARE cipher nor AES. An encrypted
  member (general-purpose bit 0) is refused, not extracted as garbage.
- Methods other than 0 and 8. No bzip2, LZMA, XZ, Zstandard, Deflate64,
  Shrink/Reduce/Implode.
- Multi-disk and split archives. A nonzero disk number is an error.
- Symlink members. Refused outright, which removes a whole class of
  extraction escape instead of trying to analyse it.

The whole archive is read into memory. That format puts its index at the end,
so streaming would be a pretence; `PLAN.md` says so instead of implying
otherwise.

## Still to come

The deflater, extraction to disk, data descriptors and Zip64 on the write
side, and two sweeps: a malicious-archive corpus, and a truncation sweep
that cuts a real archive at every structural boundary and then at every
byte offset of a small one, requiring exit 2 every time with no signal and
no hang. `PLAN.md` tracks these as numbered items.

GPL-3.0-or-later.

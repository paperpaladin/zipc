# zipc

## Contract

`zipc` is a ZIP archive reader and writer: one C11 file, no libraries, no
shelling out.

As of the last commit the write side does not exist. This section
describes the finished tool, the thing a plan is for; "Status, as of the
last commit" below says what the binary actually does, and the binary itself
refuses the unimplemented modes instead of accepting them silently. The
pointer is here because this was the first thing a reader saw and it read as
a feature list.

```
zipc -c|-t|-T|-x [-v] [-0] [-D] [-Z] [-f ARCHIVE] [-C DIR] [PATH...]
```

* `-c` writes an archive of `PATH...` (directories recursed, sorted).
* `-t` lists it from the central directory; `-tv` lists it long-form with
  method, sizes, ratio, CRC-32, DOS date/time and local-header offset, so the
  output can be diffed against `zipinfo -v`.
* `-T` tests it: every member is decompressed and its CRC-32 checked, nothing
  is written. This is `unzip -t`.
* `-x` extracts it.
* `-f FILE` names the archive; `-` or omitted means stdin/stdout.
* `-C DIR` is the extraction destination.
* `-0` stores instead of deflating. Without it, members are deflated and each
  one individually falls back to STORE when deflating made it bigger.
* `-D` writes data descriptors (general-purpose flag bit 3), not sizes
  in the local header. Read support is unconditional.
* `-Z` forces Zip64 on every member and on the end-of-central-directory, so
  the Zip64 path is reachable without a 4 GB archive.

In scope, on both sides:

* local file headers, the central directory, the end-of-central-directory
  record, and the Zip64 EOCD record plus its locator
* methods 0 (STORE) and 8 (DEFLATE)
* CRC-32 verification on every member read
* DOS date/time, including the pre-1980 clamp
* the Zip64 extra field (0x0001) for uncompressed size, compressed size and
  local-header offset
* data descriptors, with and without the 0x08074b50 signature, in both the
  4-byte and 8-byte size forms
* an archive comment, including one that contains the EOCD signature

Exit status: 0 success, 1 something was skipped or refused, 2 the archive is
not parseable.

## Status, as of the last commit

The read side works and the write side does not exist. `-t` lists the central
directory and `-T` decompresses every member and checks its CRC-32, both
compared against `unzip`, `zipinfo -v` and Python's `zipfile` over archives
written by `zip` at every compression level. `-c`, `-x`, `-C`, `-0`, `-D` and
`-Z` are not implemented, and the binary now refuses them, exit 3 for the
two modes, exit 2 for the four flags, instead of accepting them silently.
`-x` in particular used to read the archive and return 0 having extracted
nothing.

The sections below describe the finished tool, the thing a plan is for.
Of the oracles, the `unzip`/`zipinfo` and `zipfile` read comparisons are
wired up. Nothing writes an archive yet, so neither direction of the
write-side differential exists, and the malicious-archive and truncation
sweeps are item 17.

## Hard invariant

1. The central directory is authoritative. Every size, CRC and method
used to extract a member comes from the central directory, never from the
local file header. The local header is read, and checked against the central
directory, only so that a disagreement can be *reported*. An extractor that
believes the local header can be made to write a different file than the one
its own listing shows.

2. No member can ever be written outside the destination. Not by an
absolute path, not by a `..` component, not by a backslash that a
Windows-aware extractor would treat as a separator, not by a drive letter,
not by a symlink member whose target climbs out, and not through a symlink
sitting in the destination already. The response is refusal with a nonzero
exit, never silent sanitisation.

3. A hostile size cannot exhaust memory or disk. The declared
uncompressed size is checked against a per-member and a whole-archive cap
*before* anything is decompressed, the expansion ratio is capped, and the
decompressor is additionally handed a hard output limit so that a header
which lies about its size stops the inflate, not the machine.

## Oracle

Ranked, strongest first. None of the three is a build dependency; all three
are only ever invoked by `t/run.sh`.

1. Info-ZIP `unzip` 6.00, bidirectionally. `unzip -t` must validate every
   archive `zipc -c` writes, at every combination of `-0`/deflate, `-D` and
   `-Z`, and `unzip` must extract it to a tree `diff -r` says is identical to
   the input. In the other direction `zipc -x` must read what `zip 3.0`
   writes at `-0`, `-9`, `-X` and `-r` over a nested tree. `zipinfo -v` gives
   the per-member method, CRC, sizes and local-header offset, which are
   diffed against `zipc -tv`'s. `unzip`/`zip` define the format, so a
   disagreement means zipc is wrong.
2. Python's `zipfile`, a third independent implementation. It must read
   ours: `testzip()` returning `None` on every archive we write, and
   `read()` byte-identical, and we must read what it writes, including the
   `force_zip64=True` and non-seekable (data-descriptor) paths that `zip`
   itself will not produce.
3. The malicious-archive sweep. `zipfile` lets a member name be written
   verbatim, which is how the hostile archives are built: `../escape`,
   `/abs/escape`, `..\..\escape`, `a/../../escape`, `C:\escape`, a name with
   an embedded NUL, and a symlink member whose target is `/etc/passwd`. Each
   asserts a nonzero exit, a `REFUSING` line, that nothing appeared beside
   the destination, and that a canary file outside the destination was
   neither modified nor read (checked by mtime *and* atime).
4. The truncation sweep. A real archive cut at every structural boundary,
   and then at every single byte offset of a small one, fed to `-t`,
   `-T` and `-x`. Every run must exit 2 and no run may die on a signal or
   fail to terminate.
5. ASan + UBSan over the whole harness (`make test-asan`). We parse
   attacker-controlled offsets and lengths out of a byte buffer, the
   exact shape of problem that produces archiver CVEs. This one was listed
   here for several commits while being both red (LeakSanitizer, on every
   successful run) and blind (the archive buffer was rounded up to a power
   of two, so a read past the end of the file was inside the allocation).
   Both are fixed; see the EOCD item below for how that came out.

## Non-goals

* Encryption. Neither the traditional PKWARE cipher nor AES; an encrypted
  member (general-purpose bit 0) is refused, not silently extracted as
  garbage.
* Methods other than 0 and 8. No bzip2 (12), LZMA (14), XZ (95), Zstandard
  (93), Deflate64 (9), Shrink/Reduce/Implode (1-6).
* Multi-disk and split archives. A nonzero disk number is an error.
* Creating symlinks on extract. A symlink member is refused outright, which
  removes a whole class of escape instead of analysing it.
* Appending to or updating an existing archive, deleting members, member
  selection on extract, `--exclude`, `-j`/junk-paths, `--strip-components`.
* Streaming. The whole archive is read into memory, because the format puts
  its index at the end and the design does not pretend otherwise.
* Unicode path flags (bit 11) and the `up`/`ux` extra fields. Names are
  stored and read as bytes.
* Preserving ownership, or any permission bits beyond the 0777 set.
* Being fast. One hash-chain match finder, one Huffman pass per 32 KB block.

## Commit sequence

- [x] skeleton: buffer, CRC-32, usage, Makefile, an empty harness
      why: the harness has to exist and be seen to print "0 failed" before
      anything claims to pass it.
- [x] end-of-central-directory location by backwards scan
      files: zipc.c (find_end, cd_plausible, slurp), t/run.sh section 1,
      t/oracle.py (craft_eocd_in_comment, craft_eocd_in_comment_saturated),
      Makefile (SANOPT)
      proves: eight assertions, all of them watched failing against a
      find_end that cannot find anything. Info-ZIP `zip -z` writes the
      interesting archive itself, so the hard case is not a forgery: a
      comment holding 0x06054b50 within 22 bytes of the end is read by
      `unzip` and by zipc with the same member list, name for name.
      found: Info-ZIP writes an archive Info-ZIP cannot read. Move the same
      decoy further from the end and `unzip -t` exits 3 on its own output,
      because its scan takes the last signature with 22 bytes of file after
      it and never checks the comment length. Python's zipfile is worse: its
      rfind() finds one occurrence, sees too few bytes, and gives up rather
      than scanning on, so it refuses the near-end archive unzip reads.
      Both are asserted as divergences, not skipped.
      found: the old comment test compared two member counts, and both went
      to zero together when find_end was deleted, so it passed against a
      reader that found nothing. Every assertion in the section now compares
      names, and against unzip's names where it can.
      found: the comment-length filter was dead weight as far as the suite
      was concerned. Deleting it passed all 74 other assertions, because
      cd_plausible caught every decoy on its own. The saturated decoy
      (0xFFFF counts, which cd_plausible must pass through to Zip64) is the
      archive that makes it load-bearing.
      found: `make test-asan` had been red since the first commit, 30 of 69
      assertions failing on LeakSanitizer alone, so nothing had ever read
      its output. zipc never frees on purpose; detect_leaks=0.
      found: and once it ran, it could not see the bug it exists for. slurp
      rounded its buffer up to the next power of two, so a read past the end
      of the archive landed in memory the allocator owned. An off-by-three
      in the backwards scan reported 76 passed under ASan. slurp now
      reallocs down to the archive length and the same defect is a
      heap-buffer-overflow.
- [x] central directory parse and `-t` listing
      done in d62fb80; `-t`, `-tv` and `-tvv` diffed against zipinfo -v and
      zipfile. These five boxes were left unticked by the commits that
      closed them, which is why this item was picked up a second time.
- [x] local file headers, and the disagreement check against the central dir
      done in 472c998
- [x] stored extraction
      done in 9bcac44
- [x] deflate extraction, decoder vendored from ../inflate
      done in 352747c
- [x] CRC-32 verification and `-T`
      done in 352747c; crc_agree compares the CRC zipc computes against the
      one zipinfo -v reports, which Info-ZIP wrote.
- [ ] the path resolver and its refusals
- [ ] the zip bomb caps
- [ ] `-c` writing stored members
- [ ] `-c` deflating, with per-member fallback to stored
- [ ] data descriptors, read and `-D` write
- [ ] Zip64: extra field, EOCD record, locator, and `-Z`
- [ ] oracle: unzip and zipinfo, both directions
- [ ] oracle: Python zipfile, both directions, testzip
- [ ] the malicious-archive and truncation sweeps
- [ ] README

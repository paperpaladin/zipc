# zipc

A ZIP archive reader in one C11 file. No libraries, no shelling out.

It does not write archives. `-c`, `-x`, `-C`, `-0`, `-D` and `-Z` are
listed in `PLAN.md` because that is the finished tool, and the binary
*refuses* them, exit 3 for the two modes, exit 2 for the four flags,
not accepting them and doing nothing.

That refusal is the point. `-x` previously read the whole archive, extracted
nothing, and exited 0. A tool that returns success for work it did not do is
worse than one that has no such flag.

```
zipc -t|-T [-v] [-f ARCHIVE]
  -t  list the central directory; -tv long-form
  -T  test: decompress every member and check its CRC-32, write nothing
  -f  archive file; '-' or omitted means stdin
```

Exit status: 0 success, 1 a member was refused or skipped, 2 the archive is
not parseable, 3 the mode asked for is not implemented.

## The oracle

Archives written by Info-ZIP's `zip` at every compression level, read back
three ways:

- `unzip -t`: against `zipc -T`, member by member, CRC by CRC.
- `zipinfo -v`: against `zipc -tv`, and that is why the long form prints
  method, sizes, ratio, CRC-32, DOS date/time and local-header offset in a
  diffable layout.
- Python's `zipfile`: a second independent implementation, in case
  `zipc` and Info-ZIP were wrong in the same direction.

`make test`: **76 passed, 0 failed.** `make test-asan` rebuilds the same
suite under ASan and UBSan and must also be green.

## What it reads

- local file headers, the central directory, the end-of-central-directory
  record, and the Zip64 EOCD record plus its locator
- methods 0 (STORE) and 8 (DEFLATE), with CRC-32 verified on every member
- the Zip64 extra field (0x0001) for uncompressed size, compressed size and
  local-header offset
- data descriptors, with and without the 0x08074b50 signature, in both the
  4-byte and 8-byte size forms
- DOS date and time, including the pre-1980 clamp
- an archive comment, including one that contains the EOCD signature, which
  is the case that breaks a naive backwards scan for the record

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

The write side, and two sweeps that need it: a malicious-archive corpus, and
a truncation sweep that cuts a real archive at every structural boundary and
then at every byte offset of a small one, requiring exit 2 every time with no
signal and no hang. `PLAN.md` tracks these as numbered items.

GPL-3.0-or-later.

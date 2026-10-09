/* zipc -- a ZIP archive reader and writer in one C11 file.
 *
 * Creates, lists, tests and extracts ZIP archives: local file headers, the
 * central directory, the end-of-central-directory record, Zip64, methods 0
 * (STORE) and 8 (DEFLATE), CRC-32 verification and DOS date/time.
 *
 * The DEFLATE core in the middle of this file -- bit reader, canonical
 * Huffman, the RFC 1951 tables, inflate_raw, and the LZ77 + Huffman encoder
 * -- is lifted from the sibling project ../inflate, which implements RFC
 * 1951 from scratch against /usr/bin/gzip as its oracle. The same vendoring
 * was done once already in ../pngc; this is the second borrower, not a third
 * implementation. Only the gzip (RFC 1952) framing is left behind, because
 * ZIP does its own. See README.md.
 *
 * The authority on correctness is Info-ZIP unzip and Python's zipfile, not
 * this code or my reading of APPNOTE.TXT. See t/run.sh.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *prog = "zipc";
static int failures;		/* something was refused or skipped: exit 1 */

/* shortcut: die() exits without freeing, so LeakSanitizer flags it.  Only
 * out-of-memory, write-error and cap-exceeded paths reach it, none of which
 * has a useful recovery; wire the buffers to atexit if that ever matters. */
static void die(const char *m)
{
	fprintf(stderr, "%s: %s\n", prog, m);
	exit(1);
}

/* An unparseable archive is exit 2, distinct from exit 1 "refused a member",
 * so a harness can tell "this file is not a zip" from "this zip is hostile". */
static void bad(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(2);
}

static void warn_(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static void refuse(const char *path, const char *why)
{
	fprintf(stderr, "%s: REFUSING unsafe member %s: %s\n", prog, path, why);
	failures++;
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("out of memory");
	return p;
}

/* ===================== vendored from ../inflate: buffer ================= */
/* Holds indices, never interior pointers: inflate copies from its own output
 * while that output is being realloc'd, so a cached pointer would dangle.
 *
 * `limit` is the one thing added here.  ../inflate decompresses a file you
 * chose; zipc decompresses a stream whose header told us how big it claims to
 * be, and a header that lies is the zip bomb.  Exceeding the limit is fatal
 * rather than recoverable, which is why it can live in bneed() instead of
 * being threaded as an error return through every bput() in inflate_raw. */
typedef struct { uint8_t *p; size_t n, cap, limit; } Buf;

static void bneed(Buf *b, size_t extra)
{
	if (extra > SIZE_MAX - b->n)
		die("out of memory");
	if (b->limit && b->n + extra > b->limit)
		die("REFUSING: decompressed output exceeds its declared size "
		    "(zip bomb?)");
	if (b->n + extra <= b->cap)
		return;
	size_t c = b->cap ? b->cap : 1u << 16;
	while (c < b->n + extra) {
		if (c > SIZE_MAX / 2) {
			c = b->n + extra;
			break;
		}
		c <<= 1;
	}
	uint8_t *q = realloc(b->p, c);
	if (!q)
		die("out of memory");
	b->p = q;
	b->cap = c;
}

static void bput(Buf *b, unsigned v)
{
	bneed(b, 1);
	b->p[b->n++] = (uint8_t)v;
}

static void bwrite(Buf *b, const void *s, size_t n)
{
	/* A zero-length append is not a no-op: bneed does not allocate for it,
	 * so b->p can still be NULL, and memcpy(NULL, s, 0) is undefined even
	 * though it copies nothing.  Empty members are a required test case. */
	if (!n)
		return;
	bneed(b, n);
	memcpy(b->p + b->n, s, n);
	b->n += n;
}

static void bu16(Buf *b, unsigned v)
{
	bput(b, v & 0xff);
	bput(b, (v >> 8) & 0xff);
}

static void bu32(Buf *b, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		bput(b, (v >> (8 * i)) & 0xff);
}

static void bu64(Buf *b, uint64_t v)
{
	for (int i = 0; i < 8; i++)
		bput(b, (unsigned)(v >> (8 * i)) & 0xff);
}

/* ===================== vendored from ../inflate: crc32 ================== */
/* ZIP's CRC-32 is the same one gzip uses: reflected, polynomial 0xEDB88320,
 * preset and post-inverted.  Nothing to change. */
static uint32_t crctab[256];

static void crcinit(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xEDB88320u & (uint32_t) - (int32_t) (c & 1));
		crctab[i] = c;
	}
}

static uint32_t crc32b(const uint8_t *p, size_t n)
{
	uint32_t c = 0xFFFFFFFFu;
	for (size_t i = 0; i < n; i++)
		c = crctab[(c ^ p[i]) & 0xff] ^ (c >> 8);
	return c ^ 0xFFFFFFFFu;
}

/* ======================= little-endian field reads ====================== */
/* Every one of these takes the buffer length and the offset, because every
 * offset in a ZIP file came out of the file itself.  There is no path in this
 * program that reads a field without first proving the field is inside the
 * archive. */
static size_t alen;		/* archive length, for the bounds checks below */
static const uint8_t *abuf;

static int have(uint64_t off, uint64_t n)
{
	return off <= alen && n <= (uint64_t)alen - off;
}

static unsigned r16(uint64_t o)
{
	return (unsigned)abuf[o] | (unsigned)abuf[o + 1] << 8;
}

static uint32_t r32(uint64_t o)
{
	return (uint32_t)abuf[o] | (uint32_t)abuf[o + 1] << 8 |
	    (uint32_t)abuf[o + 2] << 16 | (uint32_t)abuf[o + 3] << 24;
}

static uint64_t r64(uint64_t o)
{
	return (uint64_t)r32(o) | (uint64_t)r32(o + 4) << 32;
}

/* ============================== signatures ============================== */

#define SIG_LOCAL  0x04034b50u
#define SIG_CENT   0x02014b50u
#define SIG_EOCD   0x06054b50u
#define SIG_Z64EOC 0x06064b50u
#define SIG_Z64LOC 0x07064b50u
#define SIG_DD     0x08074b50u

/* =========================== reading the archive ======================== */

/* The whole archive is read into memory.  That is a design decision, not an
 * oversight: ZIP puts its index at the end, so a reader either seeks or
 * buffers, and buffering means every offset check in this file is a
 * comparison against one length instead of an lseek that might lie.  PLAN.md
 * lists streaming as a non-goal.
 *
 * shortcut: the ceiling is the archive having to fit in RAM.  mmap() with
 * MAP_PRIVATE would lift it without changing a single bounds check, since
 * everything below works from (abuf, alen); do that when a user turns up with
 * a 40 GB zip. */
static void slurp(const char *name)
{
	int fd = 0;
	if (name && strcmp(name, "-") != 0) {
		fd = open(name, O_RDONLY);
		if (fd < 0)
			bad("%s: %s", name, strerror(errno));
	}
	Buf b = { 0 };
	for (;;) {
		bneed(&b, 1u << 16);
		ssize_t k = read(fd, b.p + b.n, 1u << 16);
		if (k < 0)
			bad("read: %s", strerror(errno));
		if (!k)
			break;
		b.n += (size_t)k;
	}
	if (fd)
		close(fd);
	abuf = b.p;
	alen = b.n;
}

/* Where the central directory is, and how many entries it holds. */
typedef struct {
	uint64_t cdoff, cdsize, nent;
	uint64_t eocd;		/* offset of the 22-byte EOCD record */
	unsigned commentlen;
	int zip64;		/* a Zip64 EOCD record was used */
} End;

/* Does a candidate EOCD at `o` point at something that looks like a central
 * directory?  Used to disambiguate a real EOCD from the signature appearing
 * by chance -- or on purpose -- inside the archive comment. */
static int cd_plausible(uint64_t o)
{
	uint64_t nent = r16(o + 10), size = r32(o + 12), off = r32(o + 16);

	/* Zip64 spells these as 0xFFFF/0xFFFFFFFF and puts the truth in its own
	 * record, so a saturated field is not evidence either way. */
	if (nent == 0xFFFFu || size == 0xFFFFFFFFu || off == 0xFFFFFFFFu)
		return 1;
	if (!have(off, size) || off + size > o)
		return 0;
	if (!nent)
		return size == 0;
	return size >= 46 && r32(off) == SIG_CENT;
}

/* APPNOTE 4.3.16: the EOCD is the last thing in the file apart from a comment
 * of up to 65535 bytes, so it is found by scanning backwards for its
 * signature.  Those four bytes can also appear inside the comment itself,
 * which sits *after* the record -- so a naive backwards scan finds the decoy
 * first.  Two filters make that unambiguous in practice: the comment length
 * field has to account for exactly the bytes that follow the record, and the
 * offset it gives has to land on a central directory header.
 *
 * shortcut: "in practice".  An attacker who controls the whole comment can
 * build a decoy that satisfies both and embeds a second, complete central
 * directory, and then the file genuinely has two readings and every extractor
 * picks one.  We pick the last one in the file, which is Info-ZIP's choice;
 * the test suite pins that agreement rather than claiming the ambiguity away. */
static void find_end(End *e)
{
	if (alen < 22)
		bad("too short to be a zip archive (%zu bytes)", alen);

	uint64_t lo = alen > 65557 ? alen - 65557 : 0;
	uint64_t found = UINT64_MAX, loose = UINT64_MAX;

	for (uint64_t o = alen - 22 + 1; o-- > lo;) {
		if (r32(o) != SIG_EOCD)
			continue;
		if ((uint64_t)r16(o + 20) != alen - o - 22)
			continue;	/* comment length does not reach the end */
		if (loose == UINT64_MAX)
			loose = o;
		if (cd_plausible(o)) {
			found = o;
			break;
		}
	}
	if (found == UINT64_MAX)
		found = loose;
	if (found == UINT64_MAX)
		bad("no end-of-central-directory record found");

	memset(e, 0, sizeof *e);
	e->eocd = found;
	e->commentlen = r16(found + 20);
	if (r16(found + 4) || r16(found + 6))
		bad("multi-disk archives are not supported (disk %u of %u)",
		    r16(found + 4), r16(found + 6));
	e->nent = r16(found + 10);
	e->cdsize = r32(found + 12);
	e->cdoff = r32(found + 16);

	/* Zip64: a 20-byte locator sits immediately before the EOCD and points
	 * back at the Zip64 EOCD record, whose fields are the real ones. */
	if (found >= 20 && r32(found - 20) == SIG_Z64LOC) {
		if (r32(found - 20 + 4))
			bad("multi-disk Zip64 archive is not supported");
		uint64_t z = r64(found - 20 + 8);
		if (!have(z, 56) || r32(z) != SIG_Z64EOC)
			bad("Zip64 locator points at 0x%llx, which is not a "
			    "Zip64 end-of-central-directory record",
			    (unsigned long long)z);
		e->zip64 = 1;
		e->nent = r64(z + 32);
		e->cdsize = r64(z + 40);
		e->cdoff = r64(z + 48);
	}

	if (!have(e->cdoff, e->cdsize))
		bad("central directory at 0x%llx + %llu bytes runs past the "
		    "end of a %zu-byte archive",
		    (unsigned long long)e->cdoff,
		    (unsigned long long)e->cdsize, alen);
	if (e->cdoff + e->cdsize > e->eocd)
		bad("central directory overlaps the end-of-central-directory record");
	/* 46 bytes is the shortest a central directory header can be, so an
	 * entry count the directory cannot possibly hold is a lie and the
	 * allocation it implies must not happen. */
	if (e->nent > e->cdsize / 46)
		bad("%llu central directory entries declared but only %llu "
		    "bytes of directory",
		    (unsigned long long)e->nent, (unsigned long long)e->cdsize);
}

/* ========================== the central directory ======================= */

/* One member, as the central directory describes it.  Every number used to
 * extract comes from here and nowhere else; see invariant 1 in PLAN.md. */
typedef struct {
	char *name;
	uint64_t usize, csize, localoff;
	uint32_t crc, extattr;
	unsigned method, flags, dostime, dosdate;
	int zip64;		/* a Zip64 extra field supplied one of the above */
	int isdir;
} Ent;

#define F_ENCRYPTED 0x0001u
#define F_DATADESC  0x0008u

/* ZIP's name field is length-counted, so a name may contain a NUL -- at which
 * point every C string in this program, and in every other extractor, means
 * something different from what the archive says.  "good\0/../escape" is the
 * attack: a checker that stops at the NUL sees a clean name and an opener
 * that does not sees the traversal.  Refuse the ambiguity. */
static int name_ok(const uint8_t *p, unsigned n)
{
	return !memchr(p, 0, n);
}

/* Walk an extra-field block: a sequence of (id:u16, size:u16, data).  Only
 * 0x0001, the Zip64 record, is interpreted.  Its fields are present only for
 * the 32-bit fields that were saturated, in the order uncompressed size,
 * compressed size, local header offset, disk number -- so the amount of data
 * is not fixed and a short field is not an error, it is the normal case. */
static void read_extra(Ent *t, uint64_t off, unsigned n,
		       int sat_u, int sat_c, int sat_o)
{
	while (n >= 4) {
		unsigned id = r16(off), sz = r16(off + 2);
		if (sz > n - 4u)
			break;	/* a field claiming more than the block holds */
		if (id == 0x0001) {
			uint64_t q = off + 4;
			unsigned left = sz;
			t->zip64 = 1;
			/* Info-ZIP and Python both write all of usize+csize in
			 * the local header even when only one was saturated,
			 * so "saturated" is a hint and "is there room" is the
			 * rule.  Taking only the saturated ones would misread
			 * every archive zip -9 produces over 4 GB. */
			if (sat_u && left >= 8) {
				t->usize = r64(q);
				q += 8;
				left -= 8;
			}
			if (sat_c && left >= 8) {
				t->csize = r64(q);
				q += 8;
				left -= 8;
			}
			if (sat_o && left >= 8) {
				t->localoff = r64(q);
				q += 8;
				left -= 8;
			}
		}
		off += 4 + sz;
		n -= 4 + sz;
	}
}

/* Parses the whole central directory.  Returns a malloc'd array of e->nent. */
static Ent *read_cd(const End *e)
{
	Ent *v = xmalloc((e->nent ? (size_t)e->nent : 1) * sizeof *v);
	uint64_t p = e->cdoff, end = e->cdoff + e->cdsize;

	for (uint64_t i = 0; i < e->nent; i++) {
		if (p + 46 > end)
			bad("central directory entry %llu starts past the end "
			    "of the directory", (unsigned long long)i);
		if (r32(p) != SIG_CENT)
			bad("central directory entry %llu has signature "
			    "0x%08x, expected 0x02014b50",
			    (unsigned long long)i, r32(p));
		Ent *t = &v[i];
		memset(t, 0, sizeof *t);
		t->flags = r16(p + 8);
		t->method = r16(p + 10);
		t->dostime = r16(p + 12);
		t->dosdate = r16(p + 14);
		t->crc = r32(p + 16);
		t->csize = r32(p + 20);
		t->usize = r32(p + 24);
		unsigned nl = r16(p + 28), el = r16(p + 30), cl = r16(p + 32);
		if (r16(p + 34))
			bad("member %llu lives on disk %u: multi-disk archives "
			    "are not supported",
			    (unsigned long long)i, r16(p + 34));
		t->extattr = r32(p + 38);
		t->localoff = r32(p + 42);

		if ((uint64_t)nl + el + cl > end - (p + 46))
			bad("central directory entry %llu: name, extra and "
			    "comment (%u+%u+%u) run past the end of the "
			    "directory", (unsigned long long)i, nl, el, cl);
		if (!nl)
			bad("central directory entry %llu has an empty name",
			    (unsigned long long)i);
		if (!name_ok(abuf + p + 46, nl))
			bad("central directory entry %llu has a NUL in its "
			    "name", (unsigned long long)i);
		t->name = xmalloc(nl + 1);
		memcpy(t->name, abuf + p + 46, nl);
		t->name[nl] = '\0';
		t->isdir = t->name[nl - 1] == '/';

		read_extra(t, p + 46 + nl, el, t->usize == 0xFFFFFFFFu,
			   t->csize == 0xFFFFFFFFu,
			   t->localoff == 0xFFFFFFFFu);
		p += 46 + nl + el + cl;
	}
	return v;
}

/* MS-DOS date and time, as used by every ZIP since 1989.  Two-second
 * granularity, no time zone -- the fields are local time, which is why unzip
 * and zipc have to agree on localtime() and not on gmtime(). */
static void dos_fmt(unsigned date, unsigned time_, char out[20])
{
	snprintf(out, 20, "%04u-%02u-%02u %02u:%02u:%02u",
		 1980 + ((date >> 9) & 0x7f), (date >> 5) & 0x0f, date & 0x1f,
		 (time_ >> 11) & 0x1f, (time_ >> 5) & 0x3f, (time_ & 0x1f) * 2);
}

static const char *method_name(unsigned m)
{
	switch (m) {
	case 0:
		return "stor";
	case 8:
		return "defl";
	default:
		return "????";
	}
}

static void list(const End *e, const Ent *v, int verbose)
{
	if (verbose >= 2) {
		/* Machine-readable, to be diffed against t/oracle.py's `info`
		 * and against zipinfo -v.  A human format that nobody compares
		 * against an oracle is decoration. */
		for (uint64_t i = 0; i < e->nent; i++)
			printf("%s\t%u\t%u\t%llu\t%llu\t%llu\n", v[i].name,
			       v[i].method, v[i].crc,
			       (unsigned long long)v[i].csize,
			       (unsigned long long)v[i].usize,
			       (unsigned long long)v[i].localoff);
		return;
	}
	if (!verbose) {
		for (uint64_t i = 0; i < e->nent; i++)
			printf("%s\n", v[i].name);
		return;
	}

	printf("end-of-central-directory at 0x%llx: %llu entries, directory at "
	       "0x%llx + %llu bytes, comment %u bytes%s\n",
	       (unsigned long long)e->eocd, (unsigned long long)e->nent,
	       (unsigned long long)e->cdoff, (unsigned long long)e->cdsize,
	       e->commentlen, e->zip64 ? ", Zip64" : "");
	printf("meth      csize      usize  ratio  crc32     "
	       "date       time      offset  name\n");
	uint64_t tc = 0, tu = 0;
	for (uint64_t i = 0; i < e->nent; i++) {
		char when[20];
		dos_fmt(v[i].dosdate, v[i].dostime, when);
		long ratio = v[i].usize ?
		    100 - (long)((v[i].csize * 100) / v[i].usize) : 0;
		printf("%s %10llu %10llu %5ld%%  %08x  %s  0x%-8llx %s%s\n",
		       method_name(v[i].method),
		       (unsigned long long)v[i].csize,
		       (unsigned long long)v[i].usize, ratio, v[i].crc, when,
		       (unsigned long long)v[i].localoff, v[i].name,
		       v[i].zip64 ? "  [zip64]" : "");
		tc += v[i].csize;
		tu += v[i].usize;
	}
	printf("%llu members, %llu bytes compressed, %llu uncompressed\n",
	       (unsigned long long)e->nent, (unsigned long long)tc,
	       (unsigned long long)tu);
}

/* =========================== local file headers ========================= */

/* Finds a member's compressed data and checks the local file header against
 * the central directory.
 *
 * The check is the whole point of reading the local header at all.  Nothing
 * in it is believed: the sizes, CRC and method used to extract all come from
 * the central directory.  An extractor that believes the local header can be
 * handed an archive whose listing shows one thing and whose extraction
 * produces another, which is how a scanner and a user end up disagreeing
 * about what is inside a file.
 *
 * Returns the offset of the compressed data, or UINT64_MAX if the member must
 * be skipped (failures has been incremented and a line printed).  A structural
 * impossibility -- a header outside the archive, a bad signature -- is exit 2
 * instead, because it means the file is not a readable archive rather than
 * that one member is bad.
 */
static uint64_t member_data(const Ent *t)
{
	if (!have(t->localoff, 30))
		bad("%s: local header at 0x%llx is outside the archive",
		    t->name, (unsigned long long)t->localoff);
	if (r32(t->localoff) != SIG_LOCAL)
		bad("%s: local header at 0x%llx has signature 0x%08x, expected "
		    "0x04034b50", t->name, (unsigned long long)t->localoff,
		    r32(t->localoff));

	unsigned lflags = r16(t->localoff + 6), lmethod = r16(t->localoff + 8);
	uint32_t lcrc = r32(t->localoff + 14);
	unsigned nl = r16(t->localoff + 26), el = r16(t->localoff + 28);
	if (!have(t->localoff + 30, (uint64_t)nl + el))
		bad("%s: local header name and extra field run past the end of "
		    "the archive", t->name);

	/* The name is stored twice.  They have to be the same name, or the
	 * listing and the extraction are describing different members. */
	if (nl != strlen(t->name) ||
	    memcmp(abuf + t->localoff + 30, t->name, nl) != 0) {
		refuse(t->name, "local header names a different member");
		return UINT64_MAX;
	}

	Ent loc = { 0 };
	loc.csize = r32(t->localoff + 18);
	loc.usize = r32(t->localoff + 22);
	read_extra(&loc, t->localoff + 30 + nl, el,
		   loc.usize == 0xFFFFFFFFu, loc.csize == 0xFFFFFFFFu, 0);

	if (lmethod != t->method) {
		refuse(t->name, "local header and central directory disagree "
		       "about the compression method");
		return UINT64_MAX;
	}
	if ((lflags & F_DATADESC) != (t->flags & F_DATADESC)) {
		refuse(t->name, "local header and central directory disagree "
		       "about the data-descriptor flag");
		return UINT64_MAX;
	}
	/* With bit 3 set the local sizes and CRC are legitimately zero: the
	 * real values follow the data.  Without it, they must agree. */
	if (!(t->flags & F_DATADESC) &&
	    (loc.csize != t->csize || loc.usize != t->usize || lcrc != t->crc)) {
		fprintf(stderr, "%s: %s: local header says crc %08x csize %llu "
			"usize %llu, central directory says crc %08x csize %llu "
			"usize %llu -- using the central directory\n",
			prog, t->name, lcrc, (unsigned long long)loc.csize,
			(unsigned long long)loc.usize, t->crc,
			(unsigned long long)t->csize,
			(unsigned long long)t->usize);
		failures++;
		return UINT64_MAX;
	}

	uint64_t off = t->localoff + 30 + nl + el;
	if (!have(off, t->csize))
		bad("%s: %llu compressed bytes at 0x%llx run past the end of a "
		    "%zu-byte archive", t->name, (unsigned long long)t->csize,
		    (unsigned long long)off, alen);
	return off;
}

/* ================================== main ================================ */

static const char USAGE[] =
    "usage: zipc -c|-t|-T|-x [-v] [-0] [-D] [-Z] [-f ARCHIVE] [-C DIR] [PATH...]\n"
    "  -c  create an archive of PATH... (directories recursed, sorted)\n"
    "  -t  list the central directory; -tv long-form\n"
    "  -T  test: decompress every member and check its CRC-32, write nothing\n"
    "  -x  extract\n"
    "  -f  archive file; '-' or omitted means stdout (-c) or stdin (-t/-T/-x)\n"
    "  -C  extract into DIR\n"
    "  -0  store, do not deflate\n"
    "  -D  write data descriptors instead of sizes in the local header\n"
    "  -Z  force Zip64 on every member and on the EOCD\n"
    "exit 0 on success, 1 if a member was refused or skipped, 2 if the\n"
    "archive is not parseable.\n";

int main(int argc, char **argv)
{
	int mode = 0, verbose = 0;
	const char *arcname = NULL;

	crcinit();

	int i = 1;
	for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
		for (const char *s = argv[i] + 1; *s; s++) {
			switch (*s) {
			case 'c': case 't': case 'T': case 'x':
				if (mode && mode != *s)
					bad("pick one of -c, -t, -T, -x");
				mode = *s;
				break;
			case 'v':
				verbose++;
				break;
			case 'f':
				if (s[1])
					arcname = s + 1;
				else if (++i < argc)
					arcname = argv[i];
				else
					bad("-f needs an argument");
				s = "";
				break;
			default:
				fputs(USAGE, stderr);
				return 2;
			}
			if (!*s)
				break;
		}
	}

	(void)crc32b;
	(void)bu16;
	(void)bu32;
	(void)bu64;
	(void)bwrite;
	(void)xmalloc;
	(void)warn_;
	(void)refuse;

	if (!mode) {
		fputs(USAGE, stderr);
		return 2;
	}

	slurp(arcname);
	End e;
	find_end(&e);
	Ent *v = read_cd(&e);
	if (mode == 't') {
		list(&e, v, verbose);
	} else if (mode == 'T') {
		for (uint64_t k = 0; k < e.nent; k++) {
			uint64_t off = member_data(&v[k]);
			if (off == UINT64_MAX)
				continue;
			if (verbose)
				printf("%s: %llu bytes of method-%u data at "
				       "0x%llx\n", v[k].name,
				       (unsigned long long)v[k].csize,
				       v[k].method, (unsigned long long)off);
		}
		if (!failures && verbose)
			printf("%llu members, every local header agrees with "
			       "the central directory\n",
			       (unsigned long long)e.nent);
	}
	return failures ? 1 : 0;
}

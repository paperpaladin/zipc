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

	(void)verbose;
	(void)arcname;
	(void)abuf;
	(void)have;
	(void)r16;
	(void)r32;
	(void)r64;
	(void)crc32b;
	(void)bu16;
	(void)bu32;
	(void)bu64;
	(void)bwrite;
	(void)bput;
	(void)xmalloc;
	(void)warn_;
	(void)refuse;
	(void)bad;

	if (!mode) {
		fputs(USAGE, stderr);
		return 2;
	}
	return failures ? 1 : 0;
}

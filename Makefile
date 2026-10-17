CC      = gcc
# -ffile-prefix-map keeps the build directory out of DWARF, so the binary is
# bit-identical wherever it is built.  Checked by ../unrepro.
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=.
# Without this, off_t is 32 bits on a 32-bit host and every Zip64 test breaks
# in a way that looks like a format bug.
CPPFLAGS = -D_FILE_OFFSET_BITS=64

zipc: zipc.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<

test: zipc
	@t/run.sh ./zipc

# zipc parses attacker-chosen offsets and lengths out of a byte buffer, so the
# sanitiser build is the one that matters.  exitcode=86 is load-bearing: a
# sanitiser abort exits 1 by default and the harness reads "exit 1" as "cleanly
# refused", so without it test-asan could not fail.  UBSan only prints unless
# told to halt.
# detect_leaks=0 because zipc deliberately never frees: it reads one archive
# and exits, so the central directory it allocates is still live at exit and
# LeakSanitizer reports it on every successful run.  Without this the gate was
# red from the first commit, 30 of its 69 assertions failing on exit 86, which
# is why nothing had ever read its output.  What the sanitiser is here for is
# the out-of-bounds read on an attacker-chosen offset, and that still halts.
SANOPT = ASAN_OPTIONS=exitcode=86:detect_leaks=0 \
	 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86

test-asan: zipc.c
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=. $(CPPFLAGS) \
		-o zipc-asan zipc.c
	@$(SANOPT) t/run.sh ./zipc-asan

clean:
	rm -f zipc zipc-asan
	rm -rf t/tmp* .scratch

.PHONY: test test-asan clean

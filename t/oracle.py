#!/usr/bin/env python3
"""The third implementation, and the archive forge.

Python's zipfile is an independent reader and writer, so it is used here as an
oracle in both directions.  It is also the only convenient way to build the
archives this suite needs that no sane archiver will produce: a member called
"../escape", a declared uncompressed size of eight gigabytes, a comment
containing the end-of-central-directory signature.  zipfile lets a member name
and a size be written verbatim, which is exactly what makes it a forge.

Everything is a subcommand so t/run.sh stays readable; run with no arguments
for the list.  Standard library only.
"""
import os
import struct
import sys
import zipfile

SIG_EOCD = b'PK\x05\x06'


def out(*a):
    print(*a)


# ------------------------------------------------------------------ reading

def cmd_names(path):
    """One member name per line, in central-directory order."""
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            out(n)


def cmd_info(path):
    """name<TAB>method<TAB>crc<TAB>csize<TAB>usize<TAB>header_offset.

    The fields zipinfo -v also reports, in a form that diffs cleanly against
    `zipc -tv --raw`.
    """
    with zipfile.ZipFile(path) as z:
        for i in sorted(z.infolist(), key=lambda i: i.filename):
            out('%s\t%d\t%u\t%d\t%d\t%d' % (i.filename, i.compress_type,
                                            i.CRC & 0xffffffff,
                                            i.compress_size, i.file_size,
                                            i.header_offset))


def cmd_testzip(path):
    """zipfile's own CRC check over every member.  Prints OK or the member."""
    with zipfile.ZipFile(path) as z:
        r = z.testzip()
    out('OK' if r is None else 'BAD ' + r)


def cmd_verify(path, tree):
    """Every member zipfile reads must equal the file of the same name in
    `tree`.  This is the check that zipc and zipfile agree on *content*, not
    merely that both think the archive is well formed."""
    bad = []
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if not n.endswith('/')]
        for n in names:
            disk = os.path.join(tree, n)
            if not os.path.isfile(disk):
                bad.append('missing on disk: ' + n)
                continue
            if z.read(n) != open(disk, 'rb').read():
                bad.append('content differs: ' + n)
        for root, _dirs, files in os.walk(tree):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), tree)
                if rel not in names:
                    bad.append('missing from archive: ' + rel)
    if bad:
        for b in bad:
            out('BAD ' + b)
        sys.exit(1)
    out('OK %d members' % len(names))


def cmd_extract(path, dest):
    """zipfile extracts into dest.  Note that zipfile *sanitises* hostile
    names rather than refusing them, so this is only ever pointed at archives
    we wrote; it is not a security oracle."""
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(path) as z:
        z.extractall(dest)
    out('OK')


# ------------------------------------------------------------------ writing

def _members(tree):
    for root, dirs, files in os.walk(tree):
        dirs.sort()
        for f in sorted(files):
            full = os.path.join(root, f)
            yield full, os.path.relpath(full, tree)


def cmd_write(path, tree, how='deflate'):
    """zipfile writes an archive of `tree` for zipc to read back.

    how: store | deflate | zip64 | stream.  `stream` writes to a pipe-like
    object so zipfile is forced to emit data descriptors, which `zip` itself
    will not do; `zip64` forces the Zip64 extra field on every member
    regardless of size.
    """
    comp = zipfile.ZIP_STORED if how == 'store' else zipfile.ZIP_DEFLATED

    class Sink:
        """Unseekable, so ZipFile falls back to data descriptors."""

        def __init__(self, f):
            self.f = f

        def write(self, b):
            return self.f.write(b)

        def flush(self):
            self.f.flush()

        def tell(self):
            return self.f.tell()

    with open(path, 'wb') as raw:
        target = Sink(raw) if how == 'stream' else raw
        with zipfile.ZipFile(target, 'w', comp, allowZip64=True) as z:
            for full, rel in _members(tree):
                size = os.path.getsize(full)
                if how == 'zip64':
                    with z.open(zipfile.ZipInfo(rel), 'w',
                                force_zip64=True) as w:
                        w.write(open(full, 'rb').read())
                elif how == 'stream':
                    zi = zipfile.ZipInfo(rel)
                    zi.compress_type = comp
                    with z.open(zi, 'w') as w:
                        w.write(open(full, 'rb').read())
                else:
                    z.write(full, rel)
                del size
    out('OK')


# ------------------------------------------------------------------- forging

def _raw(path, members, comment=b''):
    """Write an archive member by member with the names and flags given,
    bypassing every check zipfile would otherwise apply to a name.

    members: list of (name, data, method) with method 0 or 8, or
    (name, data, method, external_attr) to mark a symlink.
    """
    with zipfile.ZipFile(path, 'w', allowZip64=True) as z:
        for m in members:
            name, data, method = m[0], m[1], m[2]
            zi = zipfile.ZipInfo(filename='x')
            zi.filename = name		# assigned after construction: no cleanup
            zi.compress_type = method
            zi.date_time = (2024, 1, 1, 0, 0, 0)
            if len(m) > 3:
                zi.create_system = 3	# Unix, so external_attr is st_mode<<16
                zi.external_attr = m[3]
            z.writestr(zi, data)
        z.comment = comment


def craft_escape(path):
    _raw(path, [('../escape', b'OWNED\n', 0)])


def craft_escape_deep(path):
    _raw(path, [('a/b/../../../escape', b'OWNED\n', 0)])


def craft_absolute(path):
    _raw(path, [('/escape', b'OWNED\n', 0)])


def craft_abs_canary(path):
    """An absolute path naming a specific file, so the canary assertion is
    about that exact path and not merely about "nothing appeared"."""
    _raw(path, [(os.environ.get('ZIPC_CANARY', '/canary'), b'OWNED\n', 0)])


def craft_backslash(path):
    _raw(path, [('..\\..\\escape', b'OWNED\n', 0)])


def craft_backslash_mixed(path):
    _raw(path, [('a/..\\../escape', b'OWNED\n', 0)])


def craft_drive(path):
    _raw(path, [('C:\\escape', b'OWNED\n', 0)])


def craft_backslash_ok(path):
    """A backslash that does NOT escape.  Refusing this one too would be
    safe but wrong, and without it the backslash rule could be "reject every
    backslash" and the suite would not notice."""
    _raw(path, [('weird\\name.txt', b'fine\n', 0)])


def craft_nul(path):
    _raw(path, [('good\x00/../escape', b'OWNED\n', 0)])


def craft_dotdot_only(path):
    _raw(path, [('..', b'OWNED\n', 0)])


def craft_symlink(path):
    """A symlink member: Unix mode S_IFLNK|0777 in the top 16 bits of
    external_attr, with the target as the member's content."""
    _raw(path, [('link', b'/etc/passwd', 0, (0o120777 << 16))])


def craft_symlink_dir(path):
    """The two-member attack: a symlink out of the destination, then a
    regular member written through it."""
    _raw(path, [('out', b'..', 0, (0o120777 << 16)),
                ('out/escape', b'OWNED\n', 0)])


def craft_empty_name(path):
    _raw(path, [('', b'OWNED\n', 0)])


def craft_eocd_in_comment(path):
    """A comment holding the EOCD signature, with a comment-length field of
    its own that is consistent with the end of the file, so only the "does
    this point at a central directory" filter rejects it.

    Layout, 22 bytes exactly: signature, then disk numbers and counts chosen
    to look plausible, then a zero comment length -- which is correct for a
    decoy sitting 22 bytes from the end of the file.
    """
    _raw(path, [('real.txt', b'the real member\n', 8)])
    decoy = SIG_EOCD + struct.pack('<HHHHIIH',
                                   0, 0,	# disk, cd start disk
                                   1, 1,	# entries here, total
                                   46,		# cd size
                                   0,		# cd offset: points at a local
						# header, not a central one
                                   0)		# comment length
    assert len(decoy) == 22, len(decoy)
    with zipfile.ZipFile(path, 'a') as z:
        z.comment = decoy
    data = open(path, 'rb').read()
    assert data.endswith(decoy), 'decoy is not the last 22 bytes'
    assert data.count(SIG_EOCD) >= 2, 'decoy signature is not in the file'


def craft_eocd_in_comment_mild(path):
    """The signature in the comment, but not as the last 22 bytes, so the
    comment-length filter alone settles it.  Info-ZIP and zipfile both read
    this one correctly; the adversarial version above they do not, which is
    the only place the three implementations disagree.
    """
    _raw(path, [('real.txt', b'the real member\n', 8)],
         comment=b'look: ' + SIG_EOCD + b' and more text after it, '
         b'so the decoy is nowhere near the end of the file')
    data = open(path, 'rb').read()
    assert data.count(SIG_EOCD) >= 2, 'decoy signature is not in the file'


def craft_bomb_declared(path):
    """A member declaring eight gigabytes of output from eleven bytes of
    deflate.  Nothing is decompressed: the declared size alone must stop it."""
    _raw(path, [('bomb', b'x' * 16, 8)])
    _patch_sizes(path, 'bomb', usize=8 << 30)


def craft_bomb_ratio(path, mib=64):
    """A real, honest, highly compressible member: mib MiB of zeros.  The
    declared size is true and under the per-member cap, so only the expansion
    ratio can refuse it."""
    _raw(path, [('zeros', b'\0' * (mib << 20), 8)])


def craft_bomb_lying(path):
    """A member whose declared size is small and whose actual output is
    large.  The caps let this one through; the inflate output limit is what
    has to stop it, mid-stream."""
    _raw(path, [('liar', b'\0' * (4 << 20), 8)])
    _patch_sizes(path, 'liar', usize=1024, crc=0)


def craft_bomb_total(path):
    """Twenty members, each declaring 200 MiB.  No single one exceeds the
    per-member cap; together they exceed the whole-archive cap."""
    _raw(path, [('m%02d' % i, b'x' * 16, 8) for i in range(20)])
    for i in range(20):
        _patch_sizes(path, 'm%02d' % i, usize=200 << 20)


def _patch_sizes(path, member, usize=None, csize=None, crc=None):
    """Rewrite a member's sizes in BOTH the central directory and the local
    header, in place.

    Both, deliberately: patching only one would be testing the
    local-vs-central disagreement check instead of the size caps, and the
    first would mask the second.
    """
    data = bytearray(open(path, 'rb').read())
    name = member.encode()
    with zipfile.ZipFile(path) as z:
        zi = z.getinfo(member)
    cent = data.find(b'PK\x01\x02')
    while cent >= 0:
        nlen = struct.unpack_from('<H', data, cent + 28)[0]
        if data[cent + 46:cent + 46 + nlen] == name:
            break
        cent = data.find(b'PK\x01\x02', cent + 1)
    assert cent >= 0, 'central header for %r not found' % member
    loc = zi.header_offset
    assert data[loc:loc + 4] == b'PK\x03\x04'
    for base, off_crc, off_c, off_u in ((loc, 14, 18, 22), (cent, 16, 20, 24)):
        if crc is not None:
            struct.pack_into('<I', data, base + off_crc, crc)
        if csize is not None:
            struct.pack_into('<I', data, base + off_c, csize)
        if usize is not None:
            struct.pack_into('<I', data, base + off_u, usize)
    open(path, 'wb').write(bytes(data))


def craft_crc_bad(path):
    _raw(path, [('good.txt', b'hello world\n', 8)])
    _patch_sizes(path, 'good.txt', crc=0xdeadbeef)


def craft_local_disagrees(path):
    """The central directory says one size, the local header another.  The
    central directory is authoritative, so extraction must use its numbers
    and report the disagreement rather than quietly believing either."""
    _raw(path, [('d.txt', b'hello world\n', 0)])
    data = bytearray(open(path, 'rb').read())
    loc = data.find(b'PK\x03\x04')
    struct.pack_into('<I', data, loc + 22, 999999)	# local usize only
    open(path, 'wb').write(bytes(data))


def craft_local_name_differs(path):
    _raw(path, [('abcd.txt', b'hello\n', 0)])
    data = bytearray(open(path, 'rb').read())
    loc = data.find(b'PK\x03\x04')
    data[loc + 30:loc + 34] = b'ZZZZ'
    open(path, 'wb').write(bytes(data))


def craft_encrypted(path):
    _raw(path, [('e.txt', b'hello\n', 0)])
    data = bytearray(open(path, 'rb').read())
    for sig, off in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
        i = data.find(sig)
        struct.pack_into('<H', data, i + off,
                         struct.unpack_from('<H', data, i + off)[0] | 1)
    open(path, 'wb').write(bytes(data))


def craft_method99(path):
    _raw(path, [('m.txt', b'hello\n', 0)])
    data = bytearray(open(path, 'rb').read())
    for sig, off in ((b'PK\x03\x04', 8), (b'PK\x01\x02', 10)):
        struct.pack_into('<H', data, data.find(sig) + off, 99)
    open(path, 'wb').write(bytes(data))


def cmd_craft(which, path):
    fn = globals().get('craft_' + which.replace('-', '_'))
    if not fn:
        sys.exit('no such archive: ' + which)
    fn(path)
    out('OK')


def cmd_crafts():
    for k in sorted(globals()):
        if k.startswith('craft_'):
            out(k[6:].replace('_', '-'))


# -------------------------------------------------------------- the tree

def cmd_tree(d):
    """The round-trip tree: every case the format or the security model has
    an opinion about."""
    os.makedirs(d, exist_ok=True)
    mk = lambda p: os.makedirs(os.path.join(d, p), exist_ok=True)
    wr = lambda p, b: open(os.path.join(d, p), 'wb').write(b)

    mk('a/b/c')
    mk('emptydir')			# an empty directory
    wr('a/hello.txt', b'hello, world\n')
    wr('a/b/c/deep.txt', b'nested\n')
    wr('empty', b'')			# an empty file
    wr('binary.dat', bytes(range(256)) * 40 + b'\0\0\0')
    wr('sp ace.txt', b'spaces in the name\n')

    # A 200-character member path.  Nothing in ZIP limits a name to 255, but
    # every path component must still be a legal filename, so it is built out
    # of many short components rather than one long one.
    long = '/'.join(['dir%02d' % i for i in range(20)]) + '/' + 'n' * 76
    assert len(long) == 200, len(long)
    mk(os.path.dirname(long))
    wr(long, b'two hundred characters of path\n')

    # Compresses badly: urandom, so DEFLATE must give up and the writer must
    # fall back to STORE.
    wr('random.bin', os.urandom(300000))
    # Compresses extremely well, but honestly: a repeating pattern rather
    # than a run of zeros, so it stays under the expansion-ratio cap that
    # exists to stop bombs.  A file that only passes because the cap is
    # loose would not be testing the cap.
    wr('squishy.txt', b'the quick brown fox jumps over the lazy dog, '
       b'and the dog did not care at all about it.\n' * 12000)
    # 5 MB, mixed enough not to compress to nothing.
    blob = bytearray()
    x = 0x12345678
    while len(blob) < 5 * 1000 * 1000:
        x = (x * 1103515245 + 12345) & 0xffffffff
        blob += struct.pack('<I', x) + b'padding padding '
    wr('big5mb.bin', bytes(blob[:5 * 1000 * 1000]))
    out('OK')


# ------------------------------------------------------------------ dispatch

def main(argv):
    cmds = {k[4:]: v for k, v in globals().items() if k.startswith('cmd_')}
    if len(argv) < 2 or argv[1] not in cmds:
        sys.exit('usage: oracle.py {%s} [args...]' % '|'.join(sorted(cmds)))
    cmds[argv[1]](*argv[2:])


if __name__ == '__main__':
    main(sys.argv)

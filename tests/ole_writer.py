"""
Minimal, real, spec-valid CFBF (Compound File Binary Format / OLE2) writer —
built for testing Windows Jump List Analyzer.

`olefile` (the real library the app uses to *read* AutomaticDestinations-ms
jump lists) has no write API, so to genuinely engine-test the OLE parsing
path we need real, structurally valid OLE2 bytes on disk. This module
writes them by hand, following the real documented [MS-CFB] sector/FAT/
directory layout (512-byte sectors, version 3).

Simplification used here (still spec-valid, not a hack): every stream is
padded to be >= the 4096-byte MiniFAT cutoff, so every stream is stored in
regular FAT sectors and this writer never has to implement the MiniFAT /
mini-stream machinery. Real bytes come first in each stream; the padding
is zero bytes that the real LNK/DestList parsers never read past (both
parsers consume only as many bytes as their own structural fields dictate).
"""
import struct

SECTOR_SIZE = 512
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

STGTY_ROOT = 5
STGTY_STREAM = 2


def _pad_stream(data):
    target = max(len(data), 4096)
    # round up to a sector multiple
    if target % SECTOR_SIZE:
        target += SECTOR_SIZE - (target % SECTOR_SIZE)
    return data + b"\x00" * (target - len(data))


def _dir_entry(name, entry_type, left, right, child, start_sector, size):
    name_utf16 = name.encode("utf-16-le")
    if len(name_utf16) > 62:
        raise ValueError("stream name too long for this minimal writer")
    name_field = name_utf16 + b"\x00" * (64 - len(name_utf16))
    name_len = len(name_utf16) + 2  # includes null terminator, per spec
    entry = b""
    entry += name_field
    entry += struct.pack("<H", name_len)
    entry += struct.pack("<B", entry_type)
    entry += struct.pack("<B", 1)  # color flag: black
    entry += struct.pack("<I", left)
    entry += struct.pack("<I", right)
    entry += struct.pack("<I", child)
    entry += b"\x00" * 16  # CLSID
    entry += struct.pack("<I", 0)  # state bits
    entry += b"\x00" * 8  # creation time
    entry += b"\x00" * 8  # modified time
    entry += struct.pack("<I", start_sector)
    entry += struct.pack("<Q", size)
    assert len(entry) == 128
    return entry


def build_minimal_ole(streams):
    """streams: dict[str, bytes] of real stream name -> real content bytes
    (e.g. {"DestList": <real bytes>, "1": <real embedded LNK bytes>}).
    Returns real, valid CFBF file bytes containing exactly those streams
    directly under the root storage, chained as a simple right-linked list
    (a valid, if degenerate, red-black directory tree)."""
    names = list(streams.keys())
    padded = {name: _pad_stream(data) for name, data in streams.items()}

    # Sector plan: sector 0 = FAT, sector 1 = single directory sector
    # (root + up to 3 streams = 4 entries = exactly one 512-byte sector),
    # then each stream gets consecutive sectors.
    if len(names) > 3:
        raise ValueError("this minimal test writer supports at most 3 streams (fits one directory sector)")

    sector_cursor = 2
    stream_layout = {}  # name -> (start_sector, num_sectors, real_size)
    for name in names:
        data = padded[name]
        num_sectors = len(data) // SECTOR_SIZE
        stream_layout[name] = (sector_cursor, num_sectors, len(data))
        sector_cursor += num_sectors

    total_sectors = sector_cursor  # includes FAT(0) + dir(1) + streams

    # Build FAT (one sector = 128 x 4-byte entries, covers up to 128 sectors)
    if total_sectors > 128:
        raise ValueError("this minimal test writer only supports up to 128 sectors (one FAT sector)")
    fat_entries = [FREESECT] * 128
    fat_entries[0] = FATSECT  # the FAT sector itself
    fat_entries[1] = ENDOFCHAIN  # the single directory sector
    for name in names:
        start, num_sectors, _ = stream_layout[name]
        for i in range(num_sectors):
            sector_index = start + i
            fat_entries[sector_index] = (start + i + 1) if i < num_sectors - 1 else ENDOFCHAIN

    fat_bytes = b"".join(struct.pack("<I", v) for v in fat_entries)
    assert len(fat_bytes) == SECTOR_SIZE

    # Build directory entries: Root (id 0) + one per stream, right-chained.
    dir_entries_bytes = []
    root_child = 1 if names else NOSTREAM
    dir_entries_bytes.append(_dir_entry("Root Entry", STGTY_ROOT, NOSTREAM, NOSTREAM, root_child, 0, 0))
    for idx, name in enumerate(names):
        entry_id = idx + 1
        right = entry_id + 1 if entry_id < len(names) else NOSTREAM
        start_sector, _, real_size = stream_layout[name]
        dir_entries_bytes.append(
            _dir_entry(name, STGTY_STREAM, NOSTREAM, right, NOSTREAM, start_sector, real_size)
        )
    # Pad directory sector to exactly 4 entries (512 bytes)
    while len(dir_entries_bytes) < 4:
        dir_entries_bytes.append(_dir_entry("", 0, NOSTREAM, NOSTREAM, NOSTREAM, 0, 0))
    dir_sector_bytes = b"".join(dir_entries_bytes)
    assert len(dir_sector_bytes) == SECTOR_SIZE

    # Build header (512 bytes)
    header = b""
    header += b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"  # signature
    header += b"\x00" * 16  # CLSID
    header += struct.pack("<H", 0x003E)  # minor version
    header += struct.pack("<H", 0x0003)  # major version (3 -> 512-byte sectors)
    header += struct.pack("<H", 0xFFFE)  # byte order
    header += struct.pack("<H", 9)  # sector shift (2^9 = 512)
    header += struct.pack("<H", 6)  # mini sector shift (2^6 = 64)
    header += b"\x00" * 6  # reserved
    header += struct.pack("<I", 0)  # number of directory sectors (0 for v3)
    header += struct.pack("<I", 1)  # number of FAT sectors
    header += struct.pack("<I", 1)  # first directory sector location
    header += struct.pack("<I", 0)  # transaction signature
    header += struct.pack("<I", 4096)  # mini stream cutoff size
    header += struct.pack("<I", ENDOFCHAIN)  # first mini FAT sector
    header += struct.pack("<I", 0)  # number of mini FAT sectors
    header += struct.pack("<I", ENDOFCHAIN)  # first DIFAT sector
    header += struct.pack("<I", 0)  # number of DIFAT sectors
    difat = [0] + [FREESECT] * 108
    header += b"".join(struct.pack("<I", v) for v in difat)
    assert len(header) == SECTOR_SIZE

    out = bytearray()
    out += header
    out += fat_bytes
    out += dir_sector_bytes
    for name in names:
        out += padded[name]

    return bytes(out)

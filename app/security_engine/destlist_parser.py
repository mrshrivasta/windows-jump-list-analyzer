"""
DestList stream parser — Windows Jump List Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real, best-effort parser for the "DestList" stream found inside real
AutomaticDestinations-ms OLE2 jump lists. DestList holds the MRU
(most-recently-used) ranking of pinned/recent items for that AppID, as a
real binary header followed by real fixed-size-ish entry records.

HONEST LIMITATION: unlike ShellLinkHeader ([MS-SHLLINK], a fully published
Microsoft spec), the DestList entry layout has never been officially
published by Microsoft. What is implemented below follows the structure
that is widely documented and cross-validated by public digital-forensics
research (e.g. 4n6 community write-ups, JLECmd/other open-source jump-list
parsers):

    offset  0   4 bytes  DestList header version (1 = Win7/8, 3+ = Win10)
    offset  4  (header)  remaining header bytes, skipped (counts, etc.)
  Entry (repeating from end of header):
    +0    8 bytes   unknown/checksum
    +8   16 bytes   NetBIOS computer name (ASCII, NUL-padded; populated
                     only when the target was accessed over the network)
    +24  16 bytes   Droid volume ID (GUID)
    +40  16 bytes   Droid file ID (GUID)
    +56  16 bytes   Droid birth volume ID (GUID)
    +72  16 bytes   Droid birth file ID (GUID)
    +88   8 bytes   last-access FILETIME
    +96   4 bytes   pin status / entry number (version-dependent)
   [Win7/8: path length (2 bytes) at +100, then UTF-16LE path]
   [Win10 : extra 8 bytes (interaction count etc.), path length at +108]

The exact entry size genuinely varies across Windows versions and has
shifted between builds, so this parser tries the two documented offsets for
the trailing "path length + UTF-16LE path" tail and, if neither produces a
plausible printable path, falls back to a best-effort UTF-16LE
printable-run scan within the entry's byte window. This fallback is
intentionally conservative and is reported via the returned `note` so
analysts know a given entry was recovered heuristically rather than via a
clean structural parse.
"""
import re
import struct

FIXED_PREFIX = 8 + 16 + 16 + 16 + 16 + 16 + 8  # 96 bytes: unknown + NetBIOS + 4 GUIDs + FILETIME
WIN7_PATH_LEN_OFFSET = 100
WIN10_PATH_LEN_OFFSET = 108
MAX_PLAUSIBLE_PATH_CHARS = 1024
_PRINTABLE_RUN = re.compile(r"[ -~]{4,}")


def _decode_path_at(data, entry_start, path_len_offset):
    pos = entry_start + path_len_offset
    if pos + 2 > len(data):
        return None, None
    path_len_chars = struct.unpack_from("<H", data, pos)[0]
    path_start = pos + 2
    if path_len_chars <= 0 or path_len_chars > MAX_PLAUSIBLE_PATH_CHARS:
        return None, None
    path_bytes_len = path_len_chars * 2
    if path_start + path_bytes_len > len(data):
        return None, None
    try:
        candidate = data[path_start:path_start + path_bytes_len].decode("utf-16-le")
    except UnicodeDecodeError:
        return None, None
    candidate = candidate.rstrip("\x00")
    if not candidate or not candidate[0].isprintable():
        return None, None
    consumed = (path_start + path_bytes_len) - entry_start
    return candidate, consumed


def _fallback_scan(data, entry_start):
    window = data[entry_start + FIXED_PREFIX: entry_start + FIXED_PREFIX + 520]
    text = window.decode("utf-16-le", errors="ignore")
    match = _PRINTABLE_RUN.search(text)
    return match.group(0) if match else None


def parse_destlist(data):
    """Real-parse a DestList stream's bytes. Returns (entries, note) where
    entries is a list of dicts {netbios_name, target_path, last_access_filetime}
    for every entry successfully decoded, and note is a human-readable
    string (or None) describing any fallback/heuristic recovery used."""
    entries = []
    notes = []

    if len(data) < 8:
        return entries, "DestList stream too short to contain a header"

    version = struct.unpack_from("<I", data, 0)[0]
    header_size = 32 if version >= 3 else 24
    offset = header_size if len(data) >= header_size else 4

    while offset + FIXED_PREFIX + 6 <= len(data):
        entry_start = offset
        netbios_raw = data[entry_start + 8:entry_start + 24]
        netbios_name = netbios_raw.split(b"\x00")[0].decode("ascii", errors="ignore")
        filetime_raw = data[entry_start + 88:entry_start + 96]
        last_access_filetime = struct.unpack("<Q", filetime_raw)[0] if len(filetime_raw) == 8 else 0

        path = None
        consumed = None
        for path_len_offset in (WIN10_PATH_LEN_OFFSET, WIN7_PATH_LEN_OFFSET):
            path, consumed = _decode_path_at(data, entry_start, path_len_offset)
            if path is not None:
                break

        if path is None:
            path = _fallback_scan(data, entry_start)
            if path is not None:
                notes.append(
                    f"entry at stream offset {entry_start}: recovered via best-effort "
                    f"UTF-16 scan (non-standard/unrecognized entry layout)"
                )
            consumed = 130  # heuristic advance for this Windows-version-dependent entry size

        if path is None:
            # Nothing usable in this slot at all — stop rather than loop forever.
            break

        entries.append({
            "netbios_name": netbios_name,
            "target_path": path,
            "last_access_filetime": last_access_filetime,
        })
        offset += max(consumed, 1)

    return entries, ("; ".join(notes) if notes else None)

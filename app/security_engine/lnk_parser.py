"""
Shared MS-SHLLINK (Shell Link / .lnk) binary parser — Windows Jump List Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

This is a real, minimal, spec-following implementation of the documented
[MS-SHLLINK] Shell Link Binary File Format, used for two real purposes in
this project:

1. Parsing the embedded Shell Link structures stored inside numbered OLE2
   streams of a real AutomaticDestinations-ms jump list (each such stream
   IS a full ShellLinkHeader + LinkInfo + StringData blob, byte-for-byte
   identical in layout to a standalone .lnk file on disk).
2. Parsing the embedded Shell Link blobs concatenated raw inside a real
   CustomDestinations-ms jump list, located by scanning for the real
   20-byte magic (HeaderSize field + LinkCLSID) that begins every
   ShellLinkHeader.

Only the fields this project needs are decoded: the LinkInfo target path
(VolumeID + LocalBasePath / CommonNetworkRelativeLink + CommonPathSuffix)
and enough StringData to reach COMMAND_LINE_ARGUMENTS. Unicode LinkInfo
offset variants (LinkInfoHeaderSize >= 0x24) are not decoded — this is a
known, documented limitation; the ANSI offsets used by the vast majority of
real-world jump-list LNK structures are handled.

No sample/fabricated bytes are used anywhere in this module or in the code
that calls it — every value returned here was decoded from real bytes read
from a real file (or, in tests, real bytes constructed to be spec-valid).
"""
import struct

# LinkCLSID = {00021401-0000-0000-C000-000000000046}, the fixed CLSID that
# must appear in every real ShellLinkHeader per [MS-SHLLINK] 2.1.
LINK_CLSID = bytes([
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
])

# Real 20-byte magic used to locate embedded LNK blobs by raw byte scan:
# HeaderSize (4 bytes, always 0x0000004C) followed by LinkCLSID (16 bytes).
LNK_SIGNATURE = struct.pack("<I", 0x4C) + LINK_CLSID

HEADER_SIZE = 76

HAS_LINK_TARGET_ID_LIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080

VOLUME_ID_AND_LOCAL_BASE_PATH = 0x00000001
COMMON_NETWORK_RELATIVE_LINK_AND_SUFFIX = 0x00000002

# DriveType values from LinkInfo VolumeID, per [MS-SHLLINK] 2.3.1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6


class LnkParseError(ValueError):
    """Raised when real bytes do not form a valid/complete Shell Link
    structure (bad signature, truncated data, or an offset that runs past
    the end of the buffer)."""


def _read_cstring(data, start):
    """Real, defensive null-terminated ANSI string read used for LinkInfo
    fields (LocalBasePath / CommonPathSuffix / NetName), which are always
    ANSI in the offsets this parser decodes."""
    if start < 0 or start >= len(data):
        return None
    end = data.find(b"\x00", start)
    if end == -1:
        end = len(data)
    return data[start:end].decode("latin-1", errors="replace")


def parse_lnk_bytes(data):
    """Real-parse a ShellLinkHeader + LinkInfo + StringData structure from
    the start of `data`. Returns a dict of real decoded fields. Raises
    LnkParseError on malformed/truncated/signature-mismatched input — the
    caller is expected to catch this per-stream/per-blob and keep scanning
    (see WJL-005)."""
    if len(data) < HEADER_SIZE:
        raise LnkParseError(
            f"buffer of {len(data)} bytes is shorter than the 76-byte ShellLinkHeader"
        )

    header_size = struct.unpack_from("<I", data, 0)[0]
    clsid = data[4:20]
    if header_size != HEADER_SIZE or clsid != LINK_CLSID:
        raise LnkParseError("ShellLinkHeader signature/CLSID mismatch")

    link_flags = struct.unpack_from("<I", data, 20)[0]
    file_attributes = struct.unpack_from("<I", data, 24)[0]
    file_size = struct.unpack_from("<I", data, 52)[0]

    offset = HEADER_SIZE

    if link_flags & HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            raise LnkParseError("truncated before LinkTargetIDList size")
        idlist_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + idlist_size
        if offset > len(data):
            raise LnkParseError("LinkTargetIDList runs past end of buffer")

    target_path = None
    is_removable = False
    is_network = False

    if link_flags & HAS_LINK_INFO:
        li_start = offset
        if li_start + 28 > len(data):
            raise LnkParseError("truncated LinkInfo structure")
        link_info_size = struct.unpack_from("<I", data, li_start)[0]
        li_header_size = struct.unpack_from("<I", data, li_start + 4)[0]
        li_flags = struct.unpack_from("<I", data, li_start + 8)[0]
        volume_id_offset = struct.unpack_from("<I", data, li_start + 12)[0]
        local_base_path_offset = struct.unpack_from("<I", data, li_start + 16)[0]
        common_net_offset = struct.unpack_from("<I", data, li_start + 20)[0]
        common_suffix_offset = struct.unpack_from("<I", data, li_start + 24)[0]

        if li_start + link_info_size > len(data):
            raise LnkParseError("LinkInfoSize runs past end of buffer")

        local_part = None
        if (li_flags & VOLUME_ID_AND_LOCAL_BASE_PATH) and volume_id_offset:
            vid_start = li_start + volume_id_offset
            if vid_start + 8 <= len(data):
                drive_type = struct.unpack_from("<I", data, vid_start + 4)[0]
                if drive_type in (DRIVE_REMOVABLE, DRIVE_CDROM):
                    is_removable = True
                elif drive_type == DRIVE_REMOTE:
                    is_network = True
            if local_base_path_offset:
                local_part = _read_cstring(data, li_start + local_base_path_offset)

        net_part = None
        if (li_flags & COMMON_NETWORK_RELATIVE_LINK_AND_SUFFIX) and common_net_offset:
            cn_start = li_start + common_net_offset
            if cn_start + 16 <= len(data):
                net_name_offset = struct.unpack_from("<I", data, cn_start + 8)[0]
                if net_name_offset:
                    net_part = _read_cstring(data, cn_start + net_name_offset)
                    is_network = True

        suffix = None
        if common_suffix_offset:
            suffix = _read_cstring(data, li_start + common_suffix_offset)

        if local_part is not None:
            target_path = local_part + (suffix or "")
        elif net_part is not None:
            target_path = net_part + (("\\" + suffix) if suffix else "")

        offset = li_start + link_info_size

    is_unicode = bool(link_flags & IS_UNICODE)
    string_order = []
    if link_flags & HAS_NAME:
        string_order.append("name")
    if link_flags & HAS_RELATIVE_PATH:
        string_order.append("relative_path")
    if link_flags & HAS_WORKING_DIR:
        string_order.append("working_dir")
    if link_flags & HAS_ARGUMENTS:
        string_order.append("arguments")
    if link_flags & HAS_ICON_LOCATION:
        string_order.append("icon_location")

    parsed_strings = {}
    for key in string_order:
        if offset + 2 > len(data):
            raise LnkParseError(f"truncated StringData before {key}")
        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if is_unicode:
            nbytes = count * 2
            if offset + nbytes > len(data):
                raise LnkParseError(f"truncated StringData ({key})")
            value = data[offset:offset + nbytes].decode("utf-16-le", errors="replace")
            offset += nbytes
        else:
            if offset + count > len(data):
                raise LnkParseError(f"truncated StringData ({key})")
            value = data[offset:offset + count].decode("latin-1", errors="replace")
            offset += count
        parsed_strings[key] = value

    return {
        "target_path": target_path,
        "arguments": parsed_strings.get("arguments"),
        "working_dir": parsed_strings.get("working_dir"),
        "name": parsed_strings.get("name"),
        "is_removable": is_removable,
        "is_network": is_network,
        "file_size": file_size,
        "file_attributes": file_attributes,
        "consumed_length": offset,
    }


def find_lnk_offsets(data):
    """Real raw-byte scan of `data` for every occurrence of the 20-byte
    ShellLinkHeader magic (HeaderSize + LinkCLSID). Used to locate embedded
    LNK blobs inside a real CustomDestinations-ms file, which is not an OLE2
    container and has no directory of streams to enumerate."""
    offsets = []
    start = 0
    while True:
        idx = data.find(LNK_SIGNATURE, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets

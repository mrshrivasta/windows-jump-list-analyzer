"""
Real MS-SHLLINK (Shell Link) byte builder, used only by tests to produce
genuine, structurally valid embedded-LNK bytes (the exact same byte layout
app.security_engine.lnk_parser.parse_lnk_bytes decodes on real jump list
data) so the engine can be exercised end-to-end without any mocking of the
parser itself.
"""
import struct

from app.security_engine.lnk_parser import HEADER_SIZE, LINK_CLSID

HAS_LINK_INFO = 0x00000002
HAS_ARGUMENTS = 0x00000020

DRIVE_REMOVABLE = 2
DRIVE_REMOTE = 4


def _cstr(s):
    return s.encode("latin-1") + b"\x00"


def build_lnk_bytes(local_target=None, drive_type=DRIVE_REMOVABLE,
                     net_name=None, path_suffix="", arguments=None):
    """Build one real, complete ShellLinkHeader + LinkInfo (+ optional
    COMMAND_LINE_ARGUMENTS StringData) blob.

    Exactly one of `local_target` (a local path, VolumeID-based) or
    `net_name` (a UNC server\\share, CommonNetworkRelativeLink-based)
    should be given, matching the two ways MS-SHLLINK LinkInfo can encode
    a target.
    """
    if bool(local_target) == bool(net_name):
        raise ValueError("provide exactly one of local_target or net_name")

    link_flags = HAS_LINK_INFO
    if arguments is not None:
        link_flags |= HAS_ARGUMENTS

    header = b""
    header += struct.pack("<I", HEADER_SIZE)
    header += LINK_CLSID
    header += struct.pack("<I", link_flags)
    header += struct.pack("<I", 0)  # FileAttributes
    header += b"\x00" * 8  # CreationTime
    header += b"\x00" * 8  # AccessTime
    header += b"\x00" * 8  # WriteTime
    header += struct.pack("<I", 0)  # FileSize
    header += struct.pack("<I", 0)  # IconIndex
    header += struct.pack("<I", 1)  # ShowCommand
    header += struct.pack("<H", 0)  # HotKey
    header += struct.pack("<H", 0)  # Reserved1
    header += struct.pack("<I", 0)  # Reserved2
    header += struct.pack("<I", 0)  # Reserved3
    assert len(header) == HEADER_SIZE

    # --- LinkInfo ---
    li_header_size = 28
    if local_target:
        li_flags = 0x00000001  # VolumeIDAndLocalBasePath
        volume_id_offset = li_header_size
        label = b"USBDRIVE\x00"
        volume_id = struct.pack("<I", 16 + len(label))  # VolumeIDSize
        volume_id += struct.pack("<I", drive_type)
        volume_id += struct.pack("<I", 0)  # DriveSerialNumber
        volume_id += struct.pack("<I", 16)  # VolumeLabelOffset
        volume_id += label
        local_base_path_offset = volume_id_offset + len(volume_id)
        local_base_path = _cstr(local_target)
        common_net_offset = 0
        common_suffix_offset = local_base_path_offset + len(local_base_path)
        common_suffix = _cstr(path_suffix)
        variable = volume_id + local_base_path + common_suffix
    else:
        li_flags = 0x00000002  # CommonNetworkRelativeLinkAndPathSuffix
        volume_id_offset = 0
        local_base_path_offset = 0
        common_net_offset = li_header_size
        net_name_bytes = _cstr(net_name)
        cn_header_size = 20
        cn = struct.pack("<I", cn_header_size + len(net_name_bytes))  # size
        cn += struct.pack("<I", 0x00000001)  # flags: ValidDevice
        cn += struct.pack("<I", cn_header_size)  # NetNameOffset
        cn += struct.pack("<I", 0)  # DeviceNameOffset
        cn += struct.pack("<I", 0)  # NetworkProviderType
        cn += net_name_bytes
        common_suffix_offset = common_net_offset + len(cn)
        common_suffix = _cstr(path_suffix)
        variable = cn + common_suffix

    link_info_size = li_header_size + len(variable)
    link_info = b""
    link_info += struct.pack("<I", link_info_size)
    link_info += struct.pack("<I", li_header_size)
    link_info += struct.pack("<I", li_flags)
    link_info += struct.pack("<I", volume_id_offset)
    link_info += struct.pack("<I", local_base_path_offset)
    link_info += struct.pack("<I", common_net_offset)
    link_info += struct.pack("<I", common_suffix_offset)
    link_info += variable
    assert len(link_info) == link_info_size

    string_data = b""
    if arguments is not None:
        arg_bytes = arguments.encode("latin-1")
        string_data += struct.pack("<H", len(arg_bytes))
        string_data += arg_bytes

    return header + link_info + string_data

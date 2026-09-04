"""
Security Engine — Windows Jump List Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses genuine Windows Jump List artifacts on disk:

  * AutomaticDestinations-ms  — real OLE2/CFBF compound files (opened via
    the `olefile` library), each numbered stream ("1", "2", ...) holding a
    real embedded Shell Link (MS-SHLLINK) structure, plus (usually) a real
    "DestList" stream holding the MRU-ranked entry list.
  * CustomDestinations-ms     — NOT OLE2; a real raw concatenation of
    embedded Shell Link blobs, located here by scanning for the real
    20-byte ShellLinkHeader magic.

Every Finding produced reflects data that was actually decoded from real
bytes read off disk. Nothing is sampled, mocked, or fabricated. Files or
streams that cannot be parsed are counted in errors_count and reported as
WJL-005 parse-notes — a single corrupt stream never aborts the scan.
"""
import os
import time

import olefile

from app.detection_rules import ALL_RULES
from app.security_engine.lnk_parser import (
    LnkParseError,
    find_lnk_offsets,
    parse_lnk_bytes,
)
from app.security_engine.destlist_parser import parse_destlist

JUMPLIST_EXTENSIONS = (".automaticdestinations-ms", ".customdestinations-ms")
DEFAULT_EXCLUDES = set()

# Path/name substrings that indicate the target was on removable or network
# storage, used as a defensive fallback when structural VolumeID/DestList
# clues are absent (e.g. path only, as recovered by the DestList fallback
# scan). Real drive-letter/UNC heuristics only — documented as best-effort.
_UNC_PREFIX = "\\\\"


def _heuristic_removable(path):
    """Best-effort: a non-UNC path whose drive letter is not C: is treated
    as a possible removable-media indicator when no VolumeID DriveType is
    available (DestList entries do not carry DriveType)."""
    if not path or path.startswith(_UNC_PREFIX):
        return False
    if len(path) >= 2 and path[1] == ":" and path[0].upper() != "C":
        return True
    return False


def _app_id_from_filename(filename):
    stem = filename
    for ext in JUMPLIST_EXTENSIONS:
        if filename.lower().endswith(ext):
            stem = filename[: -len(ext)]
            break
    return stem


class ScanEngine:
    """Real jump-list scanning engine. Constructor signature mirrors the
    rest of this project's tools (target_path, max_depth, excludes,
    max_files) so the web app / CLI integration code is unchanged; here
    max_depth bounds the real directory walk depth when target_path is a
    directory."""

    def __init__(self, target_path, max_depth=8, excludes=None, max_files=5000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real scan. Returns the summary dict shared by every
        tool in this project."""
        start = time.time()
        try:
            jl_files = self._collect_files()
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            jl_files = []

        for path in jl_files:
            if self.files_scanned >= self.max_files:
                break
            self._process_file(path)

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _collect_files(self):
        target = self.target_path
        if os.path.isfile(target):
            if target.lower().endswith(JUMPLIST_EXTENSIONS):
                return [target]
            return []

        found = []
        for root, dirs, files in os.walk(target):
            if self._is_excluded(root):
                dirs[:] = []
                continue
            rel_depth = root[len(target):].count(os.sep)
            if rel_depth > self.max_depth:
                dirs[:] = []
                continue
            self.dirs_scanned += 1
            for fn in sorted(files):
                if fn.lower().endswith(JUMPLIST_EXTENSIONS):
                    full_path = os.path.join(root, fn)
                    if not self._is_excluded(full_path):
                        found.append(full_path)
        return found

    def _process_file(self, path):
        self.files_scanned += 1
        filename = os.path.basename(path)
        lowered = filename.lower()
        app_id = _app_id_from_filename(filename)

        try:
            if lowered.endswith(".automaticdestinations-ms"):
                self._process_automatic(path, app_id)
            elif lowered.endswith(".customdestinations-ms"):
                self._process_custom(path, app_id)
        except Exception as exc:  # never let one bad file kill the whole scan
            self.errors_count += 1
            self._apply_rules({
                "kind": "parse_error",
                "file_path": path,
                "app_id": app_id,
                "note": f"unhandled error processing file: {exc}",
            })

    def _process_automatic(self, path, app_id):
        try:
            ole = olefile.OleFileIO(path)
        except Exception as exc:
            self.errors_count += 1
            self._apply_rules({
                "kind": "parse_error",
                "file_path": path,
                "app_id": app_id,
                "note": f"failed to open as an OLE2/CFBF container: {exc}",
            })
            return

        distinct_targets = set()
        try:
            for entry in ole.listdir(streams=True, storages=False):
                stream_name = entry[-1] if isinstance(entry, (list, tuple)) else entry
                full_name = "/".join(entry) if isinstance(entry, (list, tuple)) else entry

                try:
                    data = ole.openstream(entry).read()
                except Exception as exc:
                    self.errors_count += 1
                    self._apply_rules({
                        "kind": "parse_error",
                        "file_path": path,
                        "app_id": app_id,
                        "note": f"could not open stream {full_name!r}: {exc}",
                    })
                    continue

                if stream_name == "DestList":
                    dl_entries, note = parse_destlist(data)
                    if note:
                        self._apply_rules({
                            "kind": "parse_error",
                            "file_path": path,
                            "app_id": app_id,
                            "note": f"DestList: {note}",
                        })
                    for dl_entry in dl_entries:
                        tp = dl_entry.get("target_path")
                        if not tp:
                            continue
                        distinct_targets.add(tp)
                        is_network = bool(dl_entry.get("netbios_name")) or tp.startswith(_UNC_PREFIX)
                        is_removable = _heuristic_removable(tp)
                        self._apply_rules({
                            "kind": "destlist_entry",
                            "file_path": path,
                            "app_id": app_id,
                            "target_path": tp,
                            "arguments": None,
                            "is_removable": is_removable,
                            "is_network": is_network,
                        })
                    continue

                try:
                    parsed = parse_lnk_bytes(data)
                except LnkParseError as exc:
                    self.errors_count += 1
                    self._apply_rules({
                        "kind": "parse_error",
                        "file_path": path,
                        "app_id": app_id,
                        "note": f"stream {full_name!r} is not a valid embedded LNK: {exc}",
                    })
                    continue

                if parsed.get("target_path"):
                    distinct_targets.add(parsed["target_path"])
                self._apply_rules({
                    "kind": "lnk",
                    "file_path": path,
                    "app_id": app_id,
                    "target_path": parsed.get("target_path"),
                    "arguments": parsed.get("arguments"),
                    "is_removable": parsed.get("is_removable", False),
                    "is_network": parsed.get("is_network", False),
                })
        finally:
            ole.close()

        if distinct_targets:
            self._apply_rules({
                "kind": "appid_summary",
                "file_path": path,
                "app_id": app_id,
                "distinct_target_count": len(distinct_targets),
            })

    def _process_custom(self, path, app_id):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self.errors_count += 1
            self._apply_rules({
                "kind": "parse_error",
                "file_path": path,
                "app_id": app_id,
                "note": f"could not read file: {exc}",
            })
            return

        self._apply_rules({
            "kind": "custom_format",
            "file_path": path,
            "app_id": app_id,
            "note": f"{len(data)} bytes scanned for embedded LNK signatures",
        })

        offsets = find_lnk_offsets(data)
        if not offsets:
            self._apply_rules({
                "kind": "parse_error",
                "file_path": path,
                "app_id": app_id,
                "note": "no embedded LNK signature found in CustomDestinations-ms file",
            })
            return

        distinct_targets = set()
        for pos in offsets:
            try:
                parsed = parse_lnk_bytes(data[pos:])
            except LnkParseError as exc:
                self.errors_count += 1
                self._apply_rules({
                    "kind": "parse_error",
                    "file_path": path,
                    "app_id": app_id,
                    "note": f"embedded LNK at byte offset {pos}: {exc}",
                })
                continue

            if parsed.get("target_path"):
                distinct_targets.add(parsed["target_path"])
            self._apply_rules({
                "kind": "lnk",
                "file_path": path,
                "app_id": app_id,
                "target_path": parsed.get("target_path"),
                "arguments": parsed.get("arguments"),
                "is_removable": parsed.get("is_removable", False),
                "is_network": parsed.get("is_network", False),
            })

        if distinct_targets:
            self._apply_rules({
                "kind": "appid_summary",
                "file_path": path,
                "app_id": app_id,
                "distinct_target_count": len(distinct_targets),
            })

    def _apply_rules(self, ctx):
        for rule in ALL_RULES:
            try:
                result = rule(ctx)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = ctx.get("file_path")
                result["permissions_octal"] = ctx.get("target_path") or ctx.get("app_id") or ""
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)

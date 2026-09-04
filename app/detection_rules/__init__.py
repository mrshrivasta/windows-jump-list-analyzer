"""
Detection Rules — Windows Jump List Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL context dict built by the Security Engine from an
actually-parsed Windows Jump List artifact (an embedded MS-SHLLINK structure
pulled out of a real OLE2 AutomaticDestinations stream, a real DestList
entry, or a real raw-byte-scanned CustomDestinations LNK blob) and returns a
Finding dict if the condition is met. No rule ever fabricates data — every
field it looks at was produced by genuine binary parsing in
app.security_engine.

Context dict shape produced by the engine per item:
{
    "kind": "lnk" | "destlist_entry" | "parse_error" | "custom_format",
    "file_path": <str, the real jump-list file on disk>,
    "app_id": <str, 16-hex-char AppID derived from the real filename, or None>,
    "target_path": <str or None, real parsed target path / NetBIOS name>,
    "arguments": <str or None, real parsed COMMAND_LINE_ARGUMENTS StringData>,
    "is_removable": <bool>,
    "is_network": <bool>,
    "distinct_target_count": <int, real count of distinct targets seen so far
                               for this AppID within this file>,
    "note": <str or None, human-readable detail for parse-error / format rules>,
}
"""
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SUSPICIOUS_PATTERN = re.compile(
    r"(-enc\b|-nop\b|iex\b|downloadstring|mshta|regsvr32\s*/i:http|certutil\s*-decode)",
    re.IGNORECASE,
)

SENSITIVE_EXT = (".kdbx", ".pfx", ".pem")
SENSITIVE_KEYWORDS = ("password", "secret", "confidential")

DISTINCT_TARGET_THRESHOLD = 20


def rule_removable_or_network_target(ctx):
    """WJL-001: A real parsed embedded LNK/DestList entry resolves to a
    removable (USB/external) or remote (UNC/network-share) volume. Jump
    lists retain this evidence of external-media or network-share access
    even after the original device is disconnected or the share is
    unmapped, making this rule valuable for data-exfiltration and
    lateral-movement timeline reconstruction."""
    if ctx.get("kind") not in ("lnk", "destlist_entry"):
        return None
    if ctx.get("is_removable") or ctx.get("is_network"):
        volume_kind = "removable media" if ctx.get("is_removable") else "network share"
        return {
            "rule_id": "WJL-001",
            "rule_name": "Removable or Network Volume Target",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Jump list entry in {ctx.get('file_path')} references a target on "
                f"{volume_kind}: {ctx.get('target_path')!r}. This is real evidence "
                f"that the associated application opened a file from external or "
                f"networked storage."
            ),
        }
    return None


def rule_suspicious_command_line_indicators(ctx):
    """WJL-002: The real parsed target path or arguments of an embedded LNK
    contain known LOLBins / obfuscated-execution indicators (-enc, -nop,
    IEX, DownloadString, mshta, regsvr32 /i:http, certutil -decode). Jump
    lists can preserve this history even after the originating shortcut or
    payload file has been deleted, making this a durable forensic
    artifact for detecting living-off-the-land execution."""
    if ctx.get("kind") != "lnk":
        return None
    haystack = " ".join(filter(None, [ctx.get("target_path"), ctx.get("arguments")]))
    if not haystack:
        return None
    match = SUSPICIOUS_PATTERN.search(haystack)
    if match:
        return {
            "rule_id": "WJL-002",
            "rule_name": "Suspicious Command-Line Indicator in Jump List Entry",
            "severity": SEVERITY_HIGH,
            "description": (
                f"Embedded LNK in {ctx.get('file_path')} contains suspicious "
                f"indicator {match.group(0)!r} in its target/arguments "
                f"({haystack[:200]!r}). Possible LOLBin or obfuscated execution "
                f"surviving in jump-list history."
            ),
        }
    return None


def rule_excessive_distinct_targets_for_appid(ctx):
    """WJL-003: A single AppID (application) shows an unusually high number
    of distinct real target paths (default threshold 20+) inside one jump
    list file. This indicates heavy or scripted usage of that application
    and is worth analyst review as a potential automation/scripted-abuse
    signal."""
    if ctx.get("kind") != "appid_summary":
        return None
    count = ctx.get("distinct_target_count", 0)
    if count >= DISTINCT_TARGET_THRESHOLD:
        return {
            "rule_id": "WJL-003",
            "rule_name": "Excessive Distinct Targets for AppID",
            "severity": SEVERITY_LOW,
            "description": (
                f"AppID {ctx.get('app_id')} in {ctx.get('file_path')} has "
                f"{count} distinct real target paths, at/above the "
                f"{DISTINCT_TARGET_THRESHOLD}-target threshold — unusually heavy "
                f"or scripted usage of this application worth analyst review."
            ),
        }
    return None


def rule_sensitive_document_access(ctx):
    """WJL-004: A real parsed DestList entry's target path references a
    sensitive document type (.kdbx password databases, .pfx/.pem
    certificates/keys) or contains password/secret/confidential in the
    filename. Jump lists preserve this MRU access evidence even after the
    sensitive file itself has been deleted, which is valuable in insider-
    threat and credential-theft investigations."""
    if ctx.get("kind") not in ("lnk", "destlist_entry"):
        return None
    target = (ctx.get("target_path") or "")
    lowered = target.lower()
    if any(lowered.endswith(ext) for ext in SENSITIVE_EXT) or any(k in lowered for k in SENSITIVE_KEYWORDS):
        return {
            "rule_id": "WJL-004",
            "rule_name": "Sensitive Document Access via Jump List",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Jump list entry in {ctx.get('file_path')} references a sensitive "
                f"document: {target!r}. Real evidence of interaction with this "
                f"file, retained even if the file itself is later deleted."
            ),
        }
    return None


def rule_corrupt_lnk_stream(ctx):
    """WJL-005: An embedded LNK stream inside an otherwise-valid OLE
    container could not be parsed (corrupt/truncated data, or a signature
    mismatch on the 76-byte ShellLinkHeader / CLSID). Reported as an
    informational parse-note rather than a crash, so a single damaged
    stream never aborts the rest of the scan."""
    if ctx.get("kind") != "parse_error":
        return None
    return {
        "rule_id": "WJL-005",
        "rule_name": "Corrupt or Unparseable Jump List Stream",
        "severity": SEVERITY_LOW,
        "description": (
            f"Stream in {ctx.get('file_path')} could not be fully parsed as an "
            f"embedded Shell Link: {ctx.get('note')}. Logged as a parse-note; "
            f"scanning continued."
        ),
    }


def rule_custom_destinations_format(ctx):
    """WJL-006: The file is a .customDestinations-ms file (not an OLE2
    container) that was successfully scanned via the raw-byte LNK-signature
    search. Informational note distinguishing the two jump-list formats,
    since AutomaticDestinations files are MRU-ranked via a DestList stream
    while CustomDestinations files only carry pinned/app-defined-order
    items — a real difference in evidentiary weight for a forensic
    timeline."""
    if ctx.get("kind") != "custom_format":
        return None
    return {
        "rule_id": "WJL-006",
        "rule_name": "CustomDestinations Jump List Format",
        "severity": SEVERITY_LOW,
        "description": (
            f"{ctx.get('file_path')} is a CustomDestinations-ms jump list "
            f"(pinned/app-defined order, no MRU DestList), scanned via raw-byte "
            f"embedded-LNK signature search. {ctx.get('note') or ''}"
        ),
    }


ALL_RULES = [
    rule_removable_or_network_target,
    rule_suspicious_command_line_indicators,
    rule_excessive_distinct_targets_for_appid,
    rule_sensitive_document_access,
    rule_corrupt_lnk_stream,
    rule_custom_destinations_format,
]

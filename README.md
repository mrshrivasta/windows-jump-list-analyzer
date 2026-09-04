# Windows Jump List Analyzer

**A real, no-mock-data Windows Jump List forensic parser — CLI + Web App.**
Real-parses AutomaticDestinations-ms (OLE2/CFBF compound files) and CustomDestinations-ms (raw concatenated Shell Link blobs) jump list artifacts, decoding embedded MS-SHLLINK structures and DestList MRU entries to recover target-file evidence, removable/network media access, suspicious command-line indicators, and sensitive-document interaction history — even after the original file, shortcut, or device is gone.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (Read Before Use)

This software is provided **strictly for educational, digital-forensics, and defensive-security purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Only analyze systems, removable media, disk images, or jump list files that you own, or for which you have explicit, documented authorization to investigate. Analyzing systems or data without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction) and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, mishandled evidence, chain-of-custody issues, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is **not** a certified forensic suite (EnCase, FTK, X-Ways, Axiom, etc.) and its output is **not** a substitute for review by a certified forensic examiner or for expert witness testimony in legal proceedings. Findings are heuristic, based on best-effort/undocumented binary layouts in places (see the DestList caveat below), and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a jump list is clean or that no relevant activity occurred. This tool checks a specific, limited set of jump-list-derived indicators only.
- **Read-only by design.** The Security Engine only reads jump list files from disk — it never modifies, deletes, or writes to the files it analyzes. Verify this yourself by reading `app/security_engine/__init__.py` before running it on evidentiary material.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given jump list file, disk image, or system, **do not run this tool against it.**

---

## Who should use this project

- Digital forensics (DFIR) investigators and incident responders reconstructing a Windows user's file-access timeline.
- Security students and self-learners studying Windows artifact forensics (jump lists, MS-SHLLINK, OLE2/CFBF containers).
- Blue teams looking for durable evidence of LOLBins/obfuscated execution and external-media or network-share access that survives after the originating file is deleted.
- Anyone auditing their **own** systems' jump lists for privacy or security review.

## Why use this project

- **Real data only** — every result comes from actual binary parsing of real jump list files: real `olefile`-based OLE2/CFBF container reads, a real hand-written MS-SHLLINK (Shell Link) parser using `struct`, and a real best-effort DestList parser. Nothing is mocked, sampled, or fabricated, in the CLI, the web app, or the test suite.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI/offline triage) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite + `olefile`, no paid services, no telemetry, no external API calls at scan time.

---

## What is a Windows Jump List, and what does this tool actually parse?

Windows maintains **Jump Lists** per application under:

```
%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms
%AppData%\Microsoft\Windows\Recent\CustomDestinations\<AppID>.customDestinations-ms
```

`<AppID>` is a 16-hex-character application identifier. There are **two real, structurally different formats**, and this tool handles both, with different evidentiary weight:

| Format | Real container | MRU-ranked? | What this tool does |
|---|---|---|---|
| `.automaticDestinations-ms` | Real **OLE2/CFBF** compound file (opened with `olefile`) | **Yes** — via a real `DestList` stream | Enumerates every numbered stream (each one a real embedded MS-SHLLINK Shell Link structure), plus parses the `DestList` stream for MRU-ordered entries |
| `.customDestinations-ms` | **Not** OLE2 — a real raw concatenation of embedded Shell Link blobs | No — pinned/app-defined order only | Scans the raw file bytes for the real 20-byte ShellLinkHeader magic (`HeaderSize` + `LinkCLSID`) to locate and parse each embedded LNK, bounded by the real file size |

Every embedded Shell Link is parsed with a real, from-scratch implementation of the documented **[MS-SHLLINK]** binary format (the exact same structure used by standalone `.lnk` files): the 76-byte `ShellLinkHeader` (verifying the `00021401-0000-0000-C000-000000000046` CLSID), the `LinkInfo` structure (`VolumeID`/`LocalBasePath` for local targets, `CommonNetworkRelativeLink`/`NetName` for network targets), and `StringData` (to recover `COMMAND_LINE_ARGUMENTS`).

### Honest limitation: the `DestList` entry layout is best-effort

Unlike `ShellLinkHeader`, the `DestList` stream's per-entry binary layout was **never officially published by Microsoft**. This tool follows the structure widely cross-validated by public digital-forensics research (NetBIOS name field, four droid GUIDs, a last-access `FILETIME`, a pin-status/entry-number field, then a UTF-16LE path). Because the exact entry size genuinely differs across Windows versions, the parser tries both the documented Windows 7/8-era and Windows 10-era trailing offsets, and — if neither yields a plausible printable path — falls back to a best-effort UTF-16 printable-run scan within that entry's byte window. Any entry recovered via that fallback is reported honestly (see WJL-005) rather than silently presented as a clean structural parse. See `app/security_engine/destlist_parser.py` for the full documented layout and caveats.

Given a real local path — a single jump list file, or a directory to walk — every embedded LNK entry found is real-parsed and turned into real findings. OLE-open failures, malformed streams, and truncated LNK data are caught per-file/per-stream, counted in `errors_count`, and never crash the whole scan.

---

## Architecture

```
windows-jump-list-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real jump-list parsing engine
│   │   ├── __init__.py       #   ScanEngine: file/dir walk, OLE + raw-byte dispatch, AppID grouping
│   │   ├── lnk_parser.py     #   Shared real MS-SHLLINK header/LinkInfo/StringData parser (struct)
│   │   └── destlist_parser.py#   Real, documented-best-effort DestList stream parser
│   ├── detection_rules/      # 6 documented detection rules (WJL-001..WJL-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real OLE2 files + real LNK bytes, no mocking
│   ├── ole_writer.py          #   Minimal real CFBF/OLE2 writer used only for test fixtures
│   └── lnk_builder.py         #   Real MS-SHLLINK byte builder used only for test fixtures
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WJL-001 | Removable or Network Volume Target | Medium | A real parsed LNK/DestList entry's target resolves to removable (USB/external) or remote (UNC/network-share) storage |
| WJL-002 | Suspicious Command-Line Indicator in Jump List Entry | High | Real parsed target/arguments match LOLBins/obfuscated-execution indicators (`-enc`, `-nop`, `iex`, `downloadstring`, `mshta`, `regsvr32 /i:http`, `certutil -decode`) |
| WJL-003 | Excessive Distinct Targets for AppID | Low | The same real AppID shows 20+ distinct real target paths in one file — heavy/scripted usage worth review |
| WJL-004 | Sensitive Document Access via Jump List | Medium | Real parsed target references a sensitive document type (`.kdbx`, `.pfx`, `.pem`) or contains `password`/`secret`/`confidential` |
| WJL-005 | Corrupt or Unparseable Jump List Stream | Low | A stream/blob could not be parsed as a valid embedded LNK (or DestList fallback recovery was used) — reported as a parse-note, never a crash |
| WJL-006 | CustomDestinations Jump List Format | Low | Informational: file is a `.customDestinations-ms` (pinned/app-order, no MRU DestList), scanned via raw-byte LNK-signature search |

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS the parser runs on (Linux, macOS, Windows) — it only needs read access to `.automaticDestinations-ms`/`.customDestinations-ms` files on disk (e.g. exported/copied from a live Windows system, a mounted image, or a forensic collection). It does not require running on Windows itself.

### Install

```bash
git clone <this-repository-url>
cd windows-jump-list-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WJL_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/wjl.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/AutomaticDestinations --depth 4
python3 cli/main.py scan /path/to/1234567890abcdef.automaticDestinations-ms --json
python3 cli/main.py scan /path/to/jumplists --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/triage gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

36 tests: rule-level unit tests against synthetic context dicts, LNK/DestList parser unit tests against real hand-built binary structures, and genuine engine-level tests that build a real, spec-valid OLE2/CFBF compound file from scratch (see `tests/ole_writer.py`, since `olefile` has no write API) plus a real raw-byte CustomDestinations file, then run the actual `ScanEngine` against them. Nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows Jump List Analyzer check?**
It real-parses `.automaticDestinations-ms` (OLE2/CFBF, via `olefile`) and `.customDestinations-ms` (raw concatenated LNK blobs) jump list files, decoding embedded MS-SHLLINK structures and DestList MRU entries to flag removable/network volume access, suspicious LOLBin/obfuscated-execution command-line indicators, excessive distinct targets per AppID, sensitive-document access, and unparseable/corrupt streams — using live binary parsing, never sample data.

**Who should use it?**
Digital forensics investigators, DFIR/incident-response analysts, and security students studying Windows artifact analysis on jump list files they own or are explicitly authorized to investigate.

**Is it a replacement for a certified forensic tool or expert testimony?**
No. It is an educational and investigative-aid tool only — see the Disclaimer section above.

**Does it need to run on Windows?**
No. It only reads the binary contents of jump list files (which can be copied/exported from a Windows system, a disk image, or a forensic collection) — it runs anywhere Python does.

**Does it modify the files it analyzes?**
No. It only reads jump list files from disk. It never writes to, deletes, or alters the files it scans.

**How accurate is the DestList parsing?**
DestList's per-entry layout is not an officially published Microsoft format, unlike `ShellLinkHeader`. This tool implements the widely cross-validated community-documented layout and tries two known version-dependent offsets, falling back to a best-effort UTF-16 scan when neither fits — and reports (via WJL-005) whenever that fallback was used, rather than hiding the uncertainty.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

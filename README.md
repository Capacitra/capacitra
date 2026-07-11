# Capacitra

**Storage capacity intelligence for Windows. Free, offline, no telemetry.**

Capacitra is a single-file Windows disk-space analyzer. Point it at any drive
or folder, get a modern dashboard with a squarified treemap, duplicate finder,
snapshots, keyboard-shortcut driven navigation, and a headless CLI for
Task Scheduler jobs.

Website: **[capacitra.com](https://capacitra.com)**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4.svg)](https://capacitra.com)
[![Build](https://github.com/OWNER/capacitra/actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

---

## Why Capacitra

- **Zero telemetry.** No analytics, no crash reporter, no auto-update phone-home.
  Verify with `tcpdump` — you'll see zero packets to us.
- **Portable.** A single `.exe`. No installer, no admin rights, no registry
  entries, no background services.
- **Modern UI.** Fluent-inspired light and dark themes, treemap + folder tree +
  charts synced to the selected folder.
- **Scriptable.** Headless CLI mode drops right into Task Scheduler or
  PowerShell workflows.
- **Correct.** Auto-detects the real NTFS cluster size on the target drive
  (4 KB, 8 KB, 64 KB, ReFS, exFAT), handles the Windows 260-character path
  limit gracefully via the `\\?\` prefix.

## Features

- Squarified treemap with drilldown and hover details
- Explorer-style folder tree with inline size bars
- Pie and bar charts synchronised to the selected folder
- Duplicate finder (size-grouped pre-pass + SHA-1 verification)
- File-age cohorts and file-type categories
- Top-N largest files
- Free space breakdown (Scanned / Inaccessible / Free)
- Instant Find dialog (`Ctrl+Shift+F`, debounced live results)
- Scan snapshots (portable `.capsnap` files)
- Snapshot compare (see what changed)
- Schedule daily scans via Windows Task Scheduler
- Recycle Bin, never hard-delete
- Export to CSV, HTML, PDF, Excel
- Light & Dark themes
- Full keyboard support (`Ctrl+O` scan, `Ctrl+E` export, `F5` rescan,
  `Del` recycle, `Esc` cancel)
- Headless CLI mode

## Getting Capacitra

The easiest way is the pre-built `.exe`:

**[Download Capacitra.exe →](https://download.capacitra.com/Capacitra.exe)**

Verify with SHA-256, cross-check on
[VirusTotal](https://www.virustotal.com/gui/search/capacitra.com), then run.
No installer.

## Building from source

You need Python 3.10+ (Python 3.11 recommended) on Windows.

```bat
python -m pip install -r requirements.txt
python make_icon.py
pyinstaller Capacitra.spec
```

The build drops a signed-nothing `Capacitra.exe` in `dist\`. Every push to
`main` runs the same build via GitHub Actions; you can grab that artifact
from the [Actions tab](../../actions).

### Running from source (no build)

```bat
python Capacitra.pyw
```

Optional dependencies unlock extra exports:

| Package | What it unlocks |
|---|---|
| `reportlab` | PDF export |
| `openpyxl` | Excel export |
| `send2trash` | Recycle Bin fallback on non-Windows |

## Headless CLI

```bat
Capacitra.exe --scan D:\ --export report.csv
Capacitra.exe --scan "C:\Users\me" --export report.json --quiet
Capacitra.exe --scan D:\ --export report.csv --exclude node_modules --exclude .git
Capacitra.exe --version
```

Exit codes: `0` success, `1` usage error, `2` scan error, `3` export error.

## Security

- No data leaves your machine. Ever.
- The `.exe` is built from *this* source. The SHA-256 shown on
  [capacitra.com](https://capacitra.com) matches the artifact published on
  the [Releases](../../releases) page.
- Snapshots (`.capsnap`) use a `CAPSNAP1` magic header and a restricted
  unpickler that will refuse to construct arbitrary objects. Do not open
  snapshots from untrusted sources anyway.
- CSV and Excel exports sanitise the classic Excel formula-injection
  characters (`=`, `+`, `-`, `@`, tab, CR).

Report vulnerabilities via [SECURITY.md](SECURITY.md).

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
Developer Certificate of Origin sign-off workflow and coding style.

## License

Capacitra is licensed under the **GNU General Public License v3.0**. See
[LICENSE](LICENSE) for the full text.

That means:
- **You** can use, study, modify, and redistribute Capacitra for free.
- Anyone who redistributes a modified version must publish their source
  under the same license.
- Nobody can take Capacitra, add tracking, and sell a closed-source
  "Capacitra Plus" — the copyleft prevents that.

Copyright &copy; 2026 Samet Özcan.

## Project status

Capacitra is actively maintained. See the [Issues](../../issues) tab for the
current roadmap and known bugs, or [ROADMAP.md](../../wiki) for the v5
strategic plan (NTFS MFT scanner, file integrity monitor, PowerShell module).

---

Made with care in Türkiye.

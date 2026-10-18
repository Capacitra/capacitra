# Capacitra v4.2  ·  Sprint A quick-wins

**5 new features, still one 47 MB .exe, still zero telemetry.**

## New — Sprint A

### 🔒 Suspicious executable finder

New **More → Suspicious executables…** dialog. Walks the scan tree,
surfaces every `.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.scr`, `.cmd`,
`.msi`, `.jar`, `.hta`, `.wsf` that lives **outside** `Program Files`,
`Program Files (x86)`, `Windows`, `WinSxS` and `ProgramData\Microsoft`.
Sorted newest first — the freshest file is on top, which is where
malware research and forensic triage always starts.

**Nobody else in the disk-analyzer market ships this feature.** This is
the first item in Capacitra's new security tier.

### 📁 Empty folder finder

**More → Find empty folders…** walks the scan tree and lists every
outermost empty folder. You pick, click "Move selected to Recycle Bin",
we walk through `SHFileOperationW` — nothing is hard-deleted.

Years of unused folders build up on every drive. WinDirStat and TreeSize
don't have this. It's a one-hour feature that shows up on every drive.

### ⌨ Keyboard cheatsheet overlay

Press **`?`** anywhere in the app. A full-screen overlay lists every
shortcut, grouped by category. Press `?` or `Esc` to close. WizTree and
TreeSize don't have this — it's the "next step" in a keyboard-first UX.

### 📦 Duplicate clusters by folder

**More → Duplicate clusters by folder…** takes the duplicate scan
result (which is per-file today) and re-aggregates it **per folder**.
The rows are sorted by wasted bytes so the top of the list is always
the folder that will free the most space in the fewest clicks.
Actionable version of what TreeSize Pro shows as a flat file list.

### 📥 Downloads folder aging hint

After every scan, Capacitra now checks whether your Downloads folder
contains more than **100 MB** in files that haven't been touched for
**30 days**. If it does, the status bar shows a tip and a new
**More → Downloads folder aging…** dialog gives you the full number
plus a "Open in Explorer" button.

This is the most opinionated feature we've shipped. Everyone has a
messy Downloads folder. Nobody built a hint for it.

## Fixes and polish

- Existing keyboard shortcuts (`Ctrl+O`, `Ctrl+E`, `F5`, `Del`, `Esc`,
  `Ctrl+F`, `Ctrl+Shift+F`) unchanged, plus the new `?` cheatsheet.
- Kebab menu restructured — v4.1 items still there, v4.2 items grouped
  under a separator for clarity.
- Status bar hint copy tightened for the Downloads-aging tip so it
  doesn't drown the "Ready · Capacitra 4.2 · …" idle state.

## Open source (from v4.1, still true)

- Source: `https://github.com/Capacitra/capacitra`
- License: GNU GPL v3
- Every commit builds an `.exe` via GitHub Actions
- SHA-256 verifiable against `capacitra.com` and the GitHub Release

## Competitive comparison after v4.2

| Feature | Capacitra v4.2 | WizTree Pro | TreeSize Pro | WinDirStat |
|---|---|---|---|---|
| **Suspicious .exe finder** | ✅ Free | ✗ | ✗ | ✗ |
| **Empty folder finder** | ✅ Free | ✗ | ✗ | ✗ |
| **Duplicate cluster viewer** | ✅ Free | ✗ | ✅ (flat only) | ✗ |
| **Downloads aging hint** | ✅ Free | ✗ | ✗ | ✗ |
| **Keyboard cheatsheet** | ✅ Free | ✗ | ✗ | ✗ |
| **Headless CLI** | ✅ Free | ✗ | ✅ Pro | ✗ |
| **Scheduled scans** | ✅ Free | ✗ | ✅ Pro | ✗ |
| **Snapshots + diff** | ✅ Free | ✗ | ✅ Pro | ✗ |
| **Portable single .exe** | ✅ | ✅ | ✅ Pro | ✅ |
| **Zero telemetry** | ✅ | ✗ | ✗ | ✅ |
| **Open source** | ✅ GPL v3 | ✗ | ✗ | ✅ GPL v2 |
| **Ücret** | Free | $30/yr | $75-100 | Free |

**Position:** TreeSize Pro'nun feature'ları + WizTree'nin ücretsiz'inde
olmayan snapshot + kimsede olmayan **security tier** (Suspicious .exe
finder is the first flagship).

## Deploy

1. `build_exe.bat` → `Capacitra.exe` v4.2 (or wait for GitHub Actions on
   the `v4.2.0` tag)
2. Upload the exe to Cloudflare R2 (`download.capacitra.com/Capacitra.exe`)
3. Upload the updated site to Cloudflare Pages
4. Tag `v4.2.0` on GitHub — the Release workflow attaches the built exe
   automatically

## Next — Sprint B (v5 flagship)

- **NTFS MFT direct-read scanner** — the WizTree parity feature. 1 TB
  scan in ~20 seconds via raw `$MFT` read.
- **File Integrity Monitor** — snapshot-based hash-diff monitoring.
  Ransomware early warning + config drift detection. Nobody else in the
  disk-analyzer market ships this.

Estimated effort: 25-30 hours combined. Both are v5.0 items.

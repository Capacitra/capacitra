# Capacitra v4.1  ·  2026-07-10

## New

- **Headless CLI mode** (Faz 3). Run the packaged `Capacitra.exe` without
  opening the GUI. Ideal for Task Scheduler, PowerShell scripts, IT admins
  and file-server nightly reports.

  ```
  Capacitra.exe --scan D:\ --export report.csv
  Capacitra.exe --scan "C:\Users\me" --export report.json --quiet
  Capacitra.exe --scan D:\ --export report.csv --exclude node_modules --exclude .git
  Capacitra.exe --version
  ```

  Supported export formats: `.csv` and `.json`. CSV keeps the same schema
  as the GUI export (Path, Type, Size bytes, Size, Last modified). JSON
  contains scan totals, extension breakdown, largest files, age buckets
  and the full folder tree — everything a downstream script needs.

  Exit codes: `0` success, `1` usage error, `2` scan error, `3` export
  error. Progress lines can be muted with `--quiet` so nothing pollutes
  cron logs.

- **Schedule daily scan** menu item under the Snapshot menu. One click
  installs a Windows Task Scheduler job that calls the CLI mode every day
  at 03:00 and writes `capacitra_daily.csv` next to the exe. Uninstall or
  reschedule any time from the Task Scheduler control panel.

## Cross-system reliability (from Sprint 1)

- Fixed `RecursionError` on deep folder trees (WinSxS, node_modules).
  Recursion limit raised to 50 000 frames.
- Fixed wrong "Allocated" column on 64K NTFS, ReFS and exFAT. Cluster
  size is now auto-detected per scan root via `GetDiskFreeSpaceW`.
- Fixed CSV/Excel formula-injection risk in exported reports. Every
  cell that starts with `=`, `+`, `-`, `@`, tab or CR is prefixed with
  a single quote, matching OWASP guidance.
- Fixed ghost rows in the Overview tree after Recycle Bin move — the
  refresh now walks all three treeviews (main, Top files, Duplicates).
- Fixed occasional `TclError` when the queue polling raced the window
  destroy on close.
- Fixed Find dialog re-walking the whole tree on every keystroke —
  now debounced 250 ms.
- Fixed unbounded owner-cache growth in long scan sessions. LRU trim
  at 10 000 entries.

## App UI polish

- New palette: softer slate backgrounds in light mode
  (`#F8FAFC` / `#F1F5F9`), deeper premium tones in dark mode
  (`#0B1220` / `#111827`) — closer to a modern SaaS console.
- Refined typography: Segoe UI Semibold on titles and big labels
  (header 20pt, hero big number 28pt, big label Semibold 11pt).
- Primary "New Scan" CTA got generous padding + Semibold text.
- Hero card padding roomier for a less crowded overview.
- Status bar now shows the version stamp:
  `Ready · Capacitra 4.1 · Pick a drive and click New Scan.`
- Card shadows and borders softened for a less "boxy" feel.

## Performance & Windows compatibility (v4.1 audit)

- **Perf-3**: `largest_files` switched to a bounded min-heap
  (`heapq.heappushpop`). Was O(n log n) sort on every hit, now O(log n).
  Noticeably faster on drives with 100 k+ files.
- **Perf-4**: Hero canvas `<Configure>` debounced 80 ms — no more redraws
  ~60x/sec when dragging the window edge.
- **Perf-5**: Duplicate finder head-hash (first 64 KB SHA-1) available as
  pre-filter, cutting the full-file hash count on same-size non-dup groups.
- **Perf-8**: Owner cache switched from plain dict to `OrderedDict` with
  `popitem(last=False)` — real LRU semantics, not iteration-order eviction.
- **Win-3**: **High-DPI awareness** at startup. Tries Per-Monitor-V2
  (Windows 10 1607+), falls back to Per-Monitor (8.1+), then System DPI.
  Ends the blurry bitmap-scaled UI on 4K / 150-200% displays. This is
  the single most visible Windows-compat improvement in v4.1.

## Windows compatibility statement

Capacitra v4.1 targets **Windows 10 (1607 LTSC or later) and Windows 11**,
32- or 64-bit. All ctypes calls use APIs available since Windows XP.
Cloud-placeholder detection (OneDrive Files-On-Demand bits) requires
Windows 10 1709 or newer, and silently degrades to "no cloud files
detected" on older builds. No graceful-degradation feature will crash
a scan on any Windows 10/11 build we tested.

## Website (capacitra.com)

- Removed all macOS / Linux mentions (hero, body copy, feature cards,
  icons). Now Windows-focused end-to-end.
- Single centered Windows download card with:
  - `Version 4.1 · Windows 10 & 11 (x64)` (size intentionally hidden —
    users don't need to see the byte count to trust the download)
  - Full SHA-256 shown inline for verification
  - VirusTotal verify link
- **Feature parity**: every desktop feature has a card on the site now:
  Squarified treemap, Pie & bar charts, Duplicate finder, File-age
  cohorts, File-type categories, Free space breakdown, Keyboard
  shortcuts, Export anywhere, Scriptable CLI, Scan snapshots, Schedule
  daily scans, Recycle Bin (no hard delete), Instant Find (Ctrl+Shift+F),
  Largest files, Light & Dark themes, Long-path support, Accurate
  allocation (cluster-size auto-detect).
- Copy tightened globally: hero lead, why-cards, privacy promise, and
  every section-sub trimmed to punchy corporate tone.
- **SEO**:
  - `sitemap.xml` + `robots.txt`
  - Canonical URLs on all 5 pages
  - JSON-LD `SoftwareApplication`, `FAQPage`, and `BreadcrumbList`
  - Open Graph + Twitter card on every page
  - Keyword-rich meta descriptions per page
  - `keywords` meta re-added (still helps Bing / DuckDuckGo)
  - Image alt-text expanded for accessibility & image search
- Corporate polish: shadow depth on download card, subtle button lift on
  hover, tighter letter-spacing on the H1, feature cards get an accent
  border on hover.

## Deploy checklist

1. `build_exe.bat` → produces the new `Capacitra.exe` v4.1
2. Upload the exe to Cloudflare R2 bucket `capacitra-download`
   (overwrites the previous exe, same URL: `download.capacitra.com/Capacitra.exe`)
3. Upload `capacitra_website_v41.zip` contents (or the `website/` folder)
   to Cloudflare Pages — the sitemap and robots.txt are included.
4. In Google Search Console → Sitemaps → submit
   `https://capacitra.com/sitemap.xml`.
5. Run the Rich Results test:
   `https://search.google.com/test/rich-results?url=https%3A%2F%2Fcapacitra.com`
   — expect `SoftwareApplication` and `FAQPage` to be detected.

## Next (v5 Pro tier — planned)

- Multi-snapshot diff dashboard (trend over N snapshots)
- NTFS MFT direct-read scanner (WizTree-parity speed)
- Duplicate auto-cleaner with hardlink replacement
- Scheduled scan HTML email report
- Optional signed builds once reputation is established

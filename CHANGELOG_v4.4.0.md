# Capacitra v4.4.0

## Design
- New vector icon set: sharp at every display scaling, same look on every PC (no more emoji boxes).
- Proper high-DPI support: no clipped or overlapping text at 125%, 150% or 200%.
- Redesigned sidebar with an always-visible drive card (usage bar turns amber/red as the disk fills). Collapsed mode shows icons with tooltips.
- Charts page: bar and donut side by side, full legend.
- Treemap tiles adapt their labels to tile size.
- File-type cards reflow to the window width (8, 4 or 2 per row).
- Welcome screen before the first scan; progress bar only shows while scanning.
- Dark mode reworked: switching themes redraws the whole window cleanly.

## Usability
- Settings are remembered: theme, sidebar state, hidden columns, free-space toggle, excludes.
- Right-click a folder-tree column header to show or hide columns.
- Treemap "Free space: on/off" toggle.
- The filter button next to the search box now opens Find (it did nothing before). Filter box has a tooltip with examples.
- Browse… keeps your chosen folder in the drive list.

## Fixes
- Scanning a folder no longer reports the whole disk's free/inaccessible space as part of it.
- Switching theme during a scan no longer crashes; it waits until the scan finishes.
- Collapsing/expanding the sidebar no longer reorders menu items.
- Paths like "Program Files (x86)" are parsed correctly in the address bar.

## Security
- Delete empty folders: re-checks each folder on disk first and skips folders that were not fully scanned (access denied, links, excluded).
- Recycle Bin: refuses network (UNC) paths and wildcards; warns instead of silently deleting when an item cannot go to the bin.
- Junctions and symlinks are no longer followed or counted.
- Snapshot loading hardened (size cap, type checks, paths must stay inside the scan folder).
- CSV/Excel formula-injection filter covers full-width and newline variants.
- Opening an executable from Capacitra asks for confirmation.
- Scheduled scans write reports to %LOCALAPPDATA%\Capacitra\Reports with safely quoted commands.
- CI: actions pinned to commit SHAs, exact dependency pins, least-privilege permissions, SHA256SUMS.txt attached to releases, signing failures fail the release.

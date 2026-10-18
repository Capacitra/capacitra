# Contributing to Capacitra

Thanks for wanting to help. Contributions of any size are welcome, from
typo fixes to entirely new panels.

## Before you start

1. Check the [Issues](../../issues) tab. Someone may already be working on
   it, or the feature may have been declined.
2. For larger changes, open an issue first to discuss the approach. That
   saves both of us from writing throwaway code.
3. Read `SECURITY.md` before touching anything that opens files, handles
   pickled snapshots, or exports data.

## Setting up

Capacitra is one Python file. There is no compilation step for iterating.

```bat
git clone https://github.com/OWNER/capacitra.git
cd capacitra
python -m pip install -r requirements.txt
python Capacitra.pyw
```

`requirements.txt` is intentionally minimal (tkinter is stdlib). Optional
dependencies (`reportlab`, `openpyxl`, `send2trash`) unlock extra exports;
you only need them if you touch that code path.

To build the actual `.exe` locally:

```bat
python make_icon.py
pyinstaller Capacitra.spec
```

GitHub Actions does exactly this on every push. If the workflow passes on
your fork, it will pass on `main`.

## Coding style

- Follow **PEP 8**. `black` is fine but not required.
- Prefer `os.scandir` over `os.walk` for anything performance-sensitive.
- All ctypes calls go through the helpers already defined near the top of
  `Capacitra.pyw`. Do not sprinkle `windll.kernel32` calls across the file.
- Guard every filesystem call with the appropriate `try / except` block.
  A single locked file must never crash a scan.
- Keep the app **offline**. Do not introduce anything that opens a socket,
  reads DNS, or phones home. That includes analytics, "just crash reporter",
  and auto-update HEAD checks. This is not negotiable.
- Do not add fields that leak the tech stack to the UI (no
  "made with Python", no "PyInstaller" strings).

## Commit sign-off (DCO)

Capacitra uses the **Developer Certificate of Origin** (DCO) instead of a
CLA. Every commit must be signed off, which means adding a `Signed-off-by:`
line to the commit message:

```bat
git commit -s -m "Fix duplicate detection on empty files"
```

That single line asserts that you have the right to contribute the code
under the project's license (GPL v3). Full text of the DCO is at
[developercertificate.org](https://developercertificate.org).

If you forget the `-s` flag, amend the commit:

```bat
git commit --amend -s
```

## Pull-request checklist

- [ ] Branch off `main`, keep PRs focused (one feature or one bugfix).
- [ ] `python -m py_compile Capacitra.pyw` succeeds.
- [ ] The GitHub Actions workflow builds green.
- [ ] Commit messages are signed off (`git commit -s`).
- [ ] You updated `README.md` if user-visible behaviour changed.
- [ ] You updated `SECURITY.md` if the threat model changed.
- [ ] No new external dependencies without discussion.

## What we won't merge

- Telemetry, analytics, "anonymous usage stats", auto-update phone-home.
- Anything that hard-deletes user files. The Recycle Bin is our only exit.
- Bundled adware, referral links, in-app upsells.
- Cross-platform ports without a serious owner. Windows-only is a
  positioning choice, not laziness.
- Third-party fonts and icons that require attribution but do not carry
  a permissive license.

## Reporting bugs

Open an [Issue](../../issues/new/choose) using the Bug Report template.
Include:

- Windows version (`winver`)
- Capacitra version (`Capacitra.exe --version`, or About panel)
- Whether you built from source or downloaded the release
- Steps to reproduce (a screenshot of the panel helps)
- A snippet of the treemap or folder tree if the crash is display-related

If the bug is a security issue, follow `SECURITY.md` instead.

## Getting your change released

Maintainers tag a release once a batch of merges is worth cutting. The
release workflow builds the `.exe`, signs it (if the code-signing cert
secret is present), and attaches the binary to the GitHub Release. The
Cloudflare R2 bucket at `download.capacitra.com` is updated separately.

Thanks again. See you in the pull requests.

# Security Policy

## Supported Versions

Capacitra is a single-file desktop application. We support only the latest
release. Please update to the newest version before reporting security
issues.

| Version | Supported |
|---|---|
| 4.1.x   | ✅ |
| < 4.1   | ❌ |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security problems.**

Instead, email **[info@capacitra.com](mailto:info@capacitra.com)** with:

- A clear description of the vulnerability
- Steps to reproduce
- The Capacitra version and Windows version you tested on
- Any proposed mitigation

We will:

1. Acknowledge receipt within 72 hours.
2. Investigate and confirm the issue within 7 days.
3. Ship a patched release, usually within 14 days for confirmed criticals.
4. Publicly credit you (unless you prefer anonymity) in the release notes.

If you would like PGP-encrypted correspondence, mention that in your first
email and we will exchange keys.

## Threat model

Capacitra is a **local desktop tool**. It never opens a network socket, does
not accept remote input, has no plugin system that loads untrusted code, and
does not run as an elevated (Administrator) process. Realistic attack
surface is therefore small.

Currently in scope:

- Executable integrity (the published `.exe` matches this source tree)
- Snapshot file (`.capsnap`) safety — loading a hostile snapshot must not
  execute arbitrary code
- CSV/Excel export sanitisation — cell values must not trigger the classic
  Excel formula-injection when the report is opened
- Path traversal — a hostile filename or symlink target must not crash the
  scanner or exfiltrate data (there is no exfiltration channel at all)
- Long-path handling — paths ≥260 chars must not crash the scanner

Out of scope:

- Physical access to the host machine
- Windows-level privilege escalation vulnerabilities
- Compromise of a downstream mirror hosting a modified `.exe` (verify
  SHA-256 against capacitra.com)

## Reproducible builds

We publish the exact `Capacitra.spec` used by GitHub Actions. If you want
to independently reproduce the shipped `.exe`, use the same Python version
and PyInstaller version listed in `.github/workflows/build.yml` — the
binary should match byte-for-byte on the same OS and toolchain.

## Snapshot format

Snapshots are prefixed with the magic bytes `CAPSNAP1`. The unpickler is
restricted to only allow the `Node` dataclass and a handful of primitive
types. Loading a snapshot from an untrusted source is still discouraged.

## Zero data leaves your machine

Capacitra opens no network sockets. If you observe outbound traffic while
Capacitra is running, that is a security bug. Please report it.

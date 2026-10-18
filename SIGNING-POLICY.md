# Code signing policy

Capacitra Windows binaries are code-signed to give users a stronger
guarantee that the `.exe` they downloaded was built from the source
tree published in this repository.

**Free code signing provided by [SignPath.io](https://about.signpath.io),
certificate by [SignPath Foundation](https://signpath.org).**

## Team roles

- **Authors** — people trusted to modify the source code without an
  additional review. Current member: `@ozcansamet`
  (Samet Özcan, Owner of the [Capacitra organization](https://github.com/Capacitra)).

- **Reviewers** — every change proposed by a non-Author (a pull request
  from an outside contributor) must be reviewed by an Author before
  merge.

- **Approvers** — every release request must be approved by an
  Approver. Current Approvers: **Owners of the
  [Capacitra organization](https://github.com/orgs/Capacitra/people?query=role%3Aowner)**.

If additional Authors, Reviewers, or Approvers join the project, this
document will be updated in the same commit that grants the role.

## Privacy policy

Capacitra **does not transfer any information to other networked
systems** unless specifically requested by the user (e.g. the user
clicking a hyperlink to `capacitra.com`, or clicking "Show in
Explorer" which invokes a Windows shell action).

The desktop application:

- Does not open any network sockets.
- Does not read or write any online configuration.
- Does not report crashes, telemetry, or usage analytics.
- Stores no state on any server. All settings and snapshots stay on
  the user's device.

The website `capacitra.com` follows a similar minimal-tracking policy —
see [privacy.html](https://capacitra.com/privacy.html) and
[cookies.html](https://capacitra.com/cookies.html) on the site.

Capacitra bundles the following third-party open source components at
build time via PyInstaller. None of them open network sockets at
runtime:

- Python 3.11 standard library (Python Software Foundation License 2)
- `reportlab` 4.5 (BSD) — used for PDF export only
- `openpyxl` 3.1 (MIT) — used for Excel export only
- `Pillow` 12.x (HPND) — used at build time to render the application icon

## Reproducible builds

Every release of Capacitra is built by GitHub Actions from a tagged
commit in this repository, using the workflow file at
[`.github/workflows/build.yml`](.github/workflows/build.yml).

The workflow:

1. Checks out the tagged commit at the pinned Python version
   (currently 3.11.x).
2. Installs the exact dependencies pinned (`==`) in `requirements.txt`.
   All third-party GitHub Actions are pinned to full commit SHAs.
3. Runs `python make_icon.py` to generate the application icon.
4. Runs `pyinstaller --clean Capacitra.spec` to build the binary.
5. Signs the binary when a certificate is configured (a signing
   failure fails the release).
6. Records the SHA-256 of the produced `Capacitra.exe` in `SHA256SUMS.txt`.
7. Uploads the binary as an Actions artifact; a separate job with
   write permission attaches it to the GitHub Release.

The SHA-256 shown on [capacitra.com](https://capacitra.com) and in the
GitHub Release description matches the workflow-produced binary and
can be verified against the artifact you downloaded.

## Security-related features and the SignPath policy

Capacitra ships a small set of **defensive** security-oriented views.
None of them scan for exploitable vulnerabilities in the user's system
or in third-party software:

- **Executable inventory** (formerly named "Suspicious executables") —
  lists every `.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.scr`,
  `.cmd`, `.msi`, `.jar`, `.hta`, `.wsf` file inside the scan tree
  that lives **outside** the standard Windows locations
  (`Program Files`, `Program Files (x86)`, `Windows`, `WinSxS`,
  `ProgramData\Microsoft`). The listing is sorted by modification
  time. This helps an administrator confirm the presence of executable
  files in unusual locations after a scan. It performs no signature
  verification, no static analysis, no network scanning, no port
  probing, and no exploit attempt. It is the executable-file
  equivalent of a folder listing.

- **Duplicate finder** — a byte-level SHA-1 comparator for storage
  savings. Does not identify vulnerable software.

- **File integrity monitor (planned in v5)** — will compare hash
  snapshots taken over time by the user to help spot files that
  changed unexpectedly, e.g. after a ransomware event. It is a
  reactive detection tool for the user's *own* files, not a scanner
  of third-party software or systems.

These features fall under SignPath's "features that detect actual
security breaches" clause, not the "hacking tools" clause.

## Reporting misuse

If you believe a Capacitra binary signed by SignPath Foundation is
being distributed in a way that violates this policy, please email
`info@capacitra.com` **and** `support@signpath.io` with details.

## Contact

Maintainer: Samet Özcan (`info@capacitra.com`)

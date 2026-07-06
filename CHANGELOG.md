# Changelog

## 2.0.1 — 2026-07-06

Fixes and hardening on top of 2.0, including an important crash fix and a new
stress/fuzz test suite.

### Fixed
- **Crash: pressing "Scan This Computer" could close the app with no message.**
  The app saved its data folder *relative to the working directory* using a
  throwing filesystem call. Launched so that its working directory isn't writable
  (e.g. a shortcut that starts in `System32`), that write threw on the main
  thread as the scan finished, and nothing caught it — so `std::terminate` closed
  the app silently. `EventDatabase` is now fully non-throwing, the desktop app
  saves to a per-user location (`%LOCALAPPDATA%\Ghostwire`) instead of the
  working directory, and an app-wide safety net catches any exception that
  escapes a slot/event handler, logs it to `ghostwire-error.log`, and keeps the
  app running.
- **O(n²) hot path** in the process-tree builder (`RelationshipEngine`) — it
  scanned every node to find each parent. 60k processes: ~3.6s → ~50ms. Only
  noticeable on large Sysmon/CSV imports.
- **Hardened the UI against markup in scanned data** — findings, summary,
  timeline and narrative are forced to plain text, so a crafted file name or a
  malicious reverse-DNS record containing HTML (e.g. `<img src=…>`) can't be
  rendered as rich text or trigger a resource load. (The HTML report already
  escaped these.)
- Reject implausible buffer sizes before allocating (TCP connection table,
  Authenticode hash/signer buffers); the CLI scan degrades gracefully on error.

### Added
- A **stress + fuzz test harness** (`ghostwire_stress`, wired into `ctest`) — 45
  checks over malformed/huge/adversarial CSV input, report HTML-escaping,
  process-graph edge cases (self-parent, cycles, 60k-node scale), and 3,000
  randomized analyzer iterations asserting score/verdict/sort/dedup invariants.
- Launch flags: `ghostwire --demo`, `ghostwire --scan`, and `ghostwire <file.csv>`.

## 2.0.0 — 2026-07-06

A major upgrade focused on trustworthiness (fewer false positives, real
attacker-technique mapping) and a rebuilt desktop experience.

### Detection engine
- **Authenticode signature verification** (`SignatureChecker`) using
  `WinVerifyTrust` with a security-catalog fallback, so catalog-signed Windows
  binaries are correctly recognised as trusted and their publisher is resolved.
  Verified only for binaries in user-writable locations, and cached per path, so
  a full scan stays fast (~seconds).
- **Signature-aware scoring** — unsigned/untrusted programs running from temp,
  Downloads, AppData, ProgramData, the Recycle Bin, etc. are flagged; signed
  programs in the same places are left alone. This is the main false-positive
  reducer.
- **System-process masquerade detection** — a core Windows name (`svchost.exe`,
  `lsass.exe`, `services.exe`, …) running from outside `System32` (T1036.005).
- **Double-extension lure detection** (`invoice.pdf.exe`, T1036.007).
- **MITRE ATT&CK tagging** — every finding now carries a technique id + name.
- **Structured, severity-ranked findings** (`Finding`) replacing the flat string
  list; results are ordered most-serious first, and a full kill chain escalates
  the verdict to Critical.
- **IPv6 connections** in the live scan, plus best-effort reverse DNS on
  suspicious hosts (bounded so it can't slow the scan).
- Ghostwire no longer reports on its own process.
- Hardened CSV/Sysmon parsing against malformed input (no more crash on a bad
  PID field).

### CLI (`anre`)
- `anre watch [seconds]` — re-scan on an interval and print only *new* findings.
- `anre sig <path>` — check one file's signature and publisher.
- Writes a shareable `data/report.html` alongside the existing outputs.

### Desktop app (`ghostwire`)
- Rebuilt UI: a welcome/hero screen, a hand-painted **risk gauge**,
  severity-coloured **finding cards** with MITRE chips, a verdict hero band, and
  a refreshed dark theme with a cyan "wire" accent.
- **Scanning now runs in the background** (QtConcurrent) — the window no longer
  freezes during a scan, with a busy indicator in the status bar.
- **Export report** button — save the self-contained HTML report.
- **Searchable Events** tab.
- `ghostwire --demo` launches straight into the example attack.

## 1.0.0

- Initial release: live process + connection scan, parent-child graph, threat
  scoring, plain-language narrative, Qt desktop app and `anre` CLI.

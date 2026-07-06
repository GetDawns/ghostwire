# Changelog

## 2.0.3 — 2026-07-06

The real fix for the "pressing Scan closes the app" crash (2.0.2 addressed the
wrong layer).

- **Root cause:** the app saved its `data/` folder *relative to the working
  directory* using the throwing `std::filesystem::create_directories`. Launched
  from a read-only working directory (e.g. a shortcut that starts in
  `System32`), that threw a `filesystem_error` on the main thread during scan
  completion, which nothing caught — so `std::terminate` closed the app with no
  message. Reproduced deterministically with a non-writable working directory.
- `EventDatabase` is now fully non-throwing (error-code filesystem calls,
  guarded file writes) — it skips saving instead of crashing.
- The desktop app writes its data to a per-user location
  (`%LOCALAPPDATA%\Ghostwire`) instead of the working directory, so saving works
  no matter how the app was launched.
- Added an app-wide safety net: any exception that escapes a slot/event handler
  is caught, logged to `ghostwire-error.log`, and shown to the user — the app
  can no longer close silently.

## 2.0.2 — 2026-07-06

Fixes a crash where pressing **Scan This Computer** could close the app with no
message.

- The live scan runs on a background thread; if anything in it threw (most
  likely an allocation failing when a Windows API reported an unexpected buffer
  size), the exception escaped the worker thread and terminated the whole
  process silently. The scan is now wrapped so any failure surfaces as a normal
  "scan unavailable" message instead of killing the app.
- Hardened the scan's buffer allocations: the TCP connection table and the
  Authenticode hash/signer buffers now reject implausible sizes instead of
  attempting a huge allocation.
- The `anre` CLI scan degrades gracefully on error too.
- Added a `ghostwire --scan` launch flag (kick off a scan on startup).

## 2.0.1 — 2026-07-06

Bug fixes and hardening found by a new stress/fuzz suite.

- **Fixed an O(n²) hot path** in `RelationshipEngine::buildGraph` — it did a
  linear scan of every node to find each parent. Building the process tree for
  60k processes dropped from ~3.6s to ~50ms. Only noticeable on large Sysmon/CSV
  imports; a normal live scan was always small.
- **Hardened the desktop UI against markup in scanned data.** Findings, summary,
  timeline and narrative labels are now forced to plain text, so a crafted file
  name or a malicious reverse-DNS record containing HTML (e.g. `<img src=…>`)
  can't be interpreted as rich text or trigger a resource load. The HTML report
  already escaped all such values.
- **Added a stress + fuzz test harness** (`ghostwire_stress`, wired into `ctest`)
  — 45 checks covering CSV robustness (malformed/huge/adversarial input), report
  HTML-escaping, graph edge cases (self-parent, cycles, scale), and 3000
  randomized analyzer iterations asserting score/verdict/sort/dedup invariants.
- **Added** `ghostwire <file.csv>` to open a CSV on launch; removed dead code.

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

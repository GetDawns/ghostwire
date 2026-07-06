# Changelog

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

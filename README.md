# Ghostwire — Attack Narrative Reconstruction Engine (ANRE)

Ghostwire is a self-service security check for your own Windows PC. Click one
button (or run one command) and it looks at everything running on your machine —
every process, who started it, whether it's **digitally signed**, and what it's
talking to on the internet — then tells you in plain English whether anything
looks wrong, and maps what it finds to real **MITRE ATT&CK** techniques.

Think of it as the "is something sketchy happening on my computer?" check you'd
normally need an IT person for. No agent to install, no Sysmon, no administrator
rights required.

> **New in 2.0:** Authenticode signature verification, system-process
> masquerade detection, MITRE ATT&CK tagging, IPv6 connections, reverse DNS,
> a shareable HTML report, a `watch` mode, and a rebuilt desktop UI with a live
> risk gauge and severity-ranked findings.

## What it does

When you scan, Ghostwire:

1. Lists every running process and its parent (via the Windows process snapshot API).
2. **Verifies the Authenticode signature** of programs in user-writable folders —
   so it can *trust* code signed by a known publisher and *flag* what isn't.
3. Maps each active outbound connection (IPv4 **and IPv6**) to the process that
   opened it, with best-effort reverse DNS on anything suspicious.
4. Builds the parent → child process tree.
5. Flags known-bad patterns — a Word/PDF app launching PowerShell, a program
   running unsigned from a temp folder, a core Windows name (`svchost.exe`,
   `lsass.exe`, …) running from the wrong place, a double-extension lure
   (`invoice.pdf.exe`), a suspicious process phoning home.
6. Gives you a risk score, a threat level, and a ranked list of **what stood
   out** — each item tagged with its MITRE ATT&CK technique.

On a healthy machine you get the boring (good) answer:

```text
What stood out
-------------
  Nothing — no suspicious process chains or connections found.

Risk Score: 5/100
Threat Level: Clean
```

If something *does* match a known attack pattern (try `anre demo` to see it),
you get the story instead — ranked most-serious first:

```text
What stood out
-------------
  [Critical] Acrobat.exe launched cmd.exe
      Document apps almost never start command-line tools. This is a hallmark of
      a malicious document or exploit running code on the machine.
      ATT&CK T1059 — Command and Scripting Interpreter
  [High] malware.exe set itself to run at startup
      ... ATT&CK T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
  [High] malware.exe is talking to the internet
      ... ATT&CK T1071 — Application Layer Protocol

Risk Score: 100/100
Threat Level: Critical
```

> Ghostwire is a lightweight heuristic triage tool, not antivirus. It's good at
> spotting suspicious *relationships* (who launched what, who's talking to the
> internet, what's unsigned). It won't catch everything, and a "Clean" score is
> not a guarantee a machine is uncompromised.

## Why signatures matter

Most simple scanners flag anything running from a temp or Downloads folder,
which produces a wall of false positives (installers, updaters, portable apps
all live there). Ghostwire checks the Authenticode signature first: a binary
signed by a trusted publisher is left alone, and only the **unsigned** ones in
those locations get called out. That one check does most of the work of keeping
the noise low enough for a non-expert to act on.

## Where the data comes from

| Source | How to use it |
|--------|---------------|
| **This computer** (default) | Live snapshot of running processes + connections. No setup. |
| **Example attack** | Built-in malicious-PDF scenario, so you can see what a detection looks like. |
| **CSV import** | Load an event export from another machine or tool. |
| **Sysmon** | Pull richer history from the Windows Event Log (needs Sysmon + admin). |

## Architecture

| Module | Role |
|--------|------|
| `EventCollector` | Scans the live system, or reads demo data / CSV / Sysmon |
| `SignatureChecker` | Authenticode + security-catalog verification, with a per-path cache |
| `RelationshipEngine` | Builds the parent-child process tree (one node per process) |
| `ThreatScoringEngine` | Scores risk and produces the ranked, MITRE-tagged findings |
| `NarrativeGenerator` | Turns suspicious events into an analyst-style story |
| `AttackChainBuilder` | Orchestrates the full reconstruction pipeline |
| `ReportWriter` | Renders a self-contained, shareable HTML report |
| `TimelineViewer` | Console output for the CLI |
| `EventDatabase` | Persists events and chains to `data/` |
| `ghostwire` (GUI) | Qt desktop app for reviewing a scan |

## Requirements

- Windows 10/11
- Visual Studio 2022 (or newer) with the C++ desktop workload (for building)
- **Qt 6 Widgets + Concurrent** — only needed for the GUI; the CLI builds without it

## Build

### 1. (Optional) Install Qt 6

Only needed for the desktop GUI. Install Qt 6.x with the **MSVC 2022 64-bit**
kit and note the path, e.g. `C:\Qt\6.11.1\msvc2022_64`.

### 2. Get the code and configure with CMake

```powershell
git clone https://github.com/GetDawns/ghostwire.git
cd ghostwire

# Point CMAKE_PREFIX_PATH at YOUR Qt install — replace the version/path to
# match what you installed (e.g. C:/Qt/6.11.1/msvc2022_64).
cmake -B build -DCMAKE_PREFIX_PATH="C:/Qt/<your-qt-version>/msvc2022_64"
cmake --build build --config Release
```

> **No Qt?** Just omit `-DCMAKE_PREFIX_PATH`. CMake will build only the `anre`
> command-line tool — no GUI, no Qt required.

This produces:

| Target | Output | Purpose |
|--------|--------|---------|
| `ghostwire` | `build\Release\ghostwire.exe` | Desktop app |
| `anre` | `build\Release\anre.exe` | Command-line tool |

To run the GUI outside Visual Studio, copy the Qt runtime next to the exe once
with `windeployqt build\Release\ghostwire.exe` (or use the packaged release).

## Run the GUI

```powershell
.\build\Release\ghostwire.exe
.\build\Release\ghostwire.exe --demo   # jump straight into the example attack
```

- **Scan This Computer** — snapshot and analyse this machine right now (runs in
  the background so the window stays responsive)
- **Import CSV file** — load an event export
- **Load example attack** — see what a real detection looks like
- **Export report** — save a self-contained HTML report you can send to someone

Tabs: **Overview** (risk gauge, verdict, ranked findings) · **Narrative** (the
attack story) · **Timeline** · **Process Chain** · **Events** (searchable).

## Run the CLI

```powershell
# Scan this computer (this is also what you get with no arguments)
.\build\Release\anre.exe scan

# Keep watching and alert only on NEW findings (default every 60s)
.\build\Release\anre.exe watch 30

# See the example attack
.\build\Release\anre.exe demo

# Check one file's signature and publisher
.\build\Release\anre.exe sig "C:\path\to\program.exe"

# Import your own events / pull from Sysmon (admin + Sysmon installed)
.\build\Release\anre.exe import C:\path\to\events.csv
.\build\Release\anre.exe sysmon 200
```

Results are also written to `data/events.csv`, `data/chain_*.txt`, and a
shareable `data/report.html`.

## CSV import format

```csv
processName,processId,parentProcessId,parentProcessName,action,target,timestamp
powershell.exe,6200,5124,chrome.exe,ProcessCreate,C:\Windows\System32\powershell.exe,2026-06-16T10:01:04
powershell.exe,6200,5124,chrome.exe,NetworkConnect,198.51.100.10:443,2026-06-16T10:02:11
```

## Detections & ATT&CK coverage

| Finding | Technique |
|---------|-----------|
| Document/browser app spawned a shell | T1059 Command and Scripting Interpreter |
| Core Windows process from the wrong folder | T1036.005 Masquerading |
| Double file extension (`invoice.pdf.exe`) | T1036.007 Double File Extension |
| Unsigned program in a user-writable folder | T1204.002 User Execution: Malicious File |
| Dropped executable in a temp folder | T1105 Ingress Tool Transfer |
| Registry Run-key persistence | T1547.001 Boot or Logon Autostart |
| Unexpected outbound connection | T1071 Application Layer Protocol |
| Repeated failed sign-ins | T1110 Brute Force |

## Stretch goals

- ~~Watch mode that re-scans on an interval and alerts on new activity~~ ✓ (`anre watch`)
- ~~IPv6 connections and reverse-DNS lookups for remote hosts~~ ✓
- ~~Signed-binary / publisher checks to cut false positives~~ ✓
- SQLite backend and Sigma-rule-driven detections
- Command-line capture for richer LOLBin detection

## Interview pitch

Most student security projects stop at port scanners or packet sniffers.
Ghostwire asks a harder question: **can a program look at a real computer and
explain, the way an analyst would, whether anything bad is happening?** That
combines live systems programming (Win32 process + network + Authenticode APIs),
graph algorithms, security domain knowledge, and product-style engineering
focused on keeping false positives low enough that a non-expert can actually use
it.

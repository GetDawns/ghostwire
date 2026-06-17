# Ghostwire — Attack Narrative Reconstruction Engine (ANRE)

Ghostwire is a self-service security check for your own Windows PC. Click one
button (or run one command) and it looks at everything running on your machine —
every process, who started it, and what it's talking to on the internet — then
tells you in plain English whether anything looks wrong.

Think of it as the "is something sketchy happening on my computer?" check you'd
normally need an IT person for. No agent to install, no Sysmon, no administrator
rights required.

## What it does

When you scan, Ghostwire:

1. Lists every running process and its parent (via the Windows process snapshot API).
2. Maps each active outbound connection to the process that opened it.
3. Builds the parent → child process tree.
4. Flags known-bad patterns — e.g. a Word document or PDF reader launching
   PowerShell, a program running from a temp folder, or a suspicious process
   phoning home.
5. Gives you a risk score, a threat level, and a short list of **what stood out**.

On a healthy machine you get the boring (good) answer:

```text
What stood out
-------------
  Nothing — no suspicious process chains or connections found.

Risk Score: 10/100
Threat Level: Low

Summary
Nothing in this snapshot matches a known attack pattern. The processes and
connections here look normal. (This is a quick heuristic check, not a full
antivirus scan.)
```

If something *does* match a known attack pattern (try `anre demo` to see it),
you get the story instead:

```text
Initial Access:
  - A malicious PDF was opened
Execution:
  - PDF reader launched cmd.exe
  - cmd.exe launched PowerShell
  - PowerShell downloaded malware.exe
Persistence:
  - Malware made a startup registry key for persistence
Command & Control:
  - malware.exe connected to external host 203.0.113.44:443

What stood out
-------------
  ! Acrobat.exe launched cmd.exe — apps like this rarely start command-line
    tools; it's a common malware pattern.
  ! malware.exe added a startup entry (HKCU\...\Run\Updater) — this makes a
    program run automatically every time you log in.
  ! malware.exe connected out to 203.0.113.44:443 — confirm you expect this
    program to talk to the internet.

Risk Score: 100/100
Threat Level: Critical
```

> Ghostwire is a lightweight heuristic triage tool, not antivirus. It's good at
> spotting suspicious *relationships* (who launched what, who's talking to the
> internet). It won't catch everything, and a "Low" score is not a guarantee a
> machine is clean.

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
| `RelationshipEngine` | Builds the parent-child process tree (one node per process) |
| `ThreatScoringEngine` | Scores risk and produces the plain-language findings |
| `NarrativeGenerator` | Turns suspicious events into an analyst-style story |
| `AttackChainBuilder` | Orchestrates the full reconstruction pipeline |
| `TimelineViewer` | Console output for the CLI |
| `EventDatabase` | Persists events and chains to `data/` |
| `ghostwire` (GUI) | Qt desktop app for reviewing a scan |

## Requirements

- Windows 10/11
- Visual Studio 2022 with the C++ desktop workload (for building)
- **Qt 6 Widgets** — only needed for the GUI; the CLI builds without it

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

CMake auto-detects your installed Visual Studio. You can also open the folder in
Visual Studio via **File → Open → CMake...**, set `CMAKE_PREFIX_PATH` in **CMake
Settings**, and build from there.

This produces:

| Target | Output | Purpose |
|--------|--------|---------|
| `ghostwire` | `build\Release\ghostwire.exe` | Desktop app |
| `anre` | `build\Release\anre.exe` | Command-line tool |

## Run the GUI

```powershell
.\build\Release\ghostwire.exe
```

- **Scan This Computer** — snapshot and analyse this machine right now
- **Import CSV file** — load an event export
- **Load example attack** — see what a real detection looks like

Tabs: **Overview** (score, verdict, what stood out) · **Narrative** (the attack
story) · **Timeline** · **Process Chain** · **Events**.

## Run the CLI

```powershell
# Scan this computer (this is also what you get with no arguments)
.\build\Release\anre.exe scan

# See the example attack
.\build\Release\anre.exe demo

# Import your own events
.\build\Release\anre.exe import C:\path\to\events.csv

# Pull from Sysmon (Administrator + Sysmon installed)
.\build\Release\anre.exe sysmon 200
```

Results are also written to `data/events.csv` and `data/chain_*.txt`.

## CSV import format

```csv
processName,processId,parentProcessId,parentProcessName,action,target,timestamp
powershell.exe,6200,5124,chrome.exe,ProcessCreate,C:\Windows\System32\powershell.exe,2026-06-16T10:01:04
powershell.exe,6200,5124,chrome.exe,NetworkConnect,198.51.100.10:443,2026-06-16T10:02:11
```

## Stretch goals

- Watch mode that re-scans on an interval and alerts on new suspicious activity
- IPv6 connections and reverse-DNS / reputation lookups for remote hosts
- Signed-binary / publisher checks to cut false positives further
- SQLite backend and Sigma-rule-driven detections

## Interview pitch

Most student security projects stop at port scanners or packet sniffers.
Ghostwire asks a harder question: **can a program look at a real computer and
explain, the way an analyst would, whether anything bad is happening?** That
combines live systems programming (Win32 process + network APIs), graph
algorithms, security domain knowledge, and product-style engineering focused on
keeping false positives low enough that a non-expert can actually use it.

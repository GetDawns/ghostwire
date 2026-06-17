# Ghostwire — Attack Narrative Reconstruction Engine (ANRE)

Ghostwire turns noisy security telemetry into a human-readable attack story. Instead of dumping raw Sysmon alerts, it reconstructs process chains, maps them to MITRE phases, scores risk, and explains what likely happened.

## What it does

Given events like:

- PDF opened
- `cmd.exe` spawned
- PowerShell downloaded malware
- Registry persistence added
- External network connection

Ghostwire produces:

```text
Attack Chain #42

Initial Access:
  - User opened a malicious PDF document

Execution:
  - PDF reader launched cmd.exe
  - cmd.exe launched PowerShell
  - PowerShell downloaded malware.exe

Persistence:
  - Malware created a startup registry key

Command & Control:
  - malware.exe connected to 203.0.113.44:443

Risk Score: 92/100
Threat Level: High
```

## Architecture

| Module | Role |
|--------|------|
| `EventCollector` | Reads Sysmon / Windows Event Logs, demo data, or CSV imports |
| `RelationshipEngine` | Builds parent-child process graph from events |
| `NarrativeGenerator` | Converts technical events into analyst-style explanations |
| `ThreatScoringEngine` | Assigns risk points and threat level |
| `AttackChainBuilder` | Orchestrates the full reconstruction pipeline |
| `TimelineViewer` | Console output for CLI mode |
| `EventDatabase` | Persists events and chains to `data/` |
| `ghostwire` (GUI) | Qt desktop console for incident review |

## Requirements

- Windows 10/11
- Visual Studio 2022 with C++ desktop workload
- **Qt 6 Widgets** (for the GUI) — install via [Qt Online Installer](https://www.qt.io/download-qt-installer) or `aqtinstall`
- Sysmon (optional, for live collection)

## Build

### 1. Install Qt 6

Install Qt 6.x with the **MSVC 2022 64-bit** kit. Note the install path, e.g. `C:\Qt\6.8.0\msvc2022_64`.

### 2. Configure with CMake

```powershell
cd C:\Users\bayro\source\repos\ghostwire

cmake -B build -G "Visual Studio 17 2022" -DCMAKE_PREFIX_PATH="C:\Qt\6.8.0\msvc2022_64"
cmake --build build --config Release
```

Or open the folder in Visual Studio via **File → Open → CMake...**, set `CMAKE_PREFIX_PATH` in **CMake Settings** to your Qt path, then build.

This produces two executables:

| Target | Output | Purpose |
|--------|--------|---------|
| `ghostwire` | `build\Release\ghostwire.exe` | Desktop UI |
| `anre` | `build\Release\anre.exe` | Command-line tool |

If Qt is not found, only `anre` (CLI) is built.

## Run the GUI

```powershell
.\build\Release\ghostwire.exe
```

1. **Collect from Sysmon** — reads live telemetry (run as Administrator, Sysmon required)
2. **Import CSV file** — load your own event export

The interface includes:

- **Overview** — risk score, threat level, incident summary
- **Narrative** — MITRE-aligned attack story
- **Timeline** — chronological event sequence
- **Process Chain** — parent/child process tree
- **Events** — raw event table

## Run the CLI

```powershell
# Live Sysmon collection (Administrator + Sysmon installed)
.\build\Release\anre.exe sysmon 200

# Import custom events
.\build\Release\anre.exe import C:\path\to\events.csv

# Built-in demo scenario
.\build\Release\anre.exe demo
```

Output is written to `data/events.csv` and `data/chain_*.txt`.

## CSV import format

```csv
processName,processId,parentProcessId,parentProcessName,action,target,timestamp
powershell.exe,6200,5124,chrome.exe,ProcessCreate,C:\Windows\System32\powershell.exe,2026-06-16T10:01:04
powershell.exe,6200,5124,chrome.exe,NetworkConnect,198.51.100.10:443,2026-06-16T10:02:11
```

## Stretch goals

- SQLite backend instead of CSV
- LLM-powered incident summaries via local or API model
- Sigma rule integration for richer detections

## Interview pitch

Most student security projects stop at port scanners or packet sniffers. Ghostwire asks a harder question: **can a computer explain an attack the way a security analyst would?** That combines systems programming, graph algorithms, security domain knowledge, and product-style engineering.

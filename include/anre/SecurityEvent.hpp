#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace anre {

enum class EventCategory {
    ProcessCreation,
    FileCreate,
    RegistryModify,
    NetworkConnection,
    LogonFailure,
    Unknown
};

enum class MitrePhase {
    InitialAccess,
    Execution,
    Persistence,
    CommandAndControl,
    Unknown
};

// Result of an Authenticode check on a process image. Used both to flag
// unsigned binaries running from user-writable locations and — just as
// importantly — to *trust* code signed by a known publisher and keep the
// false-positive rate low.
enum class SignatureStatus {
    Unknown,          // not checked (demo/CSV/Sysmon data) or check failed
    Unsigned,         // no digital signature at all
    SignedTrusted,    // signed and the signature chains to a trusted root
    SignedUntrusted   // signed, but expired / self-signed / not trusted
};

struct SecurityEvent {
    std::int64_t id = 0;
    std::string processName;
    std::int32_t processId = 0;
    std::int32_t parentProcessId = 0;
    std::string parentProcessName;
    std::string action;
    std::string target;
    std::string timestamp;
    EventCategory category = EventCategory::Unknown;
    MitrePhase phase = MitrePhase::Unknown;
    int threatPoints = 0;

    // Populated by the live scanner (empty for demo / CSV / Sysmon events).
    std::string imagePath;                              // full path to the on-disk executable
    SignatureStatus signature = SignatureStatus::Unknown;
    std::string publisher;                              // signer common name, when signed
};

// How loud a single finding is. Drives the score, the ordering, and the
// colour it gets in the UI.
enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

inline const char* severityName(Severity severity) {
    switch (severity) {
    case Severity::Critical: return "Critical";
    case Severity::High:     return "High";
    case Severity::Medium:   return "Medium";
    case Severity::Low:      return "Low";
    default:                 return "Info";
    }
}

// A single, human-readable thing worth a person's attention, tagged with the
// MITRE ATT&CK technique it maps to. Replaces the old bare list of strings so
// the CLI, the HTML report, and the GUI can all render severity and context.
struct Finding {
    Severity severity = Severity::Info;
    std::string title;      // short headline, e.g. "Office app launched PowerShell"
    std::string detail;     // plain-language explanation of why it matters
    std::string mitreId;    // ATT&CK technique id, e.g. "T1059.001"
    std::string mitreName;  // ATT&CK technique name
    std::string process;    // the process the finding is about, when applicable

    // Stable identity for de-duplication and for spotting *new* findings across
    // repeated scans (watch mode).
    std::string key() const { return mitreId + "|" + title + "|" + process; }
};

} // namespace anre

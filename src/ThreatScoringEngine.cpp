#include "anre/ThreatScoringEngine.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace anre {

namespace {

std::string lower(const std::string& value) {
    std::string copy = value;
    std::transform(copy.begin(), copy.end(), copy.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return copy;
}

bool has(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string basename(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

int weightFor(Severity severity) {
    switch (severity) {
    case Severity::Critical: return 45;
    case Severity::High:     return 28;
    case Severity::Medium:   return 15;
    case Severity::Low:      return 6;
    default:                 return 0;
    }
}

int severityRank(Severity severity) {
    return static_cast<int>(severity);
}

// A short, friendly description of where an executable lives, for finding text.
std::string locationHint(const std::string& path) {
    const std::string p = lower(path);
    if (has(p, "\\temp\\") || has(p, "\\temp")) return "a temporary folder";
    if (has(p, "\\downloads")) return "your Downloads folder";
    if (has(p, "\\appdata\\roaming")) return "an AppData (Roaming) folder";
    if (has(p, "\\appdata\\local")) return "an AppData (Local) folder";
    if (has(p, "\\programdata")) return "the ProgramData folder";
    if (has(p, "$recycle.bin")) return "the Recycle Bin";
    if (has(p, "\\public\\")) return "the Public user folder";
    return "a user-writable folder";
}

} // namespace

bool ThreatScoringEngine::isLolbin(const std::string& name) {
    const std::string process = lower(name);
    return has(process, "powershell") || has(process, "cmd.exe") ||
           has(process, "wscript") || has(process, "cscript") ||
           has(process, "mshta") || has(process, "rundll32") ||
           has(process, "regsvr32") || has(process, "certutil") ||
           has(process, "bitsadmin") || has(process, "wmic") ||
           has(process, "msbuild") || has(process, "installutil") ||
           has(process, "curl.exe");
}

bool ThreatScoringEngine::isDocumentApp(const std::string& name) {
    const std::string process = lower(name);
    return has(process, "winword") || has(process, "excel") ||
           has(process, "powerpnt") || has(process, "outlook") ||
           has(process, "acrord") || has(process, "acrobat") ||
           has(process, "wordpad") || has(process, "onenote");
}

bool ThreatScoringEngine::isBrowser(const std::string& name) {
    const std::string process = lower(name);
    return has(process, "chrome") || has(process, "msedge") ||
           has(process, "firefox") || has(process, "iexplore") ||
           has(process, "opera") || has(process, "brave");
}

bool ThreatScoringEngine::isDocumentOrBrowser(const std::string& name) {
    return isDocumentApp(name) || isBrowser(name);
}

bool ThreatScoringEngine::isFromTempLocation(const std::string& path) {
    const std::string location = lower(path);
    return has(location, "\\temp\\") || has(location, "\\appdata\\local\\temp") ||
           has(location, "\\windows\\temp") || has(location, "\\downloads\\");
}

bool ThreatScoringEngine::isFromUserWritableLocation(const std::string& path) {
    const std::string location = lower(path);
    return has(location, "\\temp\\") || has(location, "\\appdata\\") ||
           has(location, "\\downloads\\") || has(location, "\\programdata\\") ||
           has(location, "$recycle.bin") || has(location, "\\public\\") ||
           has(location, "\\windows\\temp");
}

bool ThreatScoringEngine::isProtectedSystemProcess(const std::string& name) {
    static const std::array<const char*, 12> kProtected = {
        "svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
        "winlogon.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
        "taskhostw.exe", "dwm.exe", "conhost.exe", "runtimebroker.exe"
    };
    const std::string process = lower(basename(name));
    for (const char* candidate : kProtected) {
        if (process == candidate) {
            return true;
        }
    }
    return false;
}

bool ThreatScoringEngine::isInSystemDirectory(const std::string& path) {
    const std::string location = lower(path);
    return has(location, "\\windows\\system32\\") ||
           has(location, "\\windows\\syswow64\\") ||
           has(location, "\\windows\\winsxs\\");
}

bool ThreatScoringEngine::hasDoubleExtension(const std::string& path) {
    const std::string name = lower(basename(path));
    static const std::array<const char*, 9> kLures = {
        ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
        ".txt.exe", ".jpg.exe", ".png.exe", ".zip.exe"
    };
    for (const char* lure : kLures) {
        if (name.size() >= std::string(lure).size() &&
            name.compare(name.size() - std::string(lure).size(), std::string::npos, lure) == 0) {
            return true;
        }
    }
    return false;
}

bool ThreatScoringEngine::isUntrustedSignature(SignatureStatus status) {
    return status == SignatureStatus::Unsigned || status == SignatureStatus::SignedUntrusted;
}

bool ThreatScoringEngine::isSuspiciousProcess(const std::string& name) {
    // Match "malware.exe" (the demo sample) but NOT legitimate security tools
    // whose name merely contains "malware" — e.g. Malwarebytes.
    return isLolbin(name) || has(lower(name), "malware.exe");
}

bool ThreatScoringEngine::isSuspiciousNetworkTarget(const std::string& target) {
    const std::string value = lower(target);
    if (has(value, "127.0.0.1") || has(value, "localhost") || has(value, "0.0.0.0")) {
        return false;
    }
    return value.find(':') != std::string::npos;
}

std::string ThreatScoringEngine::levelForScore(int score) const {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 35) return "Medium";
    if (score > 0)   return "Low";
    return "Clean";
}

AnalysisResult ThreatScoringEngine::analyze(const std::vector<SecurityEvent>& events) {
    AnalysisResult result;
    std::vector<Finding>& findings = result.findings;

    const auto add = [&](Finding finding) {
        for (const Finding& existing : findings) {
            if (existing.key() == finding.key()) {
                return; // already reported
            }
        }
        findings.push_back(std::move(finding));
    };

    for (const SecurityEvent& event : events) {
        const std::string imagePath = event.imagePath.empty() ? event.target : event.imagePath;
        const bool checkedSignature = event.signature != SignatureStatus::Unknown;

        switch (event.category) {
        case EventCategory::ProcessCreation: {
            // Highest-fidelity signal: a document/browser app spawning a shell.
            if (isDocumentApp(event.parentProcessName) && isLolbin(event.processName)) {
                add({Severity::Critical,
                     event.parentProcessName + " launched " + event.processName,
                     "Document apps almost never start command-line tools. This is a hallmark of a "
                     "malicious document or exploit running code on the machine.",
                     "T1059", "Command and Scripting Interpreter", event.processName});
            } else if (isBrowser(event.parentProcessName) && isLolbin(event.processName)) {
                add({Severity::High,
                     event.parentProcessName + " launched " + event.processName,
                     "A browser spawned a command-line tool. Occasionally legitimate, but a common "
                     "step in drive-by and phishing payloads — worth confirming.",
                     "T1059", "Command and Scripting Interpreter", event.processName});
            }

            // Masquerading: a core Windows process running from the wrong place.
            if (!event.imagePath.empty() && isProtectedSystemProcess(event.processName) &&
                !isInSystemDirectory(event.imagePath)) {
                add({Severity::Critical,
                     event.processName + " is running from the wrong location",
                     "A core Windows process named " + event.processName + " is running from " +
                     event.imagePath + " instead of the System32 folder. Malware often copies a "
                     "trusted name to blend in.",
                     "T1036.005", "Masquerading: Match Legitimate Name or Location", event.processName});
            }

            // Double-extension lure (invoice.pdf.exe).
            if (hasDoubleExtension(imagePath)) {
                add({Severity::High,
                     basename(imagePath) + " uses a disguised file name",
                     "This program is an executable dressed up to look like a document or image "
                     "(a double extension). That disguise is almost always deliberate.",
                     "T1036.007", "Masquerading: Double File Extension", event.processName});
            }

            // Unsigned / untrusted binary from a user-writable location. Signed
            // apps in the same folders are left alone — that's the whole point
            // of the signature check.
            if (checkedSignature && isUntrustedSignature(event.signature) &&
                isFromUserWritableLocation(imagePath)) {
                const bool unsigned_ = event.signature == SignatureStatus::Unsigned;
                add({Severity::High,
                     event.processName + " is unverified and running from " + locationHint(imagePath),
                     std::string(unsigned_ ? "This program has no digital signature" :
                                             "This program's digital signature did not validate") +
                     " and it's running from " + locationHint(imagePath) +
                     " — a combination legitimate software rarely has. Confirm you installed it on purpose.",
                     "T1204.002", "User Execution: Malicious File", event.processName});
            } else if (!checkedSignature && isFromTempLocation(imagePath) &&
                       (isSuspiciousProcess(event.processName) || isLolbin(event.processName))) {
                add({Severity::Medium,
                     event.processName + " is running from " + locationHint(imagePath),
                     event.processName + " is executing from " + locationHint(imagePath) +
                     " (" + imagePath + ") — a place malware often hides.",
                     "T1204.002", "User Execution: Malicious File", event.processName});
            }
            break;
        }
        case EventCategory::FileCreate:
            if ((has(lower(event.target), "malware") ||
                 (has(lower(event.target), ".exe") && isFromTempLocation(event.target)))) {
                add({Severity::Medium,
                     event.processName + " wrote an executable to " + locationHint(event.target),
                     event.processName + " dropped " + basename(event.target) + " into " +
                     locationHint(event.target) + ". Dropping and then running an .exe from a temp "
                     "folder is a routine malware step.",
                     "T1105", "Ingress Tool Transfer", event.processName});
            }
            break;
        case EventCategory::RegistryModify:
            if (has(lower(event.target), "run") || has(lower(event.target), "startup")) {
                add({Severity::High,
                     event.processName + " set itself to run at startup",
                     event.processName + " added a startup entry (" + event.target +
                     "). This makes a program launch automatically every time you log in — a common "
                     "way malware stays on a machine.",
                     "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", event.processName});
            }
            break;
        case EventCategory::NetworkConnection:
            if (isSuspiciousNetworkTarget(event.target) &&
                (isSuspiciousProcess(event.processName) ||
                 isFromTempLocation(imagePath) ||
                 (checkedSignature && isUntrustedSignature(event.signature)))) {
                add({Severity::High,
                     event.processName + " is talking to the internet",
                     event.processName + " opened an outbound connection to " + event.target +
                     ". For a program like this, confirm you expect it to be contacting the internet — "
                     "unexpected outbound traffic can be a sign of remote control.",
                     "T1071", "Application Layer Protocol", event.processName});
            }
            break;
        case EventCategory::LogonFailure:
            add({Severity::Medium,
                 "Repeated failed sign-in attempts",
                 "Several failed logon attempts were seen, which can indicate someone guessing a "
                 "password.",
                 "T1110", "Brute Force", event.processName});
            break;
        default:
            break;
        }
    }

    // Rank most-serious first; ties keep discovery order.
    std::stable_sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        return severityRank(a.severity) > severityRank(b.severity);
    });

    int score = 0;
    Severity worst = Severity::Info;
    for (const Finding& finding : findings) {
        score += weightFor(finding.severity);
        if (severityRank(finding.severity) > severityRank(worst)) {
            worst = finding.severity;
        }
    }

    // A full kill chain (activity spanning several distinct techniques) is worse
    // than the sum of its parts — escalate the verdict the way an analyst would.
    if (findings.size() >= 3 && worst == Severity::High) {
        worst = Severity::Critical;
    }

    result.score = findings.empty() ? 5 : std::min(score, 100);
    switch (worst) {
    case Severity::Critical: result.level = "Critical"; break;
    case Severity::High:     result.level = "High"; break;
    case Severity::Medium:   result.level = "Medium"; break;
    case Severity::Low:      result.level = "Low"; break;
    default:                 result.level = findings.empty() ? "Clean" : "Low"; break;
    }
    return result;
}

} // namespace anre

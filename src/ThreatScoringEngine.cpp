#include "anre/ThreatScoringEngine.hpp"

#include <algorithm>
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

} // namespace

// Living-off-the-land binaries: legitimate Windows tools that attackers lean on
// because they're already trusted and installed everywhere.
bool ThreatScoringEngine::isLolbin(const std::string& name) {
    const std::string process = lower(name);
    return has(process, "powershell") || has(process, "cmd.exe") ||
           has(process, "wscript") || has(process, "cscript") ||
           has(process, "mshta") || has(process, "rundll32") ||
           has(process, "regsvr32") || has(process, "certutil") ||
           has(process, "bitsadmin") || has(process, "wmic");
}

bool ThreatScoringEngine::isDocumentOrBrowser(const std::string& name) {
    const std::string process = lower(name);
    return has(process, "winword") || has(process, "excel") ||
           has(process, "powerpnt") || has(process, "outlook") ||
           has(process, "acrord") || has(process, "acrobat") ||
           has(process, "chrome") || has(process, "msedge") ||
           has(process, "firefox") || has(process, "iexplore");
}

bool ThreatScoringEngine::isFromTempLocation(const std::string& path) {
    const std::string location = lower(path);
    return has(location, "\\temp\\") || has(location, "\\appdata\\local\\temp") ||
           has(location, "\\windows\\temp") || has(location, "\\downloads\\");
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

int ThreatScoringEngine::scoreEvent(const SecurityEvent& event) {
    int score = 0;

    switch (event.category) {
    case EventCategory::LogonFailure:
        score += 5;
        break;
    case EventCategory::ProcessCreation:
        // The strongest single signal: an everyday document or browser app
        // spawning a command-line tool. Normal users never do this; exploits
        // and malicious macros do it constantly.
        if (isDocumentOrBrowser(event.parentProcessName) && isLolbin(event.processName)) {
            score += 35;
        } else if (isLolbin(event.processName)) {
            // A command-line tool on its own is common and mostly benign.
            score += 5;
        }
        if (isFromTempLocation(event.target)) {
            score += 20;
        }
        break;
    case EventCategory::FileCreate:
        if (has(lower(event.target), "malware") ||
            (has(lower(event.target), ".exe") && isFromTempLocation(event.target))) {
            score += 10;
        }
        break;
    case EventCategory::RegistryModify:
        if (has(lower(event.target), "run") || has(lower(event.target), "startup")) {
            score += 25;
        } else {
            score += 10;
        }
        break;
    case EventCategory::NetworkConnection:
        // Only flag outbound traffic from processes that have no business
        // making it. Scoring every browser connection would mark every machine
        // "Critical", which is useless.
        if (isSuspiciousNetworkTarget(event.target) &&
            (isSuspiciousProcess(event.processName) || isFromTempLocation(event.target))) {
            score += 30;
        }
        break;
    default:
        break;
    }

    if (has(lower(event.processName), "malware.exe")) {
        score += 15;
    }

    return score;
}

int ThreatScoringEngine::scoreChain(const std::vector<SecurityEvent>& events) {
    int total = 0;
    for (const SecurityEvent& event : events) {
        total += scoreEvent(event);
    }
    return std::min(total, 100);
}

std::vector<std::string> ThreatScoringEngine::findThreats(
    const std::vector<SecurityEvent>& events) {
    std::vector<std::string> findings;
    const auto add = [&](const std::string& line) {
        if (std::find(findings.begin(), findings.end(), line) == findings.end()) {
            findings.push_back(line);
        }
    };

    for (const SecurityEvent& event : events) {
        switch (event.category) {
        case EventCategory::ProcessCreation:
            if (isDocumentOrBrowser(event.parentProcessName) && isLolbin(event.processName)) {
                add(event.parentProcessName + " launched " + event.processName +
                    " — apps like this rarely start command-line tools; it's a common malware pattern.");
            }
            if (isFromTempLocation(event.target)) {
                add(event.processName + " is running from a temporary folder (" +
                    event.target + ") — a place malware often hides.");
            }
            break;
        case EventCategory::RegistryModify:
            if (has(lower(event.target), "run") || has(lower(event.target), "startup")) {
                add(event.processName + " added a startup entry (" + event.target +
                    ") — this makes a program run automatically every time you log in.");
            }
            break;
        case EventCategory::NetworkConnection:
            if (isSuspiciousNetworkTarget(event.target) &&
                (isSuspiciousProcess(event.processName) || isFromTempLocation(event.target))) {
                add(event.processName + " connected out to " + event.target +
                    " — confirm you expect this program to talk to the internet.");
            }
            break;
        default:
            break;
        }
    }

    return findings;
}

std::string ThreatScoringEngine::threatLevel(int score) const {
    if (score >= 80) {
        return "Critical";
    }
    if (score >= 60) {
        return "High";
    }
    if (score >= 35) {
        return "Medium";
    }
    if (score > 0) {
        return "Low";
    }
    return "Informational";
}

} // namespace anre

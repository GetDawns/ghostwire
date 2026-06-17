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

} // namespace

bool ThreatScoringEngine::isSuspiciousProcess(const std::string& name) {
    const std::string process = lower(name);
    return process.find("powershell") != std::string::npos ||
           process.find("cmd.exe") != std::string::npos ||
           process.find("wscript") != std::string::npos ||
           process.find("cscript") != std::string::npos ||
           process.find("malware") != std::string::npos;
}

bool ThreatScoringEngine::isSuspiciousNetworkTarget(const std::string& target) {
    const std::string value = lower(target);
    if (value.find("127.0.0.1") != std::string::npos ||
        value.find("localhost") != std::string::npos) {
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
        if (isSuspiciousProcess(event.processName)) {
            score += 15;
        }
        // A PDF reader spawning a child process is a classic exploit/macro
        // signature, so weight it heavily. Match both Acrobat and AcroRd32.
        {
            const std::string parent = lower(event.parentProcessName);
            if (parent.find("acrord") != std::string::npos ||
                parent.find("acrobat") != std::string::npos) {
                score += 20;
            }
        }
        break;
    case EventCategory::FileCreate:
        if (lower(event.target).find("malware") != std::string::npos ||
            lower(event.target).find(".exe") != std::string::npos) {
            score += 10;
        }
        break;
    case EventCategory::RegistryModify:
        if (lower(event.target).find("run") != std::string::npos) {
            score += 25;
        } else {
            score += 10;
        }
        break;
    case EventCategory::NetworkConnection:
        if (isSuspiciousNetworkTarget(event.target)) {
            score += 30;
        }
        break;
    default:
        break;
    }

    if (lower(event.processName).find("malware") != std::string::npos) {
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

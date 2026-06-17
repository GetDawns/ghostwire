#pragma once

#include "anre/SecurityEvent.hpp"
#include <string>
#include <vector>

namespace anre {

class ThreatScoringEngine {
public:
    int scoreEvent(const SecurityEvent& event);
    int scoreChain(const std::vector<SecurityEvent>& events);
    std::string threatLevel(int score) const;

    // Walk the events and return human-readable findings — the specific things
    // that pushed the score up. An empty list means nothing looked wrong.
    std::vector<std::string> findThreats(const std::vector<SecurityEvent>& events);

    // Exposed so other components (e.g. the narrative) stay consistent with how
    // the scorer decides what's worth flagging.
    static bool isSuspiciousProcess(const std::string& name);

private:
    static bool isSuspiciousNetworkTarget(const std::string& target);
    static bool isLolbin(const std::string& name);
    static bool isDocumentOrBrowser(const std::string& name);
    static bool isFromTempLocation(const std::string& path);
};

} // namespace anre

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

private:
    static bool isSuspiciousProcess(const std::string& name);
    static bool isSuspiciousNetworkTarget(const std::string& target);
};

} // namespace anre

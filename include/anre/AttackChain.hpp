#pragma once

#include "anre/EventNode.hpp"
#include "anre/SecurityEvent.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace anre {

struct NarrativeSection {
    MitrePhase phase = MitrePhase::Unknown;
    std::string phaseLabel;
    std::vector<std::string> lines;
};

struct AttackChain {
    std::int64_t id = 0;
    std::string title;
    std::vector<SecurityEvent> events;
    std::vector<EventNode> graph;
    std::vector<NarrativeSection> narrative;
    int riskScore = 0;
    std::string threatLevel;
    std::vector<std::string> timeline;
};

} // namespace anre

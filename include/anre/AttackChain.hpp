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
    // Things worth a human's attention, each tagged with severity and the MITRE
    // ATT&CK technique it maps to. Empty means nothing in this snapshot matched a
    // known-bad pattern (i.e. it looks clean).
    std::vector<Finding> findings;
    // What the scan looked at — surfaced in the report/UI for context.
    std::string source;     // "This computer", "Example attack", a CSV path, ...
    int processCount = 0;   // distinct processes observed
    int networkCount = 0;   // outbound internet connections observed
};

} // namespace anre

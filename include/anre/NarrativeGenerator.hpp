#pragma once

#include "anre/AttackChain.hpp"
#include "anre/EventNode.hpp"
#include "anre/SecurityEvent.hpp"
#include <string>
#include <vector>

namespace anre {

class NarrativeGenerator {
public:
    std::vector<NarrativeSection> generate(
        const std::vector<SecurityEvent>& events,
        const std::vector<EventNode>& graph);

    std::string generateSummary(const AttackChain& chain);

private:
    static std::string lower(const std::string& value);
    static bool contains(const std::string& haystack, const std::string& needle);
    static std::string describeProcessSpawn(
        const std::string& parent,
        const std::string& child);
    static std::string phaseLabel(MitrePhase phase);
};

} // namespace anre

#pragma once

#include "anre/EventNode.hpp"
#include "anre/SecurityEvent.hpp"
#include <vector>

namespace anre {

class RelationshipEngine {
public:
    std::vector<EventNode> buildGraph(const std::vector<SecurityEvent>& events);
};

} // namespace anre

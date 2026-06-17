#pragma once

#include "anre/EventNode.hpp"
#include "anre/SecurityEvent.hpp"
#include <vector>

namespace anre {

class RelationshipEngine {
public:
    std::vector<EventNode> buildGraph(const std::vector<SecurityEvent>& events);

private:
    static std::int64_t findNodeByPid(const std::vector<EventNode>& nodes, std::int32_t pid);
};

} // namespace anre

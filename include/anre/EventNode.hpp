#pragma once

#include "anre/SecurityEvent.hpp"
#include <cstdint>
#include <vector>

namespace anre {

struct EventNode {
    std::int64_t id = 0;
    SecurityEvent event;
    std::int32_t parentNodeId = -1;
    std::vector<std::int64_t> children;
};

} // namespace anre

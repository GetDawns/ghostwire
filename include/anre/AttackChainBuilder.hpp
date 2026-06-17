#pragma once

#include "anre/AttackChain.hpp"
#include "anre/SecurityEvent.hpp"
#include <string>
#include <vector>

namespace anre {

class AttackChainBuilder {
public:
    AttackChain build(const std::vector<SecurityEvent>& events, std::int64_t chainId);

private:
    static std::vector<std::string> buildTimeline(const std::vector<SecurityEvent>& events);
};

} // namespace anre

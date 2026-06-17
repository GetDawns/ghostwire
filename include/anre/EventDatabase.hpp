#pragma once

#include "anre/AttackChain.hpp"
#include "anre/SecurityEvent.hpp"
#include <string>
#include <vector>

namespace anre {

class EventDatabase {
public:
    explicit EventDatabase(std::string path);

    void saveEvents(const std::vector<SecurityEvent>& events);
    void saveChain(const AttackChain& chain);
    std::vector<SecurityEvent> loadEvents();
    std::vector<AttackChain> loadChains();

private:
    std::string path_;
};

} // namespace anre

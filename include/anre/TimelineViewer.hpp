#pragma once

#include "anre/AttackChain.hpp"

namespace anre {

class TimelineViewer {
public:
    static void printChain(const AttackChain& chain);
    static void printTimeline(const AttackChain& chain);
    static void printNarrative(const AttackChain& chain);
};

} // namespace anre

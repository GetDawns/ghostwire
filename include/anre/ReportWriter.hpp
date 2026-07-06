#pragma once

#include "anre/AttackChain.hpp"

#include <string>

namespace anre {

// Renders an analysed AttackChain into a single self-contained HTML file — the
// kind of thing you can email to whoever handles IT. No external assets, so it
// opens the same everywhere and works offline.
class ReportWriter {
public:
    static std::string toHtml(const AttackChain& chain);
    static bool writeHtml(const AttackChain& chain, const std::string& path);
};

} // namespace anre

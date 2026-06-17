#pragma once

#include "anre/SecurityEvent.hpp"
#include <string>
#include <vector>

namespace anre {

class EventCollector {
public:
    // Snapshot this machine right now: every running process (with its parent)
    // plus active outbound network connections. Works without Sysmon and
    // without administrator rights. This is the "scan my own computer" path.
    std::vector<SecurityEvent> scanLiveSystem();

    std::vector<SecurityEvent> collectFromSysmon(int maxEvents = 500);
    std::vector<SecurityEvent> loadDemoScenario();
    std::vector<SecurityEvent> loadFromFile(const std::string& path);

private:
    static std::string wideToUtf8(const wchar_t* wide);
    static EventCategory categoryFromAction(const std::string& action);
    static MitrePhase inferPhase(const SecurityEvent& event);
};

} // namespace anre

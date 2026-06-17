#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace anre {

enum class EventCategory {
    ProcessCreation,
    FileCreate,
    RegistryModify,
    NetworkConnection,
    LogonFailure,
    Unknown
};

enum class MitrePhase {
    InitialAccess,
    Execution,
    Persistence,
    CommandAndControl,
    Unknown
};

struct SecurityEvent {
    std::int64_t id = 0;
    std::string processName;
    std::int32_t processId = 0;
    std::int32_t parentProcessId = 0;
    std::string parentProcessName;
    std::string action;
    std::string target;
    std::string timestamp;
    EventCategory category = EventCategory::Unknown;
    MitrePhase phase = MitrePhase::Unknown;
    int threatPoints = 0;
};

} // namespace anre

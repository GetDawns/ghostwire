#include "anre/EventCollector.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <winevt.h>
#endif

namespace {

using anre::EventCategory;
using anre::MitrePhase;
using anre::SecurityEvent;

std::string trim(const std::string& value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return {};
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

std::vector<std::string> splitCsvLine(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool inQuotes = false;

    for (char ch : line) {
        if (ch == '"') {
            inQuotes = !inQuotes;
            continue;
        }
        if (ch == ',' && !inQuotes) {
            fields.push_back(trim(field));
            field.clear();
            continue;
        }
        field.push_back(ch);
    }

    fields.push_back(trim(field));
    return fields;
}

EventCategory categoryFromAction(const std::string& action) {
    if (action.find("ProcessCreate") != std::string::npos ||
        action.find("Process Creation") != std::string::npos) {
        return EventCategory::ProcessCreation;
    }
    if (action.find("FileCreate") != std::string::npos ||
        action.find("File Created") != std::string::npos) {
        return EventCategory::FileCreate;
    }
    if (action.find("Registry") != std::string::npos) {
        return EventCategory::RegistryModify;
    }
    if (action.find("NetworkConnect") != std::string::npos ||
        action.find("Network Connection") != std::string::npos) {
        return EventCategory::NetworkConnection;
    }
    if (action.find("LogonFailure") != std::string::npos ||
        action.find("Failed Logon") != std::string::npos) {
        return EventCategory::LogonFailure;
    }
    return EventCategory::Unknown;
}

MitrePhase inferPhase(const SecurityEvent& event) {
    const auto lowerName = [](const std::string& value) {
        std::string copy = value;
        std::transform(copy.begin(), copy.end(), copy.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return copy;
    };

    const std::string process = lowerName(event.processName);
    const std::string parent = lowerName(event.parentProcessName);
    const std::string target = lowerName(event.target);

    if (event.category == EventCategory::NetworkConnection) {
        return MitrePhase::CommandAndControl;
    }
    if (event.category == EventCategory::RegistryModify &&
        (target.find("run") != std::string::npos ||
         target.find("startup") != std::string::npos)) {
        return MitrePhase::Persistence;
    }
    if (parent.find("acrord") != std::string::npos ||
        parent.find("winword") != std::string::npos ||
        parent.find("excel") != std::string::npos ||
        parent.find("powerpnt") != std::string::npos ||
        process.find(".pdf") != std::string::npos) {
        return MitrePhase::InitialAccess;
    }
    if (event.category == EventCategory::ProcessCreation) {
        return MitrePhase::Execution;
    }
    return MitrePhase::Unknown;
}

SecurityEvent makeEvent(
    std::int64_t id,
    const std::string& processName,
    std::int32_t pid,
    std::int32_t ppid,
    const std::string& parentName,
    const std::string& action,
    const std::string& target,
    const std::string& timestamp) {
    SecurityEvent event;
    event.id = id;
    event.processName = processName;
    event.processId = pid;
    event.parentProcessId = ppid;
    event.parentProcessName = parentName;
    event.action = action;
    event.target = target;
    event.timestamp = timestamp;
    event.category = categoryFromAction(action);
    event.phase = inferPhase(event);
    return event;
}

} // namespace

namespace anre {

std::string EventCollector::wideToUtf8(const wchar_t* wide) {
    if (wide == nullptr) {
        return {};
    }

#ifdef _WIN32
    const int length = WideCharToMultiByte(
        CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return {};
    }

    std::string result(static_cast<std::size_t>(length - 1), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wide, -1, result.data(), length, nullptr, nullptr);
    return result;
#else
    (void)wide;
    return {};
#endif
}

EventCategory EventCollector::categoryFromAction(const std::string& action) {
    return ::categoryFromAction(action);
}

MitrePhase EventCollector::inferPhase(const SecurityEvent& event) {
    return ::inferPhase(event);
}

std::vector<SecurityEvent> EventCollector::loadDemoScenario() {
    return {
        makeEvent(1, "Acrobat.exe", 4100, 1200, "explorer.exe", "ProcessCreate", "C:\\Users\\User\\Downloads\\invoice.pdf", "10:00:01"),
        makeEvent(2, "cmd.exe", 4200, 4100, "Acrobat.exe", "ProcessCreate", "C:\\Windows\\System32\\cmd.exe", "10:01:04"),
        makeEvent(3, "powershell.exe", 4300, 4200, "cmd.exe", "ProcessCreate", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "10:01:09"),
        makeEvent(4, "powershell.exe", 4300, 4200, "cmd.exe", "FileCreate", "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe", "10:02:11"),
        makeEvent(5, "malware.exe", 4400, 4300, "powershell.exe", "ProcessCreate", "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe", "10:02:18"),
        makeEvent(6, "malware.exe", 4400, 4300, "powershell.exe", "RegistryValueSet", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "10:02:45"),
        makeEvent(7, "malware.exe", 4400, 4300, "powershell.exe", "NetworkConnect", "203.0.113.44:443", "10:03:02"),
    };
}

std::vector<SecurityEvent> EventCollector::loadFromFile(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return {};
    }

    std::vector<SecurityEvent> events;
    std::string line;
    std::getline(input, line); // header

    std::int64_t id = 1;
    while (std::getline(input, line)) {
        if (trim(line).empty()) {
            continue;
        }

        const auto fields = splitCsvLine(line);
        if (fields.size() < 7) {
            continue;
        }

        events.push_back(makeEvent(
            id++,
            fields[0],
            std::stoi(fields[1]),
            std::stoi(fields[2]),
            fields[3],
            fields[4],
            fields[5],
            fields[6]));
    }

    return events;
}

#ifdef _WIN32
namespace {

std::string extractXmlValue(const std::string& xml, const std::string& key) {
    const std::string openTag = "Name='" + key + "'>" ;
    const auto start = xml.find(openTag);
    if (start == std::string::npos) {
        return {};
    }

    const auto valueStart = start + openTag.size();
    const auto valueEnd = xml.find("</Data>", valueStart);
    if (valueEnd == std::string::npos) {
        return {};
    }

    return xml.substr(valueStart, valueEnd - valueStart);
}

std::string extractTimeCreatedUtc(const std::string& xml) {
    const auto start = xml.find("SystemTime='");
    if (start == std::string::npos) {
        return "unknown";
    }
    const auto valueStart = start + 12;
    const auto valueEnd = xml.find('\'', valueStart);
    if (valueEnd == std::string::npos) {
        return "unknown";
    }
    return xml.substr(valueStart, valueEnd - valueStart);
}

std::string basenameFromPath(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

SecurityEvent parseSysmonXml(std::int64_t id, const std::string& xml) {
    const std::string image = extractXmlValue(xml, "Image");
    const std::string parentImage = extractXmlValue(xml, "ParentImage");
    const std::string destination = extractXmlValue(xml, "DestinationIp");
    const std::string destinationPort = extractXmlValue(xml, "DestinationPort");
    const std::string targetObject = extractXmlValue(xml, "TargetObject");
    const std::string targetFilename = extractXmlValue(xml, "TargetFilename");

    std::string action = "SysmonEvent";
    std::string target;

    if (!destination.empty()) {
        action = "NetworkConnect";
        target = destination + ":" + destinationPort;
    } else if (!targetObject.empty()) {
        action = "RegistryValueSet";
        target = targetObject;
    } else if (!targetFilename.empty()) {
        action = "FileCreate";
        target = targetFilename;
    } else if (!image.empty()) {
        action = "ProcessCreate";
        target = image;
    }

    const std::int32_t pid = std::stoi(extractXmlValue(xml, "ProcessId").empty()
        ? "0" : extractXmlValue(xml, "ProcessId"));
    const std::int32_t ppid = std::stoi(extractXmlValue(xml, "ParentProcessId").empty()
        ? "0" : extractXmlValue(xml, "ParentProcessId"));

    return makeEvent(
        id,
        basenameFromPath(image),
        pid,
        ppid,
        basenameFromPath(parentImage),
        action,
        target,
        extractTimeCreatedUtc(xml));
}

} // namespace
#endif

std::vector<SecurityEvent> EventCollector::collectFromSysmon(int maxEvents) {
#ifdef _WIN32
    const wchar_t* query =
        L"<QueryList>"
        L"  <Query Id='0' Path='Microsoft-Windows-Sysmon/Operational'>"
        L"    <Select Path='Microsoft-Windows-Sysmon/Operational'>"
        L"      *[System[(EventID=1 or EventID=3 or EventID=11 or EventID=13)]]"
        L"    </Select>"
        L"  </Query>"
        L"</QueryList>";

    EVT_HANDLE results = EvtQuery(
        nullptr,
        nullptr,
        query,
        EvtQueryChannelPath | EvtQueryReverseDirection | EvtQueryTolerateQueryErrors);
    if (results == nullptr) {
        return {};
    }

    EVT_HANDLE events[16];
    DWORD returned = 0;
    std::vector<SecurityEvent> collected;
    collected.reserve(static_cast<std::size_t>(maxEvents));

    while (collected.size() < static_cast<std::size_t>(maxEvents) &&
           EvtNext(results, 16, events, 1000, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            DWORD bufferUsed = 0;
            DWORD propertyCount = 0;
            if (!EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount) &&
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::wstring buffer(bufferUsed / sizeof(wchar_t), L'\0');
                if (EvtRender(nullptr, events[i], EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
                    const std::string xml = wideToUtf8(buffer.c_str());
                    collected.push_back(parseSysmonXml(static_cast<std::int64_t>(collected.size() + 1), xml));
                }
            }
            EvtClose(events[i]);
        }
    }

    EvtClose(results);
    std::reverse(collected.begin(), collected.end());
    return collected;
#else
    (void)maxEvents;
    return {};
#endif
}

} // namespace anre

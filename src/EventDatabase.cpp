#include "anre/EventDatabase.hpp"


#include "anre/AttackChainBuilder.hpp"
#include "anre/EventCollector.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace anre {

namespace {

std::string csvEscape(const std::string& value) {
    if (value.find('"') == std::string::npos &&
        value.find(',') == std::string::npos) {
        return value;
    }

    std::string escaped = "\"";
    for (char ch : value) {
        if (ch == '"') {
            escaped += "\"\"";
        } else {
            escaped += ch;
        }
    }
    escaped += '"';
    return escaped;
}

} // namespace

EventDatabase::EventDatabase(std::string path)
    : path_(std::move(path)) {}

void EventDatabase::saveEvents(const std::vector<SecurityEvent>& events) {
    // Non-throwing throughout: if the target folder can't be created or written
    // (e.g. the app was launched with a read-only working directory), we skip
    // saving rather than let a filesystem_error escape and crash the app.
    std::error_code ec;
    std::filesystem::create_directories(path_, ec);

    const std::filesystem::path eventsPath = std::filesystem::path(path_) / "events.csv";
    std::ofstream output(eventsPath);
    if (!output.is_open()) {
        return;
    }
    output << "processName,processId,parentProcessId,parentProcessName,action,target,timestamp,category\n";
    for (const SecurityEvent& event : events) {
        output << csvEscape(event.processName) << ','
               << event.processId << ','
               << event.parentProcessId << ','
               << csvEscape(event.parentProcessName) << ','
               << csvEscape(event.action) << ','
               << csvEscape(event.target) << ','
               << csvEscape(event.timestamp) << ','
               << static_cast<int>(event.category) << '\n';
    }
}

void EventDatabase::saveChain(const AttackChain& chain) {
    std::error_code ec;
    std::filesystem::create_directories(path_, ec);

    const std::filesystem::path chainPath =
        std::filesystem::path(path_) / ("chain_" + std::to_string(chain.id) + ".txt");

    std::ofstream output(chainPath);
    if (!output.is_open()) {
        return;
    }
    output << chain.title << '\n';
    output << "Risk Score: " << chain.riskScore << "/100\n";
    output << "Threat Level: " << chain.threatLevel << "\n\n";

    for (const NarrativeSection& section : chain.narrative) {
        output << section.phaseLabel << ":\n";
        for (const std::string& line : section.lines) {
            output << "  - " << line << '\n';
        }
        output << '\n';
    }

    output << "Timeline:\n";
    for (const std::string& entry : chain.timeline) {
        output << "  " << entry << '\n';
    }
}

std::vector<SecurityEvent> EventDatabase::loadEvents() {
    EventCollector collector;
    const std::filesystem::path eventsPath = std::filesystem::path(path_) / "events.csv";
    return collector.loadFromFile(eventsPath.string());
}

std::vector<AttackChain> EventDatabase::loadChains() {
    std::vector<AttackChain> chains;
    const std::filesystem::path directory(path_);
    std::error_code ec;
    if (!std::filesystem::exists(directory, ec)) {
        return chains;
    }

    AttackChainBuilder builder;
    const auto events = loadEvents();
    if (!events.empty()) {
        chains.push_back(builder.build(events, 1));
    }

    return chains;
}

} // namespace anre

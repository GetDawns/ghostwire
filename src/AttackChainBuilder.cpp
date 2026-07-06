#include "anre/AttackChainBuilder.hpp"

#include "anre/NarrativeGenerator.hpp"
#include "anre/RelationshipEngine.hpp"
#include "anre/ThreatScoringEngine.hpp"

#include <sstream>

namespace anre {

std::vector<std::string> AttackChainBuilder::buildTimeline(
    const std::vector<SecurityEvent>& events) {
    std::vector<std::string> timeline;
    timeline.reserve(events.size());

    for (const SecurityEvent& event : events) {
        std::ostringstream line;
        line << event.timestamp << "  ";

        switch (event.category) {
        case EventCategory::ProcessCreation:
            line << event.processName << " spawned";
            if (!event.parentProcessName.empty()) {
                line << " (parent: " << event.parentProcessName << ")";
            }
            break;
        case EventCategory::FileCreate:
            line << event.processName << " created file " << event.target;
            break;
        case EventCategory::RegistryModify:
            line << event.processName << " modified registry " << event.target;
            break;
        case EventCategory::NetworkConnection:
            line << event.processName << " connected to " << event.target;
            break;
        case EventCategory::LogonFailure:
            line << "Failed logon attempt";
            break;
        default:
            line << event.action;
            break;
        }

        timeline.push_back(line.str());
    }

    return timeline;
}

AttackChain AttackChainBuilder::build(
    const std::vector<SecurityEvent>& events,
    std::int64_t chainId) {
    RelationshipEngine relationships;
    NarrativeGenerator narrativeGenerator;
    ThreatScoringEngine scorer;

    AttackChain chain;
    chain.id = chainId;
    chain.title = "Attack Chain #" + std::to_string(chainId);
    chain.events = events;
    chain.graph = relationships.buildGraph(events);
    chain.narrative = narrativeGenerator.generate(events, chain.graph);

    const AnalysisResult analysis = scorer.analyze(events);
    chain.riskScore = analysis.score;
    chain.threatLevel = analysis.level;
    chain.findings = analysis.findings;
    chain.timeline = buildTimeline(events);

    chain.processCount = static_cast<int>(chain.graph.size());
    for (const SecurityEvent& event : events) {
        if (event.category == EventCategory::NetworkConnection) {
            ++chain.networkCount;
        }
    }
    return chain;
}

} // namespace anre

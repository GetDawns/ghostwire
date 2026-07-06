#include "anre/RelationshipEngine.hpp"

#include <algorithm>
#include <cstddef>
#include <unordered_map>

namespace anre {

std::vector<EventNode> RelationshipEngine::buildGraph(
    const std::vector<SecurityEvent>& events) {
    // One node per process (PID), not per event. A single process usually
    // generates several events (spawn, file write, network, ...) and we don't
    // want the same process showing up four times in the tree. We key off the
    // first event we see for each PID and let that represent the process.
    std::vector<EventNode> nodes;
    std::unordered_map<std::int32_t, std::int64_t> pidToNodeId;

    for (const SecurityEvent& event : events) {
        if (event.processId > 0 && pidToNodeId.count(event.processId)) {
            continue; // already have a node for this process
        }

        EventNode node;
        node.id = event.id;
        node.event = event;
        nodes.push_back(node);

        if (event.processId > 0) {
            pidToNodeId[event.processId] = node.id;
        }
    }

    // Map node id -> position, so linking a child to its parent is O(1) rather
    // than a linear scan of every node (which made a big import O(n^2)).
    std::unordered_map<std::int64_t, std::size_t> nodeIndex;
    nodeIndex.reserve(nodes.size());
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        nodeIndex.emplace(nodes[i].id, i);
    }

    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const std::int32_t parentPid = nodes[i].event.parentProcessId;
        if (parentPid <= 0) {
            continue;
        }

        const auto pidIt = pidToNodeId.find(parentPid);
        if (pidIt == pidToNodeId.end() || pidIt->second == nodes[i].id) {
            continue; // unknown parent, or self-reference — skip
        }

        const auto idxIt = nodeIndex.find(pidIt->second);
        if (idxIt == nodeIndex.end()) {
            continue;
        }

        nodes[i].parentNodeId = static_cast<std::int32_t>(pidIt->second);
        nodes[idxIt->second].children.push_back(nodes[i].id);
    }

    std::sort(nodes.begin(), nodes.end(), [](const EventNode& a, const EventNode& b) {
        return a.event.timestamp < b.event.timestamp;
    });

    return nodes;
}

} // namespace anre

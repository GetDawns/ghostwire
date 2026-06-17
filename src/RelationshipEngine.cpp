#include "anre/RelationshipEngine.hpp"

#include <algorithm>
#include <unordered_map>

namespace anre {

std::int64_t RelationshipEngine::findNodeByPid(
    const std::vector<EventNode>& nodes,
    std::int32_t pid) {
    for (const EventNode& node : nodes) {
        if (node.event.processId == pid) {
            return node.id;
        }
    }
    return -1;
}

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

    for (EventNode& node : nodes) {
        if (node.event.parentProcessId <= 0) {
            continue;
        }

        const auto it = pidToNodeId.find(node.event.parentProcessId);
        if (it == pidToNodeId.end() || it->second == node.id) {
            continue; // unknown parent, or self-reference — skip
        }

        node.parentNodeId = static_cast<std::int32_t>(it->second);
        for (EventNode& parent : nodes) {
            if (parent.id == it->second) {
                parent.children.push_back(node.id);
                break;
            }
        }
    }

    std::sort(nodes.begin(), nodes.end(), [](const EventNode& a, const EventNode& b) {
        return a.event.timestamp < b.event.timestamp;
    });

    return nodes;
}

} // namespace anre

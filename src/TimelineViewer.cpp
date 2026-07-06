#include "anre/TimelineViewer.hpp"
#include "anre/NarrativeGenerator.hpp"
#include <iostream>

namespace anre {

void TimelineViewer::printTimeline(const AttackChain& chain) {
    std::cout << "\nTimeline\n";
    std::cout << "--------\n";
    for (const std::string& entry : chain.timeline) {
        std::cout << entry << '\n';
    }
}

void TimelineViewer::printNarrative(const AttackChain& chain) {
    std::cout << "\nAttack Narrative\n";
    std::cout << "----------------\n";
    for (const NarrativeSection& section : chain.narrative) {
        std::cout << section.phaseLabel << ":\n";
        for (const std::string& line : section.lines) {
            std::cout << "  - " << line << '\n';
        }
    }
}

void TimelineViewer::printChain(const AttackChain& chain) {
    std::cout << "\n========================================\n";
    std::cout << chain.title << '\n';
    std::cout << "========================================\n";

    printNarrative(chain);

    std::cout << "\nProcess Graph\n";
    std::cout << "-------------\n";
    for (const EventNode& node : chain.graph) {
        std::cout << node.event.processName << " [pid " << node.event.processId << ']';
        if (!node.children.empty()) {
            std::cout << " -> ";
            for (std::size_t i = 0; i < node.children.size(); ++i) {
                for (const EventNode& child : chain.graph) {
                    if (child.id == node.children[i]) {
                        if (i > 0) {
                            std::cout << ", ";
                        }
                        std::cout << child.event.processName;
                    }
                }
            }
        }
        std::cout << '\n';
    }

    printTimeline(chain);

    std::cout << "\nWhat stood out\n";
    std::cout << "-------------\n";
    if (chain.findings.empty()) {
        std::cout << "  Nothing — no suspicious process chains or connections found.\n";
    } else {
        for (const Finding& finding : chain.findings) {
            std::cout << "  [" << severityName(finding.severity) << "] " << finding.title << '\n';
            std::cout << "      " << finding.detail << '\n';
            if (!finding.mitreId.empty()) {
                std::cout << "      ATT&CK " << finding.mitreId << " — " << finding.mitreName << '\n';
            }
        }
    }

    std::cout << "\nRisk Score: " << chain.riskScore << "/100\n";
    std::cout << "Threat Level: " << chain.threatLevel << '\n';

    NarrativeGenerator generator;
    std::cout << "\nSummary\n";
    std::cout << generator.generateSummary(chain) << '\n';
}

} // namespace anre

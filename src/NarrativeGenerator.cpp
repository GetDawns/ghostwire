#include "anre/NarrativeGenerator.hpp"
#include "anre/ThreatScoringEngine.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace anre {

std::string NarrativeGenerator::lower(const std::string& value) {
    std::string copy = value;
    std::transform(copy.begin(), copy.end(), copy.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return copy;
}

bool NarrativeGenerator::contains(const std::string& haystack, const std::string& needle) {
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::string NarrativeGenerator::phaseLabel(MitrePhase phase) {
    switch (phase) {
    case MitrePhase::InitialAccess:
        return "Initial Access";
    case MitrePhase::Execution:
        return "Execution";
    case MitrePhase::Persistence:
        return "Persistence";
    case MitrePhase::CommandAndControl:
        return "Command & Control";
    default:
        return "Observed Activity";
    }
}

std::string NarrativeGenerator::describeProcessSpawn(
    const std::string& parent,
    const std::string& child) {
    // Both Adobe Acrobat (Acrobat.exe) and Acrobat Reader (AcroRd32.exe) count
    // as a PDF reader here — match on either so the demo and real Sysmon data
    // produce the same story.
    const bool parentIsPdfReader = contains(parent, "acrord") || contains(parent, "acrobat");

    if (parentIsPdfReader && contains(child, "cmd")) {
        return "PDF reader launched cmd.exe";
    }
    if (parentIsPdfReader && contains(child, "powershell")) {
        return "PDF reader launched PowerShell";
    }
    if ((contains(parent, "winword") || contains(parent, "excel") || contains(parent, "powerpnt")) &&
        contains(child, "powershell")) {
        return "Office document launched PowerShell";
    }
    if (contains(parent, "cmd") && contains(child, "powershell")) {
        return "cmd.exe launched PowerShell";
    }
    if (contains(parent, "powershell") && contains(child, "malware")) {
        return "PowerShell executed downloaded malware";
    }
    // No recognised pattern. Return empty so the narrative stays focused on
    // genuinely interesting spawns — otherwise a live scan of a healthy PC
    // would list hundreds of normal "services.exe launched svchost.exe" lines.
    return {};
}

std::vector<NarrativeSection> NarrativeGenerator::generate(
    const std::vector<SecurityEvent>& events,
    const std::vector<EventNode>& graph) {
    (void)graph;

    std::vector<NarrativeSection> sections;
    auto addLine = [&](MitrePhase phase, const std::string& line) {
        for (NarrativeSection& section : sections) {
            if (section.phase == phase) {
                if (std::find(section.lines.begin(), section.lines.end(), line) == section.lines.end()) {
                    section.lines.push_back(line);
                }
                return;
            }
        }

        NarrativeSection section;
        section.phase = phase;
        section.phaseLabel = phaseLabel(phase);
        section.lines.push_back(line);
        sections.push_back(section);
    };

    for (const SecurityEvent& event : events) {
        switch (event.category) {
        case EventCategory::ProcessCreation:
            if (contains(event.parentProcessName, "acrord") ||
                contains(event.parentProcessName, "acrobat") ||
                contains(event.target, ".pdf")) {
                addLine(MitrePhase::InitialAccess, "A malicious PDF was opened");
            }
            if (!event.parentProcessName.empty()) {
                const std::string description =
                    describeProcessSpawn(event.parentProcessName, event.processName);
                if (!description.empty()) {
                    addLine(
                        event.phase == MitrePhase::Unknown ? MitrePhase::Execution : event.phase,
                        description);
                }
            }
            break;
        case EventCategory::FileCreate:
            if (contains(event.processName, "powershell") &&
                contains(event.target, "malware")) {
                addLine(MitrePhase::Execution, "PowerShell downloaded malware.exe");
            } else if (contains(event.target, ".exe")) {
                addLine(MitrePhase::Execution, event.processName + " created executable " + event.target);
            }
            break;
        case EventCategory::RegistryModify:
            addLine(MitrePhase::Persistence, "Malware made a startup registry key for persistence");
            break;
        case EventCategory::NetworkConnection:
            // Only call out connections from processes that have no business
            // reaching the internet. Normal apps (browsers, etc.) talk to
            // hundreds of hosts — listing them all isn't a narrative.
            if (ThreatScoringEngine::isSuspiciousProcess(event.processName)) {
                addLine(
                    MitrePhase::CommandAndControl,
                    event.processName + " connected to external host " + event.target);
            }
            break;
        case EventCategory::LogonFailure:
            addLine(MitrePhase::InitialAccess, "Repeated failed login attempts detected");
            break;
        default:
            break;
        }
    }

    const auto phaseOrder = [](MitrePhase phase) {
        switch (phase) {
        case MitrePhase::InitialAccess:
            return 0;
        case MitrePhase::Execution:
            return 1;
        case MitrePhase::Persistence:
            return 2;
        case MitrePhase::CommandAndControl:
            return 3;
        default:
            return 4;
        }
    };

    std::sort(sections.begin(), sections.end(), [&](const NarrativeSection& a, const NarrativeSection& b) {
        return phaseOrder(a.phase) < phaseOrder(b.phase);
    });

    return sections;
}

std::string NarrativeGenerator::generateSummary(const AttackChain& chain) {
    // Nothing matched a known-bad pattern — say so plainly instead of inventing
    // an attack. This is the normal result of scanning a healthy machine.
    if (chain.findings.empty()) {
        return "Nothing in this snapshot matches a known attack pattern. The "
               "processes and connections here look normal. (This is a quick "
               "heuristic check, not a full antivirus scan.)";
    }

    // Some findings don't come with a narrative arc — e.g. a live scan that
    // spotted an unsigned program in a temp folder but no full kill chain. In
    // that case, summarise straight from the findings instead of forcing a
    // "the activity started when..." story that never happened.
    bool hasNarrative = false;
    for (const NarrativeSection& section : chain.narrative) {
        if (!section.lines.empty()) {
            hasNarrative = true;
            break;
        }
    }
    if (!hasNarrative) {
        std::ostringstream plain;
        plain << "This scan turned up " << chain.findings.size() << " thing"
              << (chain.findings.size() == 1 ? "" : "s") << " worth a look";
        const std::size_t show = chain.findings.size() < 3 ? chain.findings.size() : 3;
        for (std::size_t i = 0; i < show; ++i) {
            plain << (i == 0 ? ": " : (i + 1 == show ? "; and " : "; "))
                  << chain.findings[i].title;
        }
        plain << ". Risk score: " << chain.riskScore << "/100 (" << chain.threatLevel << ").";
        return plain.str();
    }

    std::ostringstream summary;
    summary << "The activity likely started";

    // Lower-case only the first character so acronyms like "PDF" survive
    // ("A malicious PDF was opened" -> "a malicious PDF was opened").
    const auto decapitalize = [](std::string text) {
        if (!text.empty()) {
            text[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(text[0])));
        }
        return text;
    };
    const auto capitalize = [](std::string text) {
        if (!text.empty()) {
            text[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(text[0])));
        }
        return text;
    };

    bool foundStart = false;
    for (const NarrativeSection& section : chain.narrative) {
        if (section.phase == MitrePhase::InitialAccess && !section.lines.empty()) {
            summary << " when " << decapitalize(section.lines.front());
            foundStart = true;
            break;
        }
    }

    if (!foundStart) {
        summary << " from suspicious process activity";
    }

    std::vector<std::string> middle;
    for (const NarrativeSection& section : chain.narrative) {
        if (section.phase == MitrePhase::Execution ||
            section.phase == MitrePhase::Persistence ||
            section.phase == MitrePhase::CommandAndControl) {
            middle.insert(middle.end(), section.lines.begin(), section.lines.end());
        }
    }

    if (!middle.empty()) {
        summary << ". The chain then ";
        for (std::size_t i = 0; i < middle.size(); ++i) {
            if (i > 0) {
                summary << (i + 1 == middle.size() ? ", and " : ", ");
            }
            // Keep the original wording (so "PowerShell", "cmd.exe" etc. read
            // naturally); just make sure the clause starts with a capital.
            summary << capitalize(middle[i]);
        }
    }

    summary << ". Risk score: " << chain.riskScore << "/100 (" << chain.threatLevel << ").";
    return summary.str();
}

} // namespace anre

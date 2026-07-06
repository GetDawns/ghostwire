#include "anre/AttackChainBuilder.hpp"
#include "anre/EventCollector.hpp"
#include "anre/EventDatabase.hpp"
#include "anre/ReportWriter.hpp"
#include "anre/SignatureChecker.hpp"
#include "anre/ThreatScoringEngine.hpp"
#include "anre/TimelineViewer.hpp"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

void printUsage() {
    std::cout << "Ghostwire ANRE 2.0 - Attack Narrative Reconstruction Engine\n\n";
    std::cout << "Usage:\n";
    std::cout << "  anre                      Scan this computer (default - no setup needed)\n";
    std::cout << "  anre scan                 Same as above: check running processes + connections\n";
    std::cout << "  anre watch [seconds]      Re-scan on an interval, alert on NEW findings (default 60s)\n";
    std::cout << "  anre demo                 Run the built-in malicious-PDF example\n";
    std::cout << "  anre sysmon [maxEvents]   Collect live Sysmon events (requires admin + Sysmon)\n";
    std::cout << "  anre import <csvFile>     Build a chain from a CSV event file\n";
    std::cout << "  anre sig <exePath>        Check one file's Authenticode signature and publisher\n";
    std::cout << "  anre help                 Show this help message\n";
}

const char* signatureText(anre::SignatureStatus status) {
    switch (status) {
    case anre::SignatureStatus::SignedTrusted:   return "signed & trusted";
    case anre::SignatureStatus::SignedUntrusted: return "signed but NOT trusted";
    case anre::SignatureStatus::Unsigned:        return "UNSIGNED";
    default:                                     return "unknown";
    }
}

int runSig(const std::string& path) {
    if (!anre::SignatureChecker::available()) {
        std::cout << "Signature checking is only available on Windows.\n";
        return 1;
    }
    const anre::SignatureInfo info = anre::SignatureChecker::check(path);
    std::cout << path << "\n  Signature: " << signatureText(info.status) << "\n";
    std::cout << "  Publisher: " << (info.publisher.empty() ? "(none)" : info.publisher) << "\n";
    return 0;
}

// Re-scan on an interval and print only findings we haven't seen before, so a
// quiet machine stays quiet and a new suspicious process stands out.
int runWatch(int intervalSeconds) {
    using namespace anre;
    if (intervalSeconds < 5) {
        intervalSeconds = 5;
    }

    std::cout << "Watching this computer every " << intervalSeconds
              << "s. New findings will appear below. Press Ctrl+C to stop.\n";

    EventCollector collector;
    AttackChainBuilder builder;
    std::unordered_set<std::string> seen;
    std::int64_t chainId = 1;
    bool first = true;

    while (true) {
        const auto events = collector.scanLiveSystem();
        if (!events.empty()) {
            const AttackChain chain = builder.build(events, chainId++);
            int fresh = 0;
            for (const Finding& finding : chain.findings) {
                if (seen.insert(finding.key()).second) {
                    std::cout << "  [" << severityName(finding.severity) << "] "
                              << finding.title << "\n      " << finding.detail << "\n";
                    ++fresh;
                }
            }
            if (first && fresh == 0) {
                std::cout << "  (baseline is clean - nothing suspicious right now)\n";
            }
        }
        first = false;
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
    }
}

} // namespace

int main(int argc, char* argv[]) {
    using namespace anre;

    // No argument -> scan this computer. That's what most people want when they
    // just run the tool: "is anything wrong with my machine right now?"
    const std::string mode = (argc >= 2) ? argv[1] : "scan";
    if (mode == "help" || mode == "--help" || mode == "-h") {
        printUsage();
        return 0;
    }
    if (mode == "sig") {
        if (argc < 3) {
            std::cout << "Missing file path. Usage: anre sig <exePath>\n";
            return 1;
        }
        return runSig(argv[2]);
    }
    if (mode == "watch") {
        return runWatch(argc >= 3 ? std::atoi(argv[2]) : 60);
    }

    EventCollector collector;
    AttackChainBuilder builder;
    EventDatabase database("data");

    std::vector<SecurityEvent> events;
    std::string source = "This computer";

    if (mode == "scan") {
        std::cout << "Scanning this computer - running processes and active connections...\n";
        try {
            events = collector.scanLiveSystem();
        } catch (const std::exception& e) {
            std::cout << "The scan hit an error: " << e.what() << "\n";
            events.clear();
        }
        if (events.empty()) {
            std::cout << "Could not read the process list on this system.\n";
            std::cout << "Showing the built-in example instead...\n\n";
            events = collector.loadDemoScenario();
            source = "Example attack";
        } else {
            std::cout << "Scanned " << events.size() << " processes and connections.\n";
        }
    } else if (mode == "demo") {
        events = collector.loadDemoScenario();
        source = "Example attack";
        std::cout << "Loaded demo scenario with " << events.size() << " events.\n";
    } else if (mode == "sysmon") {
        int maxEvents = 200;
        if (argc >= 3) {
            maxEvents = std::atoi(argv[2]);
        }

        events = collector.collectFromSysmon(maxEvents);
        source = "Sysmon";
        if (events.empty()) {
            std::cout << "No Sysmon events collected.\n";
            std::cout << "Make sure Sysmon is installed and run this program as Administrator.\n";
            std::cout << "Falling back to demo scenario...\n\n";
            events = collector.loadDemoScenario();
            source = "Example attack";
        } else {
            std::cout << "Collected " << events.size() << " Sysmon events.\n";
        }
    } else if (mode == "import") {
        if (argc < 3) {
            std::cout << "Missing CSV file path.\n";
            printUsage();
            return 1;
        }

        events = collector.loadFromFile(argv[2]);
        source = argv[2];
        if (events.empty()) {
            std::cout << "Could not load events from " << argv[2] << '\n';
            return 1;
        }

        std::cout << "Imported " << events.size() << " events from CSV.\n";
    } else {
        std::cout << "Unknown mode: " << mode << '\n';
        printUsage();
        return 1;
    }

    AttackChain chain = builder.build(events, 42);
    chain.source = source;
    database.saveEvents(events);
    database.saveChain(chain);
    ReportWriter::writeHtml(chain, "data/report.html");

    TimelineViewer::printChain(chain);

    std::cout << "\nSaved events to data/events.csv\n";
    std::cout << "Saved narrative to data/chain_42.txt\n";
    std::cout << "Saved shareable report to data/report.html\n";

    return 0;
}

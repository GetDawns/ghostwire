#include "anre/AttackChainBuilder.hpp"
#include "anre/EventCollector.hpp"
#include "anre/EventDatabase.hpp"
#include "anre/TimelineViewer.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

void printUsage() {
    std::cout << "Ghostwire ANRE - Attack Narrative Reconstruction Engine\n\n";
    std::cout << "Usage:\n";
    std::cout << "  anre                      Scan this computer (default — no setup needed)\n";
    std::cout << "  anre scan                 Same as above: check running processes + connections\n";
    std::cout << "  anre demo                 Run the built-in malicious-PDF example\n";
    std::cout << "  anre sysmon [maxEvents]   Collect live Sysmon events (requires admin + Sysmon)\n";
    std::cout << "  anre import <csvFile>     Build a chain from a CSV event file\n";
    std::cout << "  anre help                 Show this help message\n";
}

} // namespace

int main(int argc, char* argv[]) {
    using namespace anre;

    // No argument → scan this computer. That's what most people want when they
    // just run the tool: "is anything wrong with my machine right now?"
    const std::string mode = (argc >= 2) ? argv[1] : "scan";
    if (mode == "help" || mode == "--help" || mode == "-h") {
        printUsage();
        return 0;
    }

    EventCollector collector;
    AttackChainBuilder builder;
    EventDatabase database("data");

    std::vector<SecurityEvent> events;

    if (mode == "scan") {
        std::cout << "Scanning this computer — running processes and active connections...\n";
        events = collector.scanLiveSystem();
        if (events.empty()) {
            std::cout << "Could not read the process list on this system.\n";
            std::cout << "Showing the built-in example instead...\n\n";
            events = collector.loadDemoScenario();
        } else {
            std::cout << "Scanned " << events.size() << " processes and connections.\n";
        }
    } else if (mode == "demo") {
        events = collector.loadDemoScenario();
        std::cout << "Loaded demo scenario with " << events.size() << " events.\n";
    } else if (mode == "sysmon") {
        int maxEvents = 200;
        if (argc >= 3) {
            maxEvents = std::stoi(argv[2]);
        }

        events = collector.collectFromSysmon(maxEvents);
        if (events.empty()) {
            std::cout << "No Sysmon events collected.\n";
            std::cout << "Make sure Sysmon is installed and run this program as Administrator.\n";
            std::cout << "Falling back to demo scenario...\n\n";
            events = collector.loadDemoScenario();
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

    const AttackChain chain = builder.build(events, 42);
    database.saveEvents(events);
    database.saveChain(chain);

    TimelineViewer::printChain(chain);

    std::cout << "\nSaved events to data/events.csv\n";
    std::cout << "Saved narrative to data/chain_42.txt\n";

    return 0;
}

// Ghostwire stress + fuzz harness. Hammers the core engine (CSV parsing,
// scoring/analysis, relationship graph, report generation, signature checks)
// with malformed and adversarial input and asserts invariants. Links only
// anre_core, so it builds without Qt.
//
//   build:  configured as target `ghostwire_stress`
//   run:    ghostwire_stress.exe   (exit code != 0 means a check failed)

#include "anre/AttackChainBuilder.hpp"
#include "anre/EventCollector.hpp"
#include "anre/NarrativeGenerator.hpp"
#include "anre/ReportWriter.hpp"
#include "anre/RelationshipEngine.hpp"
#include "anre/SignatureChecker.hpp"
#include "anre/ThreatScoringEngine.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace anre;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool cond, const std::string& what) {
    if (cond) {
        ++g_pass;
    } else {
        ++g_fail;
        std::cout << "  FAIL: " << what << "\n";
    }
}

std::int64_t g_evId = 0;

SecurityEvent makeEv(EventCategory cat, const std::string& name, int pid, int ppid,
                     const std::string& parent, const std::string& target,
                     SignatureStatus sig = SignatureStatus::Unknown,
                     const std::string& imagePath = "") {
    SecurityEvent e;
    e.id = ++g_evId;   // distinct ids, like the real collector produces
    e.processName = name;
    e.processId = pid;
    e.parentProcessId = ppid;
    e.parentProcessName = parent;
    e.target = target;
    e.imagePath = imagePath;
    e.category = cat;
    e.signature = sig;
    e.timestamp = "10:00:00";
    return e;
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    out << content;
}

const std::filesystem::path& tmpDir() {
    static std::filesystem::path dir = std::filesystem::temp_directory_path() / "gw_stress";
    std::filesystem::create_directories(dir);
    return dir;
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------

void testDemoInvariants() {
    std::cout << "[demo invariants]\n";
    EventCollector collector;
    AttackChainBuilder builder;
    const AttackChain chain = builder.build(collector.loadDemoScenario(), 42);

    check(chain.riskScore == 100, "demo risk score is 100");
    check(chain.threatLevel == "Critical", "demo verdict is Critical");
    check(!chain.findings.empty(), "demo has findings");
    check(chain.findings.front().severity == Severity::Critical, "top finding is Critical");
    check(chain.narrative.size() == 4, "demo narrative has 4 phases");

    bool allTagged = true;
    for (const Finding& f : chain.findings) {
        if (f.mitreId.empty() || f.title.empty()) allTagged = false;
    }
    check(allTagged, "every finding has a MITRE id and title");

    // findings must be sorted most-severe first
    bool sorted = true;
    for (std::size_t i = 1; i < chain.findings.size(); ++i) {
        if (static_cast<int>(chain.findings[i - 1].severity) <
            static_cast<int>(chain.findings[i].severity)) sorted = false;
    }
    check(sorted, "findings sorted by severity descending");
}

void testCleanCase() {
    std::cout << "[clean case]\n";
    ThreatScoringEngine engine;
    const AnalysisResult empty = engine.analyze({});
    check(empty.findings.empty(), "empty input -> no findings");
    check(empty.level == "Clean", "empty input -> Clean verdict");
    check(empty.score == 5, "empty input -> score 5");

    // A single ordinary signed process should not be flagged.
    std::vector<SecurityEvent> benign = {
        makeEv(EventCategory::ProcessCreation, "notepad.exe", 100, 4, "explorer.exe",
               "C:\\Windows\\System32\\notepad.exe", SignatureStatus::SignedTrusted,
               "C:\\Windows\\System32\\notepad.exe")};
    const AnalysisResult r = engine.analyze(benign);
    check(r.findings.empty(), "signed system process -> no findings");
}

void testSignatureAwareness() {
    std::cout << "[signature awareness]\n";
    ThreatScoringEngine engine;

    // Signed app in Downloads -> quiet.
    auto signedDl = engine.analyze({makeEv(EventCategory::ProcessCreation, "Setup.exe", 10, 4,
        "explorer.exe", "C:\\Users\\me\\Downloads\\Setup.exe", SignatureStatus::SignedTrusted,
        "C:\\Users\\me\\Downloads\\Setup.exe")});
    check(signedDl.findings.empty(), "signed installer in Downloads is not flagged");

    // Unsigned app in Downloads -> flagged.
    auto unsignedDl = engine.analyze({makeEv(EventCategory::ProcessCreation, "free_vbucks.exe", 11, 4,
        "explorer.exe", "C:\\Users\\me\\Downloads\\free_vbucks.exe", SignatureStatus::Unsigned,
        "C:\\Users\\me\\Downloads\\free_vbucks.exe")});
    check(!unsignedDl.findings.empty(), "unsigned binary in Downloads is flagged");

    // Masquerade: svchost outside System32.
    auto masq = engine.analyze({makeEv(EventCategory::ProcessCreation, "svchost.exe", 12, 4,
        "explorer.exe", "C:\\Users\\me\\AppData\\Local\\Temp\\svchost.exe", SignatureStatus::Unsigned,
        "C:\\Users\\me\\AppData\\Local\\Temp\\svchost.exe")});
    bool foundMasq = false;
    for (const Finding& f : masq.findings) if (contains(f.mitreId, "T1036")) foundMasq = true;
    check(foundMasq, "svchost outside System32 -> masquerade finding");

    // Real svchost in System32 -> no masquerade.
    auto realSvc = engine.analyze({makeEv(EventCategory::ProcessCreation, "svchost.exe", 13, 4,
        "services.exe", "C:\\Windows\\System32\\svchost.exe", SignatureStatus::SignedTrusted,
        "C:\\Windows\\System32\\svchost.exe")});
    check(realSvc.findings.empty(), "real svchost in System32 -> not flagged");

    // Double extension.
    auto dbl = engine.analyze({makeEv(EventCategory::ProcessCreation, "invoice.pdf.exe", 14, 4,
        "explorer.exe", "C:\\Users\\me\\Downloads\\invoice.pdf.exe", SignatureStatus::Unsigned,
        "C:\\Users\\me\\Downloads\\invoice.pdf.exe")});
    bool foundDbl = false;
    for (const Finding& f : dbl.findings) if (contains(f.mitreId, "T1036.007")) foundDbl = true;
    check(foundDbl, "double-extension lure detected");
}

void testCsvRobustness() {
    std::cout << "[csv robustness]\n";
    EventCollector collector;
    const auto dir = tmpDir();

    struct Case { std::string name; std::string content; };
    const std::vector<Case> cases = {
        {"empty", ""},
        {"header_only", "processName,processId,parentProcessId,parentProcessName,action,target,timestamp\n"},
        {"short_rows", "a,b,c\nx,y\n\n"},
        {"nonnumeric_pid", "h\nfoo.exe,NOTANUMBER,ALSONOT,bar.exe,ProcessCreate,C:\\x,10:00\n"},
        {"huge_pid", "h\nfoo.exe,999999999999999999999,88,bar.exe,ProcessCreate,C:\\x,10:00\n"},
        {"negative_pid", "h\nfoo.exe,-5,-9,bar.exe,ProcessCreate,C:\\x,10:00\n"},
        {"quoted_commas", "h\npowershell.exe,10,5,\"chrome.exe, inc\",NetworkConnect,\"1.2.3.4:443\",10:00\n"},
        {"all_empty_fields", "h\n,,,,,,\n"},
        {"unicode", "h\n\xE2\x9C\x93.exe,10,5,\xF0\x9F\x92\xA9.exe,ProcessCreate,C:\\\xC3\xA9,10:00\n"},
        {"crlf", "h\r\nfoo.exe,10,5,bar.exe,ProcessCreate,C:\\x,10:00\r\n"},
        {"trailing_garbage", "h\nfoo.exe,10,5,bar.exe,ProcessCreate,C:\\x,10:00,EXTRA,MORE,FIELDS\n"},
    };

    AttackChainBuilder builder;
    for (const Case& c : cases) {
        const auto path = dir / (c.name + ".csv");
        writeFile(path, c.content);
        bool crashed = false;
        std::size_t count = 0;
        try {
            const auto events = collector.loadFromFile(path.string());
            count = events.size();
            const AttackChain chain = builder.build(events, 1);
            ReportWriter::toHtml(chain); // must not throw either
        } catch (...) {
            crashed = true;
        }
        check(!crashed, "csv '" + c.name + "' parsed without throwing (" + std::to_string(count) + " events)");
    }

    // Non-existent file.
    bool crashed = false;
    try {
        const auto events = collector.loadFromFile((dir / "does_not_exist.csv").string());
        check(events.empty(), "missing file -> empty result");
    } catch (...) { crashed = true; }
    check(!crashed, "missing file did not throw");

    // A huge file: 200k rows.
    {
        std::string big = "processName,processId,parentProcessId,parentProcessName,action,target,timestamp\n";
        big.reserve(200000 * 60);
        for (int i = 0; i < 200000; ++i) {
            big += "p" + std::to_string(i) + ".exe," + std::to_string(i % 5000) + "," +
                   std::to_string((i + 1) % 5000) + ",parent.exe,ProcessCreate,C:\\x,10:00\n";
        }
        const auto path = dir / "huge.csv";
        writeFile(path, big);
        const auto start = std::chrono::steady_clock::now();
        const auto events = collector.loadFromFile(path.string());
        AttackChainBuilder b;
        const AttackChain chain = b.build(events, 1);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        std::cout << "  (200k rows: " << events.size() << " events, build " << ms << " ms)\n";
        check(events.size() == 200000, "200k rows all parsed");
        check(ms < 8000, "200k-event pipeline finishes under 8s");
    }
}

void testReportEscaping() {
    std::cout << "[report html escaping]\n";
    AttackChainBuilder builder;

    // Craft events whose process name / target carry HTML that must be neutralised.
    std::vector<SecurityEvent> evil = {
        makeEv(EventCategory::ProcessCreation, "<script>powershell</script>", 10, 5, "WINWORD.EXE",
               "C:\\Users\\x\\AppData\\Local\\Temp\\<script>.exe", SignatureStatus::Unsigned,
               "C:\\Users\\x\\AppData\\Local\\Temp\\<script>.exe"),
        makeEv(EventCategory::NetworkConnection, "malware.exe", 11, 10, "",
               "6.6.6.6:443\"><img src=x onerror=alert(1)>"),
    };
    const AttackChain chain = builder.build(evil, 7);
    const std::string html = ReportWriter::toHtml(chain);

    check(!contains(html, "<script>powershell"), "process-name <script> is escaped in report");
    check(!contains(html, "<img src=x onerror"), "target <img onerror> is escaped in report");
    check(contains(html, "&lt;script&gt;"), "report contains the escaped form");

    // Empty chain report must not throw and must be a full document.
    AttackChain emptyChain = builder.build({}, 1);
    const std::string emptyHtml = ReportWriter::toHtml(emptyChain);
    check(contains(emptyHtml, "</html>"), "empty-chain report is a complete document");
}

void testGraphEdgeCases() {
    std::cout << "[relationship graph]\n";
    RelationshipEngine engine;

    // Self-parent (pid == ppid) must not create a self-child or loop.
    auto self = engine.buildGraph({makeEv(EventCategory::ProcessCreation, "a.exe", 5, 5, "a.exe", "x")});
    check(self.size() == 1, "self-parent -> one node");
    bool selfChild = false;
    for (const auto& n : self) for (auto c : n.children) if (c == n.id) selfChild = true;
    check(!selfChild, "self-parent -> no self-child edge");

    // Two-node cycle A<->B must terminate and not crash.
    std::vector<SecurityEvent> cycle = {
        makeEv(EventCategory::ProcessCreation, "a.exe", 1, 2, "b.exe", "x"),
        makeEv(EventCategory::ProcessCreation, "b.exe", 2, 1, "a.exe", "y"),
    };
    bool crashed = false;
    try { auto g = engine.buildGraph(cycle); check(g.size() == 2, "cycle -> two nodes"); }
    catch (...) { crashed = true; }
    check(!crashed, "A<->B cycle handled without crash/hang");

    // Scale: 60k events, must be well under quadratic time.
    std::vector<SecurityEvent> many;
    many.reserve(60000);
    for (int i = 0; i < 60000; ++i) {
        many.push_back(makeEv(EventCategory::ProcessCreation, "p.exe", i + 1, i, "q.exe", "x"));
    }
    const auto start = std::chrono::steady_clock::now();
    const auto graph = engine.buildGraph(many);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << "  (60k-node graph built in " << ms << " ms)\n";
    check(graph.size() == 60000, "60k nodes built");
    check(ms < 3000, "60k-node graph builds under 3s (not O(n^2))");
}

void testAnalyzerFuzz() {
    std::cout << "[analyzer fuzz]\n";
    std::mt19937 rng(0xC0FFEE);
    const std::vector<std::string> names = {
        "powershell.exe", "cmd.exe", "malware.exe", "chrome.exe", "svchost.exe",
        "lsass.exe", "notepad.exe", "invoice.pdf.exe", "rundll32.exe", "a b c.exe", ""};
    const std::vector<std::string> parents = {
        "WINWORD.EXE", "explorer.exe", "chrome.exe", "services.exe", "cmd.exe", ""};
    const std::vector<std::string> targets = {
        "C:\\Windows\\System32\\x.exe", "C:\\Users\\u\\AppData\\Local\\Temp\\x.exe",
        "C:\\Users\\u\\Downloads\\x.exe", "203.0.113.5:443",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X", "[2001:db8::1]:443", ""};
    const std::vector<EventCategory> cats = {
        EventCategory::ProcessCreation, EventCategory::FileCreate, EventCategory::RegistryModify,
        EventCategory::NetworkConnection, EventCategory::LogonFailure, EventCategory::Unknown};
    const std::vector<SignatureStatus> sigs = {
        SignatureStatus::Unknown, SignatureStatus::Unsigned,
        SignatureStatus::SignedTrusted, SignatureStatus::SignedUntrusted};

    ThreatScoringEngine engine;
    bool ok = true;
    long long totalMs = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        const int n = static_cast<int>(rng() % 40);
        std::vector<SecurityEvent> events;
        for (int i = 0; i < n; ++i) {
            const std::string& tgt = targets[rng() % targets.size()];
            events.push_back(makeEv(cats[rng() % cats.size()], names[rng() % names.size()],
                                    static_cast<int>(rng() % 9000), static_cast<int>(rng() % 9000),
                                    parents[rng() % parents.size()], tgt,
                                    sigs[rng() % sigs.size()], tgt));
        }
        const auto start = std::chrono::steady_clock::now();
        const AnalysisResult r = engine.analyze(events);
        totalMs += std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();

        if (r.score < 0 || r.score > 100) ok = false;
        if (r.level != "Clean" && r.level != "Low" && r.level != "Medium" &&
            r.level != "High" && r.level != "Critical") ok = false;
        // sorted descending
        for (std::size_t i = 1; i < r.findings.size(); ++i)
            if (static_cast<int>(r.findings[i - 1].severity) < static_cast<int>(r.findings[i].severity)) ok = false;
        // no duplicate keys
        for (std::size_t i = 0; i < r.findings.size(); ++i)
            for (std::size_t j = i + 1; j < r.findings.size(); ++j)
                if (r.findings[i].key() == r.findings[j].key()) ok = false;
        // empty -> Clean
        if (events.empty() && r.level != "Clean") ok = false;

        // report generation must never throw on fuzzed data
        AttackChainBuilder builder;
        try { ReportWriter::toHtml(builder.build(events, iter)); }
        catch (...) { ok = false; }
    }
    check(ok, "3000 fuzz iterations hold all invariants (score range, verdict, sort, dedup)");
    std::cout << "  (fuzz analyze avg " << (totalMs / 3000.0) << " us/iter)\n";
}

void testSignatureChecker() {
    std::cout << "[signature checker]\n";
    // Empty and bogus paths must be safe.
    bool crashed = false;
    try {
        check(SignatureChecker::check("").status == SignatureStatus::Unknown, "empty path -> Unknown");
        SignatureChecker::check("C:\\this\\does\\not\\exist_zzz.exe");
        SignatureChecker::check("C:\\Windows"); // a directory
        SignatureChecker::check(std::string(400, 'A')); // absurd path
    } catch (...) { crashed = true; }
    check(!crashed, "signature checks on bad paths did not throw");

    if (SignatureChecker::available()) {
        // Loop over real system binaries to shake out handle leaks; also confirm
        // a couple of known-signed OS files come back trusted.
        std::vector<std::string> real;
        for (const char* n : {"notepad.exe", "explorer.exe", "cmd.exe", "svchost.exe",
                              "kernel32.dll", "user32.dll"}) {
            std::string p = std::string("C:\\Windows\\System32\\") + n;
            if (std::filesystem::exists(p)) real.push_back(p);
        }
        std::string winExp = "C:\\Windows\\explorer.exe";
        if (std::filesystem::exists(winExp)) real.push_back(winExp);

        int trusted = 0;
        for (int i = 0; i < 2000; ++i) {
            for (const auto& p : real) {
                if (SignatureChecker::check(p).status == SignatureStatus::SignedTrusted && i == 0) ++trusted;
            }
        }
        check(!real.empty() && trusted == static_cast<int>(real.size()),
              "all sampled Windows system binaries verify as trusted");
    }
}

} // namespace

int main() {
    std::cout << "=== Ghostwire stress + fuzz ===\n";
    testDemoInvariants();
    testCleanCase();
    testSignatureAwareness();
    testCsvRobustness();
    testReportEscaping();
    testGraphEdgeCases();
    testAnalyzerFuzz();
    testSignatureChecker();

    std::cout << "\n===============================\n";
    std::cout << "Passed: " << g_pass << "   Failed: " << g_fail << "\n";
    try { std::filesystem::remove_all(tmpDir()); } catch (...) {}
    return g_fail == 0 ? 0 : 1;
}

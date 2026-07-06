#pragma once

#include "anre/SecurityEvent.hpp"
#include <string>
#include <vector>

namespace anre {

struct AnalysisResult {
    int score = 0;                    // 0-100 intensity, for the gauge
    std::string level;                // "Critical" | "High" | "Medium" | "Low" | "Clean"
    std::vector<Finding> findings;    // severity-ranked, most serious first
};

class ThreatScoringEngine {
public:
    // Single entry point: walk the events and produce the score, the overall
    // verdict, and the ranked list of findings. The verdict tracks the single
    // most serious finding (one Critical hit ⇒ Critical verdict), while the
    // score reflects the overall weight of everything seen.
    AnalysisResult analyze(const std::vector<SecurityEvent>& events);

    std::string levelForScore(int score) const;

    // Exposed so the narrative generator stays consistent with how the scorer
    // decides which processes have "no business" doing certain things.
    static bool isSuspiciousProcess(const std::string& name);

    // Exposed so the live scanner only spends time verifying signatures for the
    // binaries the rules actually care about (those in user-writable folders),
    // which keeps a full-system scan fast.
    static bool isFromUserWritableLocation(const std::string& path);

private:
    static bool isLolbin(const std::string& name);
    static bool isDocumentApp(const std::string& name);
    static bool isBrowser(const std::string& name);
    static bool isDocumentOrBrowser(const std::string& name);
    static bool isFromTempLocation(const std::string& path);
    static bool isSuspiciousNetworkTarget(const std::string& target);
    static bool isProtectedSystemProcess(const std::string& name);
    static bool isInSystemDirectory(const std::string& path);
    static bool hasDoubleExtension(const std::string& path);
    static bool isUntrustedSignature(SignatureStatus status);
};

} // namespace anre

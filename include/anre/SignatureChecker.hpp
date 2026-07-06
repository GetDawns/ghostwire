#pragma once

#include "anre/SecurityEvent.hpp"

#include <string>

namespace anre {

struct SignatureInfo {
    SignatureStatus status = SignatureStatus::Unknown;
    std::string publisher;   // signer common name when signed, otherwise empty
};

// Authenticode verification for a Windows executable. Answers two questions a
// heuristic scanner cares about: "is this signed by someone we can trust?" (so
// we can stay quiet about it) and "is this an unsigned binary running from a
// place malware likes?" (so we can flag it).
//
// Results are cached by path — a live scan sees dozens of svchost.exe processes
// that all share one image, and we only want to hit the disk once per file.
class SignatureChecker {
public:
    static SignatureInfo check(const std::string& imagePath);

    // Test / non-Windows builds get a no-op that reports Unknown.
    static bool available();
};

} // namespace anre

#include "anre/ReportWriter.hpp"
#include "anre/NarrativeGenerator.hpp"

#include <fstream>
#include <sstream>

namespace anre {

namespace {

std::string escape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        default:  out += c; break;
        }
    }
    return out;
}

std::string severitySlug(Severity severity) {
    switch (severity) {
    case Severity::Critical: return "critical";
    case Severity::High:     return "high";
    case Severity::Medium:   return "medium";
    case Severity::Low:      return "low";
    default:                 return "info";
    }
}

std::string levelSlug(const std::string& level) {
    std::string s;
    for (char c : level) {
        s += static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    }
    return s;
}

} // namespace

std::string ReportWriter::toHtml(const AttackChain& chain) {
    NarrativeGenerator generator;
    const std::string summary = generator.generateSummary(chain);
    const std::string level = chain.threatLevel.empty() ? "Clean" : chain.threatLevel;
    const std::string slug = levelSlug(level);

    std::ostringstream h;
    h << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
         "<title>Ghostwire Report — " << escape(chain.title) << "</title><style>"
         ":root{--bg:#0c0e12;--card:#151922;--line:#242a36;--text:#d5dae3;--dim:#8b93a3;"
         "--critical:#f2555a;--high:#f0a94c;--medium:#4d9ee0;--low:#8b93a3;--info:#5aac6b;--accent:#38bdf8}"
         "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);"
         "font-family:'Segoe UI',system-ui,sans-serif;line-height:1.55}"
         ".wrap{max-width:900px;margin:0 auto;padding:40px 24px}"
         "header{display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:20px}"
         ".mark{width:12px;height:12px;border-radius:50%;background:var(--accent);box-shadow:0 0 14px var(--accent)}"
         "h1{font-size:20px;margin:0;letter-spacing:.3px}.sub{color:var(--dim);font-size:13px;margin-top:2px}"
         ".verdict{display:flex;align-items:center;gap:24px;margin:28px 0;padding:24px;border-radius:12px;"
         "background:var(--card);border:1px solid var(--line)}"
         ".gauge{--v:0;width:104px;height:104px;border-radius:50%;flex:none;display:grid;place-items:center;"
         "background:conic-gradient(var(--ring) calc(var(--v)*3.6deg),#222834 0)}"
         ".gauge .inner{width:82px;height:82px;border-radius:50%;background:var(--card);display:grid;place-items:center}"
         ".gauge b{font-size:26px}.gauge span{font-size:10px;color:var(--dim)}"
         ".v-critical{--ring:var(--critical)}.v-high{--ring:var(--high)}.v-medium{--ring:var(--medium)}"
         ".v-low{--ring:var(--low)}.v-clean{--ring:var(--info)}"
         ".vlabel{font-size:24px;font-weight:600}.vsub{color:var(--dim);margin-top:4px}"
         ".stats{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}"
         ".stat{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}"
         ".stat b{font-size:22px;display:block}.stat span{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.6px}"
         "h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);margin:32px 0 12px}"
         ".finding{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--low);"
         "border-radius:8px;padding:14px 16px;margin-bottom:10px}"
         ".finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}"
         ".finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}"
         ".ftop{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}"
         ".pill{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;padding:3px 8px;border-radius:20px}"
         ".pill.critical{background:rgba(242,85,90,.15);color:var(--critical)}"
         ".pill.high{background:rgba(240,169,76,.15);color:var(--high)}"
         ".pill.medium{background:rgba(77,158,224,.15);color:var(--medium)}"
         ".pill.low{background:rgba(139,147,163,.15);color:var(--low)}"
         ".ftitle{font-weight:600}.fdetail{color:var(--dim);font-size:13px}"
         ".mitre{font-family:Consolas,monospace;font-size:11px;color:var(--accent);"
         "background:rgba(56,189,248,.1);padding:2px 7px;border-radius:5px}"
         ".phase{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);"
         "border-radius:8px;padding:12px 16px;margin-bottom:8px}"
         ".phase h3{margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--accent)}"
         ".phase p{margin:2px 0;font-size:13px}"
         "table{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}"
         "th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}"
         "th{color:var(--dim);text-transform:uppercase;font-size:10px;letter-spacing:.6px}"
         "td.mono{font-family:Consolas,monospace}"
         ".clean{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;color:var(--info)}"
         "footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);color:var(--dim);font-size:12px}"
         "</style></head><body><div class=\"wrap\">";

    h << "<header><div class=\"mark\"></div><div><h1>Ghostwire Security Report</h1>"
         "<div class=\"sub\">" << escape(chain.title);
    if (!chain.source.empty()) {
        h << " &middot; source: " << escape(chain.source);
    }
    h << "</div></div></header>";

    // Verdict + gauge
    h << "<div class=\"verdict v-" << slug << "\">"
         "<div class=\"gauge\" style=\"--v:" << chain.riskScore << "\"><div class=\"inner\">"
         "<div style=\"text-align:center\"><b>" << chain.riskScore << "</b><br><span>/ 100</span></div>"
         "</div></div><div><div class=\"vlabel\">" << escape(level) << "</div>"
         "<div class=\"vsub\">";
    if (chain.findings.empty()) {
        h << "Nothing in this snapshot matched a known attack pattern.";
    } else {
        h << chain.findings.size() << " thing" << (chain.findings.size() == 1 ? "" : "s")
          << " worth a look across " << chain.narrative.size() << " attack phase"
          << (chain.narrative.size() == 1 ? "" : "s") << ".";
    }
    h << "</div></div></div>";

    // Stats
    h << "<div class=\"stats\">"
         "<div class=\"stat\"><b>" << chain.processCount << "</b><span>Processes</span></div>"
         "<div class=\"stat\"><b>" << chain.networkCount << "</b><span>Internet connections</span></div>"
         "<div class=\"stat\"><b>" << chain.findings.size() << "</b><span>Findings</span></div>"
         "<div class=\"stat\"><b>" << chain.events.size() << "</b><span>Events</span></div>"
         "</div>";

    // Findings
    h << "<h2>What stood out</h2>";
    if (chain.findings.empty()) {
        h << "<div class=\"clean\">Nothing — no suspicious process chains or connections were found. "
             "(This is a quick heuristic check, not a full antivirus scan.)</div>";
    } else {
        for (const Finding& f : chain.findings) {
            const std::string s = severitySlug(f.severity);
            h << "<div class=\"finding " << s << "\"><div class=\"ftop\">"
                 "<span class=\"pill " << s << "\">" << severityName(f.severity) << "</span>"
                 "<span class=\"ftitle\">" << escape(f.title) << "</span>";
            if (!f.mitreId.empty()) {
                h << "<span class=\"mitre\">" << escape(f.mitreId) << "</span>";
            }
            h << "</div><div class=\"fdetail\">" << escape(f.detail);
            if (!f.mitreName.empty()) {
                h << " <em>(" << escape(f.mitreName) << ")</em>";
            }
            h << "</div></div>";
        }
    }

    // Narrative
    if (!chain.narrative.empty()) {
        h << "<h2>Attack story</h2>";
        for (const NarrativeSection& section : chain.narrative) {
            h << "<div class=\"phase\"><h3>" << escape(section.phaseLabel) << "</h3>";
            for (const std::string& line : section.lines) {
                h << "<p>" << escape(line) << "</p>";
            }
            h << "</div>";
        }
    }

    // Summary paragraph
    h << "<h2>Summary</h2><p style=\"color:var(--dim)\">" << escape(summary) << "</p>";

    // Timeline table
    if (!chain.timeline.empty()) {
        h << "<h2>Timeline</h2><table><tr><th>#</th><th>Event</th></tr>";
        int n = 1;
        for (const std::string& entry : chain.timeline) {
            h << "<tr><td class=\"mono\">" << n++ << "</td><td>" << escape(entry) << "</td></tr>";
        }
        h << "</table>";
    }

    h << "<footer>Generated by Ghostwire ANRE 2.0 — a lightweight heuristic triage tool, not "
         "antivirus. A clean result is not a guarantee a machine is uncompromised.</footer>"
         "</div></body></html>";
    return h.str();
}

bool ReportWriter::writeHtml(const AttackChain& chain, const std::string& path) {
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open()) {
        return false;
    }
    out << toHtml(chain);
    return out.good();
}

} // namespace anre

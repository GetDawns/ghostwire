#include "IncidentPanel.hpp"
#include "GuiUtil.hpp"
#include "RiskGauge.hpp"

#include "anre/NarrativeGenerator.hpp"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QVBoxLayout>

namespace {

QString severitySlug(anre::Severity severity) {
    switch (severity) {
    case anre::Severity::Critical: return "critical";
    case anre::Severity::High:     return "high";
    case anre::Severity::Medium:   return "medium";
    case anre::Severity::Low:      return "low";
    default:                       return "info";
    }
}

} // namespace

IncidentPanel::IncidentPanel(QWidget* parent) : QWidget(parent) {
    setObjectName("panel");

    auto* outerWrap = new QVBoxLayout(this);
    outerWrap->setContentsMargins(0, 0, 0, 0);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outerWrap->addWidget(scroll);

    auto* host = new QWidget;
    host->setObjectName("panel");
    scroll->setWidget(host);

    auto* outer = new QVBoxLayout(host);
    outer->setContentsMargins(22, 22, 22, 22);
    outer->setSpacing(18);

    // ---- hero band ----
    auto* hero = new QFrame;
    hero->setObjectName("heroCard");
    auto* heroLayout = new QHBoxLayout(hero);
    heroLayout->setContentsMargins(22, 20, 22, 20);
    heroLayout->setSpacing(24);

    gauge_ = new RiskGauge;
    gauge_->setFixedSize(148, 148);
    heroLayout->addWidget(gauge_, 0, Qt::AlignTop);

    auto* heroRight = new QVBoxLayout;
    heroRight->setSpacing(6);

    verdictLabel_ = new QLabel("Ready to scan");
    verdictLabel_->setObjectName("verdictLabel");
    verdictSub_ = new QLabel;
    verdictSub_->setObjectName("verdictSub");
    verdictSub_->setWordWrap(true);

    statsRow_ = new QWidget;
    statsRowLayout_ = new QHBoxLayout(statsRow_);
    statsRowLayout_->setContentsMargins(0, 8, 0, 0);
    statsRowLayout_->setSpacing(10);

    heroRight->addWidget(verdictLabel_);
    heroRight->addWidget(verdictSub_);
    heroRight->addWidget(statsRow_);
    heroRight->addStretch();

    heroLayout->addLayout(heroRight, 1);
    outer->addWidget(hero);

    // ---- findings ----
    findingsHeader_ = new QLabel("WHAT STOOD OUT");
    findingsHeader_->setObjectName("sectionHeader");
    outer->addWidget(findingsHeader_);

    auto* findingsHost = new QWidget;
    findingsLayout_ = new QVBoxLayout(findingsHost);
    findingsLayout_->setContentsMargins(0, 0, 0, 0);
    findingsLayout_->setSpacing(10);
    outer->addWidget(findingsHost);

    // ---- summary ----
    auto* summaryHeader = new QLabel("SUMMARY");
    summaryHeader->setObjectName("sectionHeader");
    outer->addWidget(summaryHeader);

    summaryLabel_ = new QLabel;
    summaryLabel_->setObjectName("summaryBox");
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summaryLabel_->setContentsMargins(14, 12, 14, 12);
    outer->addWidget(summaryLabel_);

    outer->addStretch(1);
}

QWidget* IncidentPanel::makeStat(const QString& value, const QString& label) {
    auto* chip = new QFrame;
    chip->setObjectName("statChip");
    auto* layout = new QVBoxLayout(chip);
    layout->setContentsMargins(14, 8, 14, 8);
    layout->setSpacing(0);

    auto* valueLabel = new QLabel(value);
    valueLabel->setObjectName("statValue");
    auto* textLabel = new QLabel(label);
    textLabel->setObjectName("statLabel");

    layout->addWidget(valueLabel);
    layout->addWidget(textLabel);
    return chip;
}

QWidget* IncidentPanel::makeFindingCard(const anre::Finding& finding) {
    const QString slug = severitySlug(finding.severity);

    auto* card = new QFrame;
    card->setObjectName("finding_" + slug);
    card->setProperty("class", "findingCard");

    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(16, 12, 16, 13);
    layout->setSpacing(6);

    auto* top = new QHBoxLayout;
    top->setSpacing(9);

    auto* pill = new QLabel(QString::fromLatin1(anre::severityName(finding.severity)).toUpper());
    pill->setObjectName("pill_" + slug);

    auto* title = new QLabel(qstr(finding.title));
    title->setObjectName("findingTitle");
    title->setWordWrap(true);

    top->addWidget(pill, 0, Qt::AlignTop);
    top->addWidget(title, 1);

    if (!finding.mitreId.empty()) {
        auto* mitre = new QLabel(qstr(finding.mitreId));
        mitre->setObjectName("mitreChip");
        mitre->setToolTip(qstr(finding.mitreName));
        top->addWidget(mitre, 0, Qt::AlignTop);
    }

    layout->addLayout(top);

    auto* detail = new QLabel(qstr(finding.detail));
    detail->setObjectName("findingDetail");
    detail->setWordWrap(true);
    detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(detail);

    return card;
}

void IncidentPanel::setChain(const anre::AttackChain& chain) {
    const QString level = qstr(chain.threatLevel);
    gauge_->setValue(chain.riskScore, level);

    // Verdict headline.
    QString headline;
    if (chain.findings.empty()) {
        headline = "Looks clean";
    } else if (level.compare("Critical", Qt::CaseInsensitive) == 0) {
        headline = "Critical — signs of compromise";
    } else if (level.compare("High", Qt::CaseInsensitive) == 0) {
        headline = "High — worth investigating now";
    } else if (level.compare("Medium", Qt::CaseInsensitive) == 0) {
        headline = "Medium — a few things to check";
    } else {
        headline = "Low — minor notes";
    }
    verdictLabel_->setText(headline);

    if (chain.findings.empty()) {
        verdictSub_->setText("Nothing in this snapshot matched a known attack pattern.");
    } else {
        verdictSub_->setText(QString("%1 finding%2 across %3 process%4 and %5 internet connection%6.")
            .arg(chain.findings.size())
            .arg(chain.findings.size() == 1 ? "" : "s")
            .arg(chain.processCount)
            .arg(chain.processCount == 1 ? "" : "es")
            .arg(chain.networkCount)
            .arg(chain.networkCount == 1 ? "" : "s"));
    }

    // Stats chips.
    while (QLayoutItem* item = statsRowLayout_->takeAt(0)) {
        if (QWidget* w = item->widget()) w->deleteLater();
        delete item;
    }
    statsRowLayout_->addWidget(makeStat(QString::number(chain.processCount), "PROCESSES"));
    statsRowLayout_->addWidget(makeStat(QString::number(chain.networkCount), "CONNECTIONS"));
    statsRowLayout_->addWidget(makeStat(QString::number(chain.findings.size()), "FINDINGS"));
    statsRowLayout_->addWidget(makeStat(QString::number(chain.events.size()), "EVENTS"));
    statsRowLayout_->addStretch();

    // Findings.
    while (QLayoutItem* item = findingsLayout_->takeAt(0)) {
        if (QWidget* w = item->widget()) w->deleteLater();
        delete item;
    }
    if (chain.findings.empty()) {
        auto* clean = new QLabel(
            "Nothing — no suspicious process chains or connections were found. "
            "(This is a quick heuristic check, not a full antivirus scan.)");
        clean->setObjectName("cleanNote");
        clean->setWordWrap(true);
        findingsLayout_->addWidget(clean);
    } else {
        for (const anre::Finding& finding : chain.findings) {
            findingsLayout_->addWidget(makeFindingCard(finding));
        }
    }

    anre::NarrativeGenerator generator;
    summaryLabel_->setText(qstr(generator.generateSummary(chain)));
}

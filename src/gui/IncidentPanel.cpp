#include "IncidentPanel.hpp"
#include "GuiUtil.hpp"

#include "anre/NarrativeGenerator.hpp"

#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QVBoxLayout>

IncidentPanel::IncidentPanel(QWidget* parent)
    : QWidget(parent) {
    setObjectName("panel");

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(20, 20, 20, 20);
    outer->setSpacing(16);

    auto* metrics = new QGridLayout;
    metrics->setHorizontalSpacing(12);
    metrics->setVerticalSpacing(12);

    contentLayout_ = new QVBoxLayout;
    contentLayout_->setSpacing(12);

    outer->addLayout(metrics);
    outer->addLayout(contentLayout_, 1);

    summaryLabel_ = new QLabel;
    summaryLabel_->setObjectName("summaryBox");
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summaryLabel_->setContentsMargins(12, 12, 12, 12);

    riskBar_ = new QProgressBar;
    riskBar_->setRange(0, 100);
    riskBar_->setTextVisible(false);
    riskBar_->setFixedHeight(8);

    riskValueLabel_ = new QLabel("—");
    riskValueLabel_->setObjectName("metricValue");

    badgeLabel_ = new QLabel("—");
    badgeLabel_->setObjectName("badgeLow");

    auto* riskCard = new QFrame;
    riskCard->setObjectName("metricCard");
    auto* riskLayout = new QVBoxLayout(riskCard);
    riskLayout->setContentsMargins(14, 12, 14, 12);
    auto* riskLabel = new QLabel("RISK SCORE");
    riskLabel->setObjectName("metricLabel");
    riskLayout->addWidget(riskLabel);
    riskLayout->addWidget(riskValueLabel_);
    riskLayout->addWidget(riskBar_);
    riskLayout->addWidget(badgeLabel_, 0, Qt::AlignLeft);

    metrics->addWidget(riskCard, 0, 0, 1, 2);
}

QWidget* IncidentPanel::makeMetricCard(const QString& label, const QString& value, bool monospace) {
    auto* card = new QFrame;
    card->setObjectName("metricCard");

    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(14, 12, 14, 12);

    auto* labelWidget = new QLabel(label);
    labelWidget->setObjectName("metricLabel");
    layout->addWidget(labelWidget);

    auto* valueWidget = new QLabel(value);
    valueWidget->setObjectName(monospace ? "metricValueMono" : "metricValue");
    layout->addWidget(valueWidget);

    contentLayout_->addWidget(card);
    return card;
}

QLabel* IncidentPanel::makeBadge(const QString& level) {
    const QString normalized = level.toLower();
    if (normalized == "critical") {
        badgeLabel_->setObjectName("badgeCritical");
    } else if (normalized == "high") {
        badgeLabel_->setObjectName("badgeHigh");
    } else if (normalized == "medium") {
        badgeLabel_->setObjectName("badgeMedium");
    } else {
        badgeLabel_->setObjectName("badgeLow");
    }
    badgeLabel_->setStyle(badgeLabel_->style());
    badgeLabel_->setText(level.toUpper());
    return badgeLabel_;
}

void IncidentPanel::setChain(const anre::AttackChain& chain) {
    while (QLayoutItem* item = contentLayout_->takeAt(0)) {
        if (QWidget* widget = item->widget()) {
            widget->deleteLater();
        }
        delete item;
    }

    riskValueLabel_->setText(QString::number(chain.riskScore));
    riskBar_->setValue(chain.riskScore);

    const QString level = qstr(chain.threatLevel);
    if (level.compare("Critical", Qt::CaseInsensitive) == 0) {
        riskBar_->setObjectName("riskBarCritical");
    } else if (level.compare("High", Qt::CaseInsensitive) == 0) {
        riskBar_->setObjectName("riskBarHigh");
    } else if (level.compare("Medium", Qt::CaseInsensitive) == 0) {
        riskBar_->setObjectName("riskBarMedium");
    } else {
        riskBar_->setObjectName("riskBarLow");
    }
    riskBar_->setStyle(riskBar_->style());
    makeBadge(level);

    makeMetricCard("EVENTS", QString::number(chain.events.size()), true);
    makeMetricCard("GRAPH NODES", QString::number(chain.graph.size()), true);
    makeMetricCard("PHASES", QString::number(chain.narrative.size()), true);

    if (auto* metricsRow = new QHBoxLayout) {
        metricsRow->setSpacing(12);
        while (contentLayout_->count() > 0) {
            QLayoutItem* item = contentLayout_->takeAt(0);
            if (QWidget* widget = item->widget()) {
                metricsRow->addWidget(widget, 1);
            }
            delete item;
        }
        contentLayout_->addLayout(metricsRow);
    }

    anre::NarrativeGenerator generator;
    summaryLabel_->setText(qstr(generator.generateSummary(chain)));
    contentLayout_->addWidget(summaryLabel_, 1);
}

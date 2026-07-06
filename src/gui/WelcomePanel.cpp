#include "WelcomePanel.hpp"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

QFrame* featureChip(const QString& title, const QString& subtitle) {
    auto* chip = new QFrame;
    chip->setObjectName("featureChip");
    auto* layout = new QVBoxLayout(chip);
    layout->setContentsMargins(16, 14, 16, 14);
    layout->setSpacing(3);

    auto* titleLabel = new QLabel(title);
    titleLabel->setObjectName("featureTitle");
    auto* subLabel = new QLabel(subtitle);
    subLabel->setObjectName("featureSub");
    subLabel->setWordWrap(true);

    layout->addWidget(titleLabel);
    layout->addWidget(subLabel);
    return chip;
}

} // namespace

WelcomePanel::WelcomePanel(QWidget* parent) : QWidget(parent) {
    setObjectName("welcome");

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(40, 40, 40, 40);
    outer->addStretch(1);

    auto* mark = new QLabel("●");
    mark->setObjectName("welcomeMark");
    mark->setAlignment(Qt::AlignCenter);

    auto* title = new QLabel("Ghostwire");
    title->setObjectName("welcomeTitle");
    title->setAlignment(Qt::AlignCenter);

    auto* tagline = new QLabel("Is anything sketchy happening on this computer?");
    tagline->setObjectName("welcomeTagline");
    tagline->setAlignment(Qt::AlignCenter);

    auto* blurb = new QLabel(
        "Ghostwire takes one look at every program running right now — who started it, "
        "where it lives, whether it's digitally signed, and what it's talking to on the "
        "internet — then tells you in plain English whether anything looks wrong. "
        "No agent to install, no admin rights.");
    blurb->setObjectName("welcomeBlurb");
    blurb->setAlignment(Qt::AlignCenter);
    blurb->setWordWrap(true);
    blurb->setMaximumWidth(560);

    auto* blurbRow = new QHBoxLayout;
    blurbRow->addStretch();
    blurbRow->addWidget(blurb);
    blurbRow->addStretch();

    auto* scanBtn = new QPushButton("Scan This Computer");
    scanBtn->setObjectName("heroBtn");
    scanBtn->setCursor(Qt::PointingHandCursor);
    scanBtn->setMinimumWidth(240);

    auto* scanRow = new QHBoxLayout;
    scanRow->addStretch();
    scanRow->addWidget(scanBtn);
    scanRow->addStretch();

    auto* demoBtn = new QPushButton("Load example attack");
    demoBtn->setObjectName("ghostBtn");
    demoBtn->setCursor(Qt::PointingHandCursor);
    auto* importBtn = new QPushButton("Import CSV…");
    importBtn->setObjectName("ghostBtn");
    importBtn->setCursor(Qt::PointingHandCursor);

    auto* secondaryRow = new QHBoxLayout;
    secondaryRow->setSpacing(10);
    secondaryRow->addStretch();
    secondaryRow->addWidget(demoBtn);
    secondaryRow->addWidget(importBtn);
    secondaryRow->addStretch();

    auto* features = new QHBoxLayout;
    features->setSpacing(12);
    features->addStretch();
    features->addWidget(featureChip("Signature-aware", "Trusts code signed by a known publisher, flags what isn't."));
    features->addWidget(featureChip("MITRE ATT&CK", "Every finding is mapped to a real attacker technique."));
    features->addWidget(featureChip("Plain English", "Written for a person, not a SOC analyst."));
    features->addStretch();

    outer->addWidget(mark);
    outer->addSpacing(6);
    outer->addWidget(title);
    outer->addWidget(tagline);
    outer->addSpacing(10);
    outer->addLayout(blurbRow);
    outer->addSpacing(26);
    outer->addLayout(scanRow);
    outer->addSpacing(10);
    outer->addLayout(secondaryRow);
    outer->addSpacing(34);
    outer->addLayout(features);
    outer->addStretch(1);

    connect(scanBtn, &QPushButton::clicked, this, &WelcomePanel::scanRequested);
    connect(demoBtn, &QPushButton::clicked, this, &WelcomePanel::demoRequested);
    connect(importBtn, &QPushButton::clicked, this, &WelcomePanel::importRequested);
}

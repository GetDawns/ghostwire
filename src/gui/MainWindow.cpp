#include "MainWindow.hpp"
#include "EventsTablePanel.hpp"
#include "GuiUtil.hpp"
#include "IncidentPanel.hpp"
#include "ProcessGraphPanel.hpp"
#include "TimelinePanel.hpp"

#include "anre/AttackChainBuilder.hpp"
#include "anre/EventCollector.hpp"
#include "anre/EventDatabase.hpp"

#include <QApplication>
#include <QButtonGroup>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QTabWidget>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent) {
    setWindowTitle("Ghostwire");
    resize(1280, 820);
    setMinimumSize(960, 640);

    applyStyle();
    buildLayout();
    setStatus("Ready — select a data source to begin analysis");
}

void MainWindow::applyStyle() {
    QFile styleFile(":/styles/app.qss");
    if (styleFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qApp->setStyleSheet(QString::fromUtf8(styleFile.readAll()));
    }
}

void MainWindow::buildLayout() {
    auto* central = new QWidget;
    setCentralWidget(central);

    auto* root = new QHBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ---- sidebar ----
    auto* sidebar = new QWidget;
    sidebar->setObjectName("sidebar");
    sidebar->setFixedWidth(228);

    auto* sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(16, 20, 16, 16);
    sidebarLayout->setSpacing(6);

    auto* brand = new QLabel("Ghostwire");
    brand->setObjectName("brandLabel");
    auto* brandSub = new QLabel("Attack Narrative Engine");
    brandSub->setObjectName("brandSub");
    sidebarLayout->addWidget(brand);
    sidebarLayout->addWidget(brandSub);
    sidebarLayout->addSpacing(20);

    auto* sourceHeader = new QLabel("DATA SOURCES");
    sourceHeader->setObjectName("sectionHeader");
    sidebarLayout->addWidget(sourceHeader);
    sidebarLayout->addSpacing(4);

    auto* sysmonBtn = new QPushButton("Collect from Sysmon");
    sysmonBtn->setObjectName("primaryBtn");
    sysmonBtn->setCursor(Qt::PointingHandCursor);

    auto* csvBtn = new QPushButton("Import CSV file");
    csvBtn->setObjectName("sourceBtn");
    csvBtn->setCursor(Qt::PointingHandCursor);

    sidebarLayout->addWidget(sysmonBtn);
    sidebarLayout->addWidget(csvBtn);
    sidebarLayout->addSpacing(20);

    auto* incidentHeader = new QLabel("INCIDENTS");
    incidentHeader->setObjectName("sectionHeader");
    sidebarLayout->addWidget(incidentHeader);
    sidebarLayout->addSpacing(4);

    auto* incidentListHost = new QWidget;
    auto* incidentListLayout = new QVBoxLayout(incidentListHost);
    incidentListLayout->setContentsMargins(0, 0, 0, 0);
    incidentListLayout->setSpacing(0);
    incidentListLayout_ = incidentListLayout;
    sidebarLayout->addWidget(incidentListHost, 1);

    sidebarLayout->addStretch(0);

    // ---- main column ----
    auto* mainColumn = new QWidget;
    auto* mainLayout = new QVBoxLayout(mainColumn);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    auto* headerBar = new QWidget;
    headerBar->setObjectName("headerBar");
    auto* headerLayout = new QHBoxLayout(headerBar);
    headerLayout->setContentsMargins(20, 0, 20, 0);

    incidentTitle_ = new QLabel("No incident loaded");
    incidentTitle_->setObjectName("incidentTitle");

    headerBadge_ = new QLabel;
    headerBadge_->setObjectName("badgeLow");
    headerBadge_->hide();

    refreshBtn_ = new QPushButton("Refresh");
    refreshBtn_->setEnabled(false);
    refreshBtn_->setFixedWidth(90);

    headerLayout->addWidget(incidentTitle_);
    headerLayout->addSpacing(12);
    headerLayout->addWidget(headerBadge_);
    headerLayout->addStretch();
    headerLayout->addWidget(refreshBtn_);

    tabs_ = new QTabWidget;
    overviewPanel_ = new IncidentPanel;
    timelinePanel_ = new TimelinePanel;
    graphPanel_ = new ProcessGraphPanel;
    eventsPanel_ = new EventsTablePanel;

    narrativeHost_ = new QWidget;
    narrativeHost_->setObjectName("panel");
    narrativeLayout_ = new QVBoxLayout(narrativeHost_);
    narrativeLayout_->setContentsMargins(20, 20, 20, 20);
    narrativeLayout_->setSpacing(10);

    tabs_->addTab(overviewPanel_, "Overview");
    tabs_->addTab(narrativeHost_, "Narrative");
    tabs_->addTab(timelinePanel_, "Timeline");
    tabs_->addTab(graphPanel_, "Process Chain");
    tabs_->addTab(eventsPanel_, "Events");

    mainLayout->addWidget(headerBar);
    mainLayout->addWidget(tabs_, 1);

    root->addWidget(sidebar);
    root->addWidget(mainColumn, 1);

    // ---- status bar ----
    auto* status = new QWidget;
    status->setObjectName("statusBar");
    status->setFixedHeight(28);
    auto* statusLayout = new QHBoxLayout(status);
    statusLayout->setContentsMargins(16, 0, 16, 0);

    statusLeft_ = new QLabel("Ready");
    statusRight_ = new QLabel;
    statusLayout->addWidget(statusLeft_);
    statusLayout->addStretch();
    statusLayout->addWidget(statusRight_);

    mainLayout->addWidget(status);

    connect(sysmonBtn, &QPushButton::clicked, this, &MainWindow::onCollectSysmon);
    connect(csvBtn, &QPushButton::clicked, this, &MainWindow::onImportCsv);
    connect(refreshBtn_, &QPushButton::clicked, this, &MainWindow::onRefresh);
}

void MainWindow::setStatus(const QString& message) {
    statusLeft_->setText(message);
}

void MainWindow::loadEvents(const std::vector<anre::SecurityEvent>& events, const QString& sourceLabel) {
    if (events.empty()) {
        QMessageBox::warning(this, "No events", "No events were returned from the selected source.");
        return;
    }

    currentEvents_ = events;
    currentSource_ = sourceLabel;

    anre::AttackChainBuilder builder;
    currentChain_ = builder.build(events, nextChainId_++);

    anre::EventDatabase database("data");
    database.saveEvents(events);
    database.saveChain(currentChain_);

    displayChain(currentChain_);
    addIncidentEntry(currentChain_);
    refreshBtn_->setEnabled(true);

    setStatus(QString("Loaded %1 events from %2").arg(events.size()).arg(sourceLabel));
    statusRight_->setText(QString("Saved to data/  ·  Chain #%1").arg(currentChain_.id));
}

void MainWindow::displayChain(const anre::AttackChain& chain) {
    incidentTitle_->setText(qstr(chain.title));

    const QString level = qstr(chain.threatLevel);
    headerBadge_->setText(level.toUpper());
    headerBadge_->show();

    if (level.compare("Critical", Qt::CaseInsensitive) == 0) {
        headerBadge_->setObjectName("badgeCritical");
    } else if (level.compare("High", Qt::CaseInsensitive) == 0) {
        headerBadge_->setObjectName("badgeHigh");
    } else if (level.compare("Medium", Qt::CaseInsensitive) == 0) {
        headerBadge_->setObjectName("badgeMedium");
    } else {
        headerBadge_->setObjectName("badgeLow");
    }
    headerBadge_->setStyle(headerBadge_->style());

    overviewPanel_->setChain(chain);
    timelinePanel_->setChain(chain);
    graphPanel_->setChain(chain);
    eventsPanel_->setChain(chain);

    while (QLayoutItem* item = narrativeLayout_->takeAt(0)) {
        if (QWidget* widget = item->widget()) {
            widget->deleteLater();
        }
        delete item;
    }

    if (chain.narrative.empty()) {
        auto* empty = new QLabel("No narrative sections were generated for this event set.");
        empty->setObjectName("phaseLine");
        narrativeLayout_->addWidget(empty);
    } else {
        for (const anre::NarrativeSection& section : chain.narrative) {
            auto* card = new QFrame;
            card->setObjectName("phaseCard");

            auto* cardLayout = new QVBoxLayout(card);
            cardLayout->setContentsMargins(14, 12, 14, 12);
            cardLayout->setSpacing(6);

            auto* title = new QLabel(qstr(section.phaseLabel).toUpper());
            title->setObjectName("phaseTitle");
            cardLayout->addWidget(title);

            for (const std::string& line : section.lines) {
                auto* row = new QLabel(QString("  %1").arg(qstr(line)));
                row->setObjectName("phaseLine");
                row->setWordWrap(true);
                row->setTextInteractionFlags(Qt::TextSelectableByMouse);
                cardLayout->addWidget(row);
            }

            narrativeLayout_->addWidget(card);
        }
    }

    narrativeLayout_->addStretch();
}

void MainWindow::addIncidentEntry(const anre::AttackChain& chain) {
    if (incidentListLayout_ == nullptr) {
        return;
    }

    if (activeIncidentBtn_ != nullptr) {
        activeIncidentBtn_->setChecked(false);
    }

    auto* btn = new QPushButton(
        QString("#%1  ·  %2  ·  %3")
            .arg(chain.id)
            .arg(qstr(chain.threatLevel))
            .arg(chain.events.size()));
    btn->setObjectName("incidentBtn");
    btn->setCheckable(true);
    btn->setChecked(true);
    btn->setCursor(Qt::PointingHandCursor);

    incidentListLayout_->addWidget(btn);
    activeIncidentBtn_ = btn;

    connect(btn, &QPushButton::clicked, this, [this, chain]() {
        displayChain(chain);
        incidentTitle_->setText(qstr(chain.title));
    });
}

void MainWindow::onCollectSysmon() {
    setStatus("Collecting Sysmon events…");

    anre::EventCollector collector;
    const auto events = collector.collectFromSysmon(300);

    if (events.empty()) {
        QMessageBox::information(
            this,
            "Sysmon unavailable",
            "Could not read Sysmon events.\n\n"
            "Ensure Sysmon is installed and run Ghostwire as Administrator.");
        setStatus("Sysmon collection failed");
        return;
    }

    loadEvents(events, "Sysmon");
}

void MainWindow::onImportCsv() {
    const QString path = QFileDialog::getOpenFileName(
        this,
        "Import event log",
        QString(),
        "CSV files (*.csv);;All files (*.*)");

    if (path.isEmpty()) {
        return;
    }

    setStatus("Importing CSV…");

    anre::EventCollector collector;
    const auto events = collector.loadFromFile(stdstr(path));

    if (events.empty()) {
        QMessageBox::warning(
            this,
            "Import failed",
            "The selected file could not be parsed or contains no valid events.");
        setStatus("CSV import failed");
        return;
    }

    loadEvents(events, path);
}

void MainWindow::onRefresh() {
    if (currentEvents_.empty()) {
        return;
    }

    if (currentSource_.startsWith("Sysmon", Qt::CaseInsensitive)) {
        onCollectSysmon();
        return;
    }

    anre::EventCollector collector;
    const auto events = collector.loadFromFile(stdstr(currentSource_));
    loadEvents(events, currentSource_);
}

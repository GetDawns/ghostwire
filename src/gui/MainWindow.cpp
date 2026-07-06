#include "MainWindow.hpp"
#include "EventsTablePanel.hpp"
#include "GuiUtil.hpp"
#include "IncidentPanel.hpp"
#include "ProcessGraphPanel.hpp"
#include "TimelinePanel.hpp"
#include "WelcomePanel.hpp"

#include "anre/AttackChainBuilder.hpp"
#include "anre/EventCollector.hpp"
#include "anre/EventDatabase.hpp"
#include "anre/ReportWriter.hpp"

#include <QApplication>
#include <QDesktopServices>
#include <QFile>
#include <QFileDialog>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QStackedWidget>
#include <QTabWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <QtConcurrent>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent) {
    setWindowTitle("Ghostwire");
    resize(1300, 840);
    setMinimumSize(1000, 660);

    scanWatcher_ = new QFutureWatcher<std::vector<anre::SecurityEvent>>(this);
    connect(scanWatcher_, &QFutureWatcher<std::vector<anre::SecurityEvent>>::finished,
            this, &MainWindow::onScanFinished);

    applyStyle();
    buildLayout();
    setStatus("Ready — click \"Scan This Computer\" to check this machine");
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
    sidebar->setFixedWidth(236);

    auto* sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(16, 20, 16, 16);
    sidebarLayout->setSpacing(6);

    auto* brandRow = new QHBoxLayout;
    brandRow->setSpacing(8);
    auto* brandDot = new QLabel("●");
    brandDot->setObjectName("brandDot");
    auto* brand = new QLabel("Ghostwire");
    brand->setObjectName("brandLabel");
    brandRow->addWidget(brandDot);
    brandRow->addWidget(brand);
    brandRow->addStretch();
    sidebarLayout->addLayout(brandRow);

    auto* brandSub = new QLabel("Attack Narrative Engine");
    brandSub->setObjectName("brandSub");
    sidebarLayout->addWidget(brandSub);
    sidebarLayout->addSpacing(22);

    auto* sourceHeader = new QLabel("DATA SOURCES");
    sourceHeader->setObjectName("sectionHeader");
    sidebarLayout->addWidget(sourceHeader);
    sidebarLayout->addSpacing(4);

    scanBtn_ = new QPushButton("Scan This Computer");
    scanBtn_->setObjectName("primaryBtn");
    scanBtn_->setCursor(Qt::PointingHandCursor);

    csvBtn_ = new QPushButton("Import CSV file");
    csvBtn_->setObjectName("sourceBtn");
    csvBtn_->setCursor(Qt::PointingHandCursor);

    demoBtn_ = new QPushButton("Load example attack");
    demoBtn_->setObjectName("sourceBtn");
    demoBtn_->setCursor(Qt::PointingHandCursor);

    sidebarLayout->addWidget(scanBtn_);
    sidebarLayout->addWidget(csvBtn_);
    sidebarLayout->addWidget(demoBtn_);
    sidebarLayout->addSpacing(22);

    auto* incidentHeader = new QLabel("INCIDENTS");
    incidentHeader->setObjectName("sectionHeader");
    sidebarLayout->addWidget(incidentHeader);
    sidebarLayout->addSpacing(4);

    auto* incidentListHost = new QWidget;
    incidentListLayout_ = new QVBoxLayout(incidentListHost);
    incidentListLayout_->setContentsMargins(0, 0, 0, 0);
    incidentListLayout_->setSpacing(0);
    sidebarLayout->addWidget(incidentListHost, 1);
    sidebarLayout->addStretch(0);

    // ---- main column ----
    auto* mainColumn = new QWidget;
    auto* mainLayout = new QVBoxLayout(mainColumn);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    headerBar_ = new QWidget;
    headerBar_->setObjectName("headerBar");
    auto* headerLayout = new QHBoxLayout(headerBar_);
    headerLayout->setContentsMargins(22, 0, 22, 0);

    incidentTitle_ = new QLabel("No incident loaded");
    incidentTitle_->setObjectName("incidentTitle");

    headerBadge_ = new QLabel;
    headerBadge_->setObjectName("badgeLow");
    headerBadge_->hide();

    exportBtn_ = new QPushButton("Export report");
    exportBtn_->setCursor(Qt::PointingHandCursor);
    exportBtn_->setEnabled(false);

    refreshBtn_ = new QPushButton("Refresh");
    refreshBtn_->setCursor(Qt::PointingHandCursor);
    refreshBtn_->setEnabled(false);
    refreshBtn_->setFixedWidth(92);

    headerLayout->addWidget(incidentTitle_);
    headerLayout->addSpacing(12);
    headerLayout->addWidget(headerBadge_);
    headerLayout->addStretch();
    headerLayout->addWidget(exportBtn_);
    headerLayout->addSpacing(8);
    headerLayout->addWidget(refreshBtn_);
    headerBar_->hide();

    // Stack: welcome first, results (tabs) after a scan.
    stack_ = new QStackedWidget;

    welcomePanel_ = new WelcomePanel;

    tabs_ = new QTabWidget;
    overviewPanel_ = new IncidentPanel;
    timelinePanel_ = new TimelinePanel;
    graphPanel_ = new ProcessGraphPanel;
    eventsPanel_ = new EventsTablePanel;

    narrativeHost_ = new QWidget;
    narrativeHost_->setObjectName("panel");
    {
        auto* narrativeScrollHost = new QVBoxLayout(narrativeHost_);
        narrativeScrollHost->setContentsMargins(0, 0, 0, 0);
        auto* inner = new QWidget;
        inner->setObjectName("panel");
        narrativeLayout_ = new QVBoxLayout(inner);
        narrativeLayout_->setContentsMargins(22, 22, 22, 22);
        narrativeLayout_->setSpacing(10);
        narrativeScrollHost->addWidget(inner);
    }

    tabs_->addTab(overviewPanel_, "Overview");
    tabs_->addTab(narrativeHost_, "Narrative");
    tabs_->addTab(timelinePanel_, "Timeline");
    tabs_->addTab(graphPanel_, "Process Chain");
    tabs_->addTab(eventsPanel_, "Events");

    stack_->addWidget(welcomePanel_);
    stack_->addWidget(tabs_);
    stack_->setCurrentWidget(welcomePanel_);

    mainLayout->addWidget(headerBar_);
    mainLayout->addWidget(stack_, 1);

    // ---- status bar ----
    auto* status = new QWidget;
    status->setObjectName("statusBar");
    status->setFixedHeight(30);
    auto* statusLayout = new QHBoxLayout(status);
    statusLayout->setContentsMargins(16, 0, 16, 0);
    statusLayout->setSpacing(12);

    statusLeft_ = new QLabel("Ready");
    busyBar_ = new QProgressBar;
    busyBar_->setRange(0, 0); // indeterminate
    busyBar_->setFixedWidth(120);
    busyBar_->setTextVisible(false);
    busyBar_->hide();
    statusRight_ = new QLabel;

    statusLayout->addWidget(statusLeft_);
    statusLayout->addStretch();
    statusLayout->addWidget(busyBar_);
    statusLayout->addWidget(statusRight_);

    mainLayout->addWidget(status);

    root->addWidget(sidebar);
    root->addWidget(mainColumn, 1);

    connect(scanBtn_, &QPushButton::clicked, this, &MainWindow::onScanSystem);
    connect(csvBtn_, &QPushButton::clicked, this, &MainWindow::onImportCsv);
    connect(demoBtn_, &QPushButton::clicked, this, &MainWindow::onLoadDemo);
    connect(refreshBtn_, &QPushButton::clicked, this, &MainWindow::onRefresh);
    connect(exportBtn_, &QPushButton::clicked, this, &MainWindow::onExportReport);

    connect(welcomePanel_, &WelcomePanel::scanRequested, this, &MainWindow::onScanSystem);
    connect(welcomePanel_, &WelcomePanel::demoRequested, this, &MainWindow::onLoadDemo);
    connect(welcomePanel_, &WelcomePanel::importRequested, this, &MainWindow::onImportCsv);
}

void MainWindow::setStatus(const QString& message) {
    statusLeft_->setText(message);
}

void MainWindow::setScanning(bool scanning, const QString& message) {
    scanning_ = scanning;
    scanBtn_->setEnabled(!scanning);
    csvBtn_->setEnabled(!scanning);
    demoBtn_->setEnabled(!scanning);
    refreshBtn_->setEnabled(!scanning && !currentEvents_.empty());
    welcomePanel_->setEnabled(!scanning);
    busyBar_->setVisible(scanning);
    if (!message.isEmpty()) {
        setStatus(message);
    }
}

void MainWindow::showResults() {
    headerBar_->show();
    stack_->setCurrentWidget(tabs_);
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
    currentChain_.source = stdstr(sourceLabel);

    anre::EventDatabase database("data");
    database.saveEvents(events);
    database.saveChain(currentChain_);

    showResults();
    displayChain(currentChain_);
    addIncidentEntry(currentChain_);
    refreshBtn_->setEnabled(true);
    exportBtn_->setEnabled(true);

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
    } else if (level.compare("Clean", Qt::CaseInsensitive) == 0) {
        headerBadge_->setObjectName("badgeClean");
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
        auto* empty = new QLabel(
            "No step-by-step attack story for this scan — that's normal when findings are "
            "about individual programs rather than a chain of events. See the Overview tab.");
        empty->setObjectName("phaseLine");
        empty->setWordWrap(true);
        narrativeLayout_->addWidget(empty);
    } else {
        for (const anre::NarrativeSection& section : chain.narrative) {
            auto* card = new QFrame;
            card->setObjectName("phaseCard");

            auto* cardLayout = new QVBoxLayout(card);
            cardLayout->setContentsMargins(16, 12, 16, 12);
            cardLayout->setSpacing(6);

            auto* title = new QLabel(qstr(section.phaseLabel).toUpper());
            title->setObjectName("phaseTitle");
            cardLayout->addWidget(title);

            for (const std::string& line : section.lines) {
                auto* row = new QLabel(QString("•  %1").arg(qstr(line)));
                row->setObjectName("phaseLine");
                row->setWordWrap(true);
                row->setTextFormat(Qt::PlainText);
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
        QString("#%1  ·  %2  ·  %3 events")
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
        showResults();
        displayChain(chain);
        incidentTitle_->setText(qstr(chain.title));
        exportBtn_->setEnabled(true);
    });
}

void MainWindow::onScanSystem() {
    if (scanning_) {
        return;
    }
    setScanning(true, "Scanning this computer — reading processes, signatures and connections…");

    // The scan touches a lot of OS state on a worker thread. If anything in it
    // throws (e.g. an API returns an odd buffer size and an allocation fails),
    // swallow it here and return empty — an escaped exception on the pool thread
    // would take the whole app down with no message.
    auto future = QtConcurrent::run([]() -> std::vector<anre::SecurityEvent> {
        try {
            anre::EventCollector collector;
            return collector.scanLiveSystem();
        } catch (...) {
            return {};
        }
    });
    scanWatcher_->setFuture(future);
}

void MainWindow::onScanFinished() {
    setScanning(false, QString());

    std::vector<anre::SecurityEvent> events;
    try {
        events = scanWatcher_->future().result();
    } catch (...) {
        events.clear();
    }

    if (events.empty()) {
        QMessageBox::information(
            this,
            "Scan unavailable",
            "The scan didn't return anything. Either the process list couldn't be read "
            "on this system, or the scan was interrupted.\n\n"
            "Try the example attack to see how Ghostwire works.");
        setStatus("Scan failed");
        return;
    }

    loadEvents(events, "This computer");
}

void MainWindow::onLoadDemo() {
    anre::EventCollector collector;
    loadEvents(collector.loadDemoScenario(), "Example attack");
}

void MainWindow::openExampleAttack() {
    onLoadDemo();
}

void MainWindow::startScan() {
    onScanSystem();
}

void MainWindow::onImportCsv() {
    const QString path = QFileDialog::getOpenFileName(
        this, "Import event log", QString(), "CSV files (*.csv);;All files (*.*)");
    if (path.isEmpty()) {
        return;
    }
    openCsv(path);
}

void MainWindow::openCsv(const QString& path) {
    setStatus("Importing CSV…");
    anre::EventCollector collector;
    const auto events = collector.loadFromFile(stdstr(path));
    if (events.empty()) {
        QMessageBox::warning(
            this, "Import failed",
            "The selected file could not be parsed or contains no valid events.");
        setStatus("CSV import failed");
        return;
    }

    loadEvents(events, path);
}

void MainWindow::onRefresh() {
    if (currentEvents_.empty() || scanning_) {
        return;
    }

    if (currentSource_ == "This computer") {
        onScanSystem();
        return;
    }
    if (currentSource_ == "Example attack") {
        onLoadDemo();
        return;
    }

    anre::EventCollector collector;
    const auto events = collector.loadFromFile(stdstr(currentSource_));
    loadEvents(events, currentSource_);
}

void MainWindow::onExportReport() {
    if (currentEvents_.empty()) {
        return;
    }

    const QString suggested = QString("ghostwire-report-%1.html").arg(currentChain_.id);
    const QString path = QFileDialog::getSaveFileName(
        this, "Export report", suggested, "HTML files (*.html);;All files (*.*)");
    if (path.isEmpty()) {
        return;
    }

    if (anre::ReportWriter::writeHtml(currentChain_, stdstr(path))) {
        setStatus("Report saved");
        statusRight_->setText("Report exported");
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    } else {
        QMessageBox::warning(this, "Export failed", "Could not write the report to that location.");
    }
}

#pragma once

#include "anre/AttackChain.hpp"
#include "anre/SecurityEvent.hpp"

#include <QFutureWatcher>
#include <QMainWindow>
#include <QString>
#include <vector>

class IncidentPanel;
class TimelinePanel;
class ProcessGraphPanel;
class EventsTablePanel;
class WelcomePanel;
class QPushButton;
class QLabel;
class QTabWidget;
class QStackedWidget;
class QProgressBar;
class QVBoxLayout;
class QWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

    // Load the built-in example attack immediately — handy for demos and for
    // seeing what a real detection looks like without waiting for a scan.
    void openExampleAttack();

    // Import a CSV of events by path (used for `ghostwire <file.csv>`).
    void openCsv(const QString& path);

private slots:
    void onScanSystem();
    void onScanFinished();
    void onImportCsv();
    void onLoadDemo();
    void onRefresh();
    void onExportReport();

private:
    void applyStyle();
    void buildLayout();
    void setStatus(const QString& message);
    void setScanning(bool scanning, const QString& message);
    void showResults();
    void displayChain(const anre::AttackChain& chain);
    void loadEvents(const std::vector<anre::SecurityEvent>& events, const QString& sourceLabel);
    void addIncidentEntry(const anre::AttackChain& chain);

    IncidentPanel* overviewPanel_ = nullptr;
    TimelinePanel* timelinePanel_ = nullptr;
    ProcessGraphPanel* graphPanel_ = nullptr;
    EventsTablePanel* eventsPanel_ = nullptr;
    WelcomePanel* welcomePanel_ = nullptr;

    QStackedWidget* stack_ = nullptr;
    QTabWidget* tabs_ = nullptr;
    QWidget* headerBar_ = nullptr;
    QWidget* narrativeHost_ = nullptr;
    QVBoxLayout* narrativeLayout_ = nullptr;

    QLabel* incidentTitle_ = nullptr;
    QLabel* headerBadge_ = nullptr;
    QLabel* statusLeft_ = nullptr;
    QLabel* statusRight_ = nullptr;
    QProgressBar* busyBar_ = nullptr;
    QPushButton* refreshBtn_ = nullptr;
    QPushButton* exportBtn_ = nullptr;
    QPushButton* scanBtn_ = nullptr;
    QPushButton* csvBtn_ = nullptr;
    QPushButton* demoBtn_ = nullptr;

    QPushButton* activeIncidentBtn_ = nullptr;
    QVBoxLayout* incidentListLayout_ = nullptr;
    std::vector<anre::SecurityEvent> currentEvents_;
    anre::AttackChain currentChain_;
    QString currentSource_;
    int nextChainId_ = 1;
    bool scanning_ = false;

    QFutureWatcher<std::vector<anre::SecurityEvent>>* scanWatcher_ = nullptr;
};

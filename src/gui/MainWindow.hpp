#pragma once

#include "anre/AttackChain.hpp"

#include <QMainWindow>
#include <QString>
#include <vector>

class IncidentPanel;
class TimelinePanel;
class ProcessGraphPanel;
class EventsTablePanel;
class QPushButton;
class QLabel;
class QTabWidget;
class QVBoxLayout;
class QWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onCollectSysmon();
    void onImportCsv();
    void onRefresh();

private:
    void applyStyle();
    void buildLayout();
    void setStatus(const QString& message);
    void displayChain(const anre::AttackChain& chain);
    void loadEvents(const std::vector<anre::SecurityEvent>& events, const QString& sourceLabel);
    void addIncidentEntry(const anre::AttackChain& chain);

    IncidentPanel* overviewPanel_ = nullptr;
    TimelinePanel* timelinePanel_ = nullptr;
    ProcessGraphPanel* graphPanel_ = nullptr;
    EventsTablePanel* eventsPanel_ = nullptr;

    QTabWidget* tabs_ = nullptr;
    QWidget* narrativeHost_ = nullptr;
    QVBoxLayout* narrativeLayout_ = nullptr;

    QLabel* incidentTitle_ = nullptr;
    QLabel* headerBadge_ = nullptr;
    QLabel* statusLeft_ = nullptr;
    QLabel* statusRight_ = nullptr;
    QPushButton* refreshBtn_ = nullptr;

    QPushButton* activeIncidentBtn_ = nullptr;
    QVBoxLayout* incidentListLayout_ = nullptr;
    std::vector<anre::SecurityEvent> currentEvents_;
    anre::AttackChain currentChain_;
    QString currentSource_;
    int nextChainId_ = 1;
};

#pragma once

#include "anre/AttackChain.hpp"

#include <QWidget>

class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class RiskGauge;

// The "Overview" tab: a hero band (risk gauge + verdict + key stats) on top of
// the ranked, severity-coloured findings and the plain-language summary.
class IncidentPanel : public QWidget {
    Q_OBJECT

public:
    explicit IncidentPanel(QWidget* parent = nullptr);

    void setChain(const anre::AttackChain& chain);

private:
    QWidget* makeStat(const QString& value, const QString& label);
    QWidget* makeFindingCard(const anre::Finding& finding);

    RiskGauge* gauge_ = nullptr;
    QLabel* verdictLabel_ = nullptr;
    QLabel* verdictSub_ = nullptr;
    QWidget* statsRow_ = nullptr;
    QHBoxLayout* statsRowLayout_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    QLabel* findingsHeader_ = nullptr;
    QVBoxLayout* findingsLayout_ = nullptr;
};

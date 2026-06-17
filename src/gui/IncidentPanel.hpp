#pragma once

#include "anre/AttackChain.hpp"

#include <QWidget>

class QLabel;
class QProgressBar;
class QVBoxLayout;

class IncidentPanel : public QWidget {
    Q_OBJECT

public:
    explicit IncidentPanel(QWidget* parent = nullptr);

    void setChain(const anre::AttackChain& chain);

private:
    QWidget* makeMetricCard(const QString& label, const QString& value, bool monospace = false);
    QLabel* makeBadge(const QString& level);

    QVBoxLayout* contentLayout_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    QProgressBar* riskBar_ = nullptr;
    QLabel* riskValueLabel_ = nullptr;
    QLabel* badgeLabel_ = nullptr;
};

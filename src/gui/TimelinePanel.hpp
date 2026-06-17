#pragma once

#include "anre/AttackChain.hpp"

#include <QWidget>

class QVBoxLayout;

class TimelinePanel : public QWidget {
    Q_OBJECT

public:
    explicit TimelinePanel(QWidget* parent = nullptr);

    void setChain(const anre::AttackChain& chain);

private:
    QVBoxLayout* rowsLayout_ = nullptr;
};

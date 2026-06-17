#pragma once

#include "anre/AttackChain.hpp"

#include <QWidget>

class QTableWidget;

class EventsTablePanel : public QWidget {
    Q_OBJECT

public:
    explicit EventsTablePanel(QWidget* parent = nullptr);

    void setChain(const anre::AttackChain& chain);

private:
    QTableWidget* table_ = nullptr;
};

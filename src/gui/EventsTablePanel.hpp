#pragma once

#include "anre/AttackChain.hpp"

#include <QWidget>

class QTableWidget;
class QLineEdit;

class EventsTablePanel : public QWidget {
    Q_OBJECT

public:
    explicit EventsTablePanel(QWidget* parent = nullptr);

    void setChain(const anre::AttackChain& chain);

private:
    void applyFilter(const QString& text);

    QTableWidget* table_ = nullptr;
    QLineEdit* filter_ = nullptr;
};

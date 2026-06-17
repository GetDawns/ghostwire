#pragma once

#include "anre/AttackChain.hpp"

#include <QWidget>

class QTreeWidget;

class ProcessGraphPanel : public QWidget {
    Q_OBJECT

public:
    explicit ProcessGraphPanel(QWidget* parent = nullptr);

    void setChain(const anre::AttackChain& chain);

private:
    QTreeWidget* tree_ = nullptr;
};

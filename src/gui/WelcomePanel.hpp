#pragma once

#include <QWidget>

// The first thing you see: a hero screen that explains what Ghostwire does and
// puts the primary action — scan this computer — front and centre. Swapped out
// for the results tabs once a scan has run.
class WelcomePanel : public QWidget {
    Q_OBJECT

public:
    explicit WelcomePanel(QWidget* parent = nullptr);

signals:
    void scanRequested();
    void demoRequested();
    void importRequested();
};

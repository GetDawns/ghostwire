#pragma once

#include <QString>
#include <QWidget>

// A circular risk gauge: a coloured arc that fills in proportion to the 0-100
// score, with the number and verdict in the middle. Painted by hand so it reads
// the same on every machine and scales cleanly.
class RiskGauge : public QWidget {
    Q_OBJECT

public:
    explicit RiskGauge(QWidget* parent = nullptr);

    void setValue(int score, const QString& level);
    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    int score_ = 0;
    QString level_ = "Clean";
};

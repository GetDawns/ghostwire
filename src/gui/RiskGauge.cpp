#include "RiskGauge.hpp"

#include <QColor>
#include <QFont>
#include <QPainter>
#include <QPainterPath>
#include <QRectF>

namespace {

QColor colorForLevel(const QString& level) {
    if (level.compare("Critical", Qt::CaseInsensitive) == 0) return QColor("#f2555a");
    if (level.compare("High", Qt::CaseInsensitive) == 0)     return QColor("#f0a94c");
    if (level.compare("Medium", Qt::CaseInsensitive) == 0)   return QColor("#4d9ee0");
    if (level.compare("Low", Qt::CaseInsensitive) == 0)      return QColor("#c2c8d2");
    return QColor("#5aac6b"); // Clean
}

} // namespace

RiskGauge::RiskGauge(QWidget* parent) : QWidget(parent) {}

void RiskGauge::setValue(int score, const QString& level) {
    score_ = score < 0 ? 0 : (score > 100 ? 100 : score);
    level_ = level.isEmpty() ? QStringLiteral("Clean") : level;
    update();
}

QSize RiskGauge::sizeHint() const { return QSize(150, 150); }
QSize RiskGauge::minimumSizeHint() const { return QSize(120, 120); }

void RiskGauge::paintEvent(QPaintEvent*) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const qreal side = qMin(width(), height());
    const qreal thickness = side * 0.10;
    const QRectF ring(
        (width() - side) / 2.0 + thickness / 2.0,
        (height() - side) / 2.0 + thickness / 2.0,
        side - thickness,
        side - thickness);

    const QColor accent = colorForLevel(level_);

    // Track
    QPen trackPen(QColor("#232936"), thickness, Qt::SolidLine, Qt::RoundCap);
    painter.setPen(trackPen);
    painter.drawArc(ring, 0, 360 * 16);

    // Value arc — start at the top (90°) and sweep clockwise.
    if (score_ > 0) {
        QPen valuePen(accent, thickness, Qt::SolidLine, Qt::RoundCap);
        painter.setPen(valuePen);
        const int startAngle = 90 * 16;
        const int spanAngle = -static_cast<int>(3.6 * score_ * 16);
        painter.drawArc(ring, startAngle, spanAngle);
    }

    // Centre: score + level.
    painter.setPen(QColor("#f3f5f8"));
    QFont scoreFont = font();
    scoreFont.setPointSizeF(side * 0.22);
    scoreFont.setWeight(QFont::DemiBold);
    painter.setFont(scoreFont);
    const QRectF numberRect(ring.left(), ring.top() + side * 0.10, ring.width(), ring.height() * 0.55);
    painter.drawText(numberRect, Qt::AlignCenter, QString::number(score_));

    painter.setPen(accent);
    QFont levelFont = font();
    levelFont.setPointSizeF(side * 0.085);
    levelFont.setWeight(QFont::DemiBold);
    levelFont.setCapitalization(QFont::AllUppercase);
    levelFont.setLetterSpacing(QFont::AbsoluteSpacing, 1.0);
    painter.setFont(levelFont);
    const QRectF levelRect(ring.left(), ring.center().y() + side * 0.06, ring.width(), side * 0.20);
    painter.drawText(levelRect, Qt::AlignHCenter | Qt::AlignTop, level_);
}

#include "TimelinePanel.hpp"
#include "GuiUtil.hpp"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QVBoxLayout>

TimelinePanel::TimelinePanel(QWidget* parent)
    : QWidget(parent) {
    setObjectName("panel");

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    auto* host = new QWidget;
    rowsLayout_ = new QVBoxLayout(host);
    rowsLayout_->setContentsMargins(24, 24, 24, 24);
    rowsLayout_->setSpacing(0);
    rowsLayout_->addStretch();

    scroll->setWidget(host);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(scroll);
}

void TimelinePanel::setChain(const anre::AttackChain& chain) {
    while (QLayoutItem* item = rowsLayout_->takeAt(0)) {
        if (QWidget* widget = item->widget()) {
            widget->deleteLater();
        }
        delete item;
    }

    for (const anre::SecurityEvent& event : chain.events) {
        auto* row = new QWidget;
        row->setObjectName("timelineRow");

        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(12);

        auto* time = new QLabel(qstr(event.timestamp));
        time->setObjectName("timelineTime");
        time->setAlignment(Qt::AlignTop | Qt::AlignRight);

        auto* dot = new QLabel;
        dot->setObjectName("timelineDot");
        dot->setFixedSize(8, 8);

        QString detail;
        switch (event.category) {
        case anre::EventCategory::ProcessCreation:
            detail = QString("%1 spawned").arg(qstr(event.processName));
            if (!event.parentProcessName.empty()) {
                detail += QString(" via %1").arg(qstr(event.parentProcessName));
            }
            break;
        case anre::EventCategory::FileCreate:
            detail = QString("%1 wrote %2")
                         .arg(qstr(event.processName), qstr(event.target));
            break;
        case anre::EventCategory::RegistryModify:
            detail = QString("%1 modified %2")
                         .arg(qstr(event.processName), qstr(event.target));
            break;
        case anre::EventCategory::NetworkConnection:
            detail = QString("%1 connected to %2")
                         .arg(qstr(event.processName), qstr(event.target));
            break;
        default:
            detail = qstr(event.action);
            break;
        }

        auto* text = new QLabel(detail);
        text->setObjectName("timelineText");
        text->setWordWrap(true);
        text->setTextFormat(Qt::PlainText);
        text->setTextInteractionFlags(Qt::TextSelectableByMouse);

        layout->addWidget(time);
        layout->addWidget(dot, 0, Qt::AlignTop);
        layout->addWidget(text, 1);

        rowsLayout_->addWidget(row);
    }

    rowsLayout_->addStretch();
}

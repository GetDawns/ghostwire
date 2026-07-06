#include "EventsTablePanel.hpp"
#include "GuiUtil.hpp"

#include <QHeaderView>
#include <QLineEdit>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

QString categoryLabel(anre::EventCategory category) {
    switch (category) {
    case anre::EventCategory::ProcessCreation:
        return "Process";
    case anre::EventCategory::FileCreate:
        return "File";
    case anre::EventCategory::RegistryModify:
        return "Registry";
    case anre::EventCategory::NetworkConnection:
        return "Network";
    case anre::EventCategory::LogonFailure:
        return "Logon";
    default:
        return "Other";
    }
}

} // namespace

EventsTablePanel::EventsTablePanel(QWidget* parent)
    : QWidget(parent) {
    setObjectName("panel");

    filter_ = new QLineEdit;
    filter_->setObjectName("filterBox");
    filter_->setPlaceholderText("Filter events — process, IP, path, category…");
    filter_->setClearButtonEnabled(true);

    table_ = new QTableWidget(this);
    table_->setColumnCount(8);
    table_->setHorizontalHeaderLabels({
        "Time", "Process", "PID", "Parent", "PPID", "Category", "Action", "Target",
    });
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);
    layout->addWidget(filter_);
    layout->addWidget(table_);

    connect(filter_, &QLineEdit::textChanged, this, &EventsTablePanel::applyFilter);
}

void EventsTablePanel::applyFilter(const QString& text) {
    const QString needle = text.trimmed().toLower();
    for (int row = 0; row < table_->rowCount(); ++row) {
        bool match = needle.isEmpty();
        for (int col = 0; col < table_->columnCount() && !match; ++col) {
            if (QTableWidgetItem* item = table_->item(row, col)) {
                if (item->text().toLower().contains(needle)) {
                    match = true;
                }
            }
        }
        table_->setRowHidden(row, !match);
    }
}

void EventsTablePanel::setChain(const anre::AttackChain& chain) {
    table_->setRowCount(static_cast<int>(chain.events.size()));

    int row = 0;
    for (const anre::SecurityEvent& event : chain.events) {
        table_->setItem(row, 0, new QTableWidgetItem(qstr(event.timestamp)));
        table_->setItem(row, 1, new QTableWidgetItem(qstr(event.processName)));
        table_->setItem(row, 2, new QTableWidgetItem(QString::number(event.processId)));
        table_->setItem(row, 3, new QTableWidgetItem(qstr(event.parentProcessName)));
        table_->setItem(row, 4, new QTableWidgetItem(QString::number(event.parentProcessId)));
        table_->setItem(row, 5, new QTableWidgetItem(categoryLabel(event.category)));
        table_->setItem(row, 6, new QTableWidgetItem(qstr(event.action)));
        table_->setItem(row, 7, new QTableWidgetItem(qstr(event.target)));
        ++row;
    }

    table_->resizeColumnsToContents();
    applyFilter(filter_->text());
}

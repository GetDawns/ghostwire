#include "ProcessGraphPanel.hpp"
#include "GuiUtil.hpp"

#include <QHeaderView>
#include <QMap>
#include <QTreeWidget>
#include <QVBoxLayout>

ProcessGraphPanel::ProcessGraphPanel(QWidget* parent)
    : QWidget(parent) {
    setObjectName("panel");

    tree_ = new QTreeWidget(this);
    tree_->setHeaderLabels({"Process", "PID", "Parent PID", "Action"});
    tree_->setAlternatingRowColors(true);
    tree_->setRootIsDecorated(true);
    tree_->setUniformRowHeights(true);
    tree_->header()->setStretchLastSection(true);
    tree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->addWidget(tree_);
}

void ProcessGraphPanel::setChain(const anre::AttackChain& chain) {
    tree_->clear();

    QMap<qint64, QTreeWidgetItem*> items;
    for (const anre::EventNode& node : chain.graph) {
        auto* item = new QTreeWidgetItem({
            qstr(node.event.processName),
            QString::number(node.event.processId),
            QString::number(node.event.parentProcessId),
            qstr(node.event.action),
        });
        items.insert(node.id, item);
    }

    for (const anre::EventNode& node : chain.graph) {
        QTreeWidgetItem* item = items.value(node.id, nullptr);
        if (item == nullptr) {
            continue;
        }

        if (node.parentNodeId >= 0 && items.contains(node.parentNodeId)) {
            items[node.parentNodeId]->addChild(item);
        } else {
            tree_->addTopLevelItem(item);
        }
    }

    tree_->expandAll();
    for (int i = 0; i < tree_->columnCount(); ++i) {
        tree_->resizeColumnToContents(i);
    }
}

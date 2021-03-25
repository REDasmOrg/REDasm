#pragma once

#include <QSortFilterProxyModel>
#include <QWidget>
#include "../../../models/dev/functiongraphmodel.h"
#include "../../../models/functionsmodel.h"
#include "../../../hooks/isurface.h"

namespace Ui {
class FunctionGraphTab;
}

class FunctionGraphTab : public QWidget
{
    Q_OBJECT

    public:
        explicit FunctionGraphTab(QWidget *parent = nullptr);
        ~FunctionGraphTab();
        void setContext(const RDContextPtr& ctx);

    private Q_SLOTS:
        void showGraph(const QModelIndex& current, const QModelIndex&);
        void copyUnitTests() const;
        void copyGraph() const;
        void copyHash() const;

    private:
        const RDGraph* getGraph(const QModelIndex& index) const;
        const RDGraph* getSelectedGraph() const;

    private:
        Ui::FunctionGraphTab *ui;
        FunctionsModel* m_functionsmodel{nullptr};
        QSortFilterProxyModel* m_sortedblocksmodel{nullptr};
        FunctionGraphModel* m_functiongraphmodel{nullptr};
};


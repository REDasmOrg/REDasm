#pragma once

#include <QSortFilterProxyModel>
#include <QDialog>
#include "../../../models/dev/functionlistmodel.h"
#include "../../../models/dev/functiongraphmodel.h"

namespace Ui {
class FunctionGraphDialog;
}

class FunctionGraphDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit FunctionGraphDialog(QWidget *parent = nullptr);
        ~FunctionGraphDialog();
        void setDisassembler(RDDisassembler* disassembler);

    private slots:
        void showGraph(const QModelIndex& current, const QModelIndex&);
        void copyGraph() const;

    private:
        Ui::FunctionGraphDialog *ui;
        FunctionListModel* m_functionlistmodel{nullptr};
        QSortFilterProxyModel* m_sortedblocksmodel{nullptr};
        FunctionGraphModel* m_functiongraphmodel{nullptr};
};


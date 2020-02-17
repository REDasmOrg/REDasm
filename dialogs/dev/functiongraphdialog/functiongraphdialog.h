#pragma once

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

    private slots:
        void showGraph(const QModelIndex& current, const QModelIndex&);

    private:
        Ui::FunctionGraphDialog *ui;
        FunctionListModel* m_functionlistmodel;
        FunctionGraphModel* m_functiongraphmodel;
};


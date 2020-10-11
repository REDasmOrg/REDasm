#pragma once

#include <QDialog>
#include "../hooks/icommand.h"

namespace Ui {
class ProblemsDialog;
}

class QStandardItemModel;

class ProblemsDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ProblemsDialog(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ~ProblemsDialog();

    private:
        Ui::ProblemsDialog *ui;
        RDContextPtr m_context;
        QStandardItemModel* m_problemsmodel;

};

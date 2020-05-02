#pragma once

#include <QDialog>

namespace Ui {
class ProblemsDialog;
}

class QStandardItemModel;

class ProblemsDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ProblemsDialog(QWidget *parent = nullptr);
        ~ProblemsDialog();

    private:
        Ui::ProblemsDialog *ui;
        QStandardItemModel* m_problemsmodel;
};

#ifndef PROBLEMSDIALOG_H
#define PROBLEMSDIALOG_H

#include <QDialog>

namespace Ui {
class ProblemsDialog;
}

class ProblemsDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ProblemsDialog(QWidget *parent = nullptr);
        ~ProblemsDialog();

    private:
        Ui::ProblemsDialog *ui;
};

#endif // PROBLEMSDIALOG_H

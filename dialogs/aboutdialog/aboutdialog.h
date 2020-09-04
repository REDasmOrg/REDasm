#pragma once

#include <QDialog>

namespace Ui {
class AboutDialog;
}

class AboutDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit AboutDialog(QWidget *parent = 0);
        ~AboutDialog();

    private:
        void initDependencies();

    private:
        Ui::AboutDialog *ui;
};

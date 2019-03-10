#ifndef FORMATLOADERDIALOG_H
#define FORMATLOADERDIALOG_H

#include <QDialog>

namespace Ui {
class FormatLoaderDialog;
}

class FormatLoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit FormatLoaderDialog(QWidget *parent = nullptr);
        ~FormatLoaderDialog();

    private:
        Ui::FormatLoaderDialog *ui;
};

#endif // FORMATLOADERDIALOG_H

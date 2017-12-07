#ifndef DATABASEDIALOG_H
#define DATABASEDIALOG_H

#include <QDialog>
#include "../models/databasemodel.h"

namespace Ui {
class DatabaseDialog;
}

class DatabaseDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit DatabaseDialog(QWidget *parent = 0);
        ~DatabaseDialog();

    private:
        void validateDialog();

    private slots:
        void on_tbImport_clicked();
        void on_tbSave_clicked();

    private:
        Ui::DatabaseDialog *ui;
        DatabaseModel* _databasemodel;
};

#endif // DATABASEDIALOG_H

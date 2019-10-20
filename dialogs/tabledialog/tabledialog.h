#pragma once

#include <QDialog>
#include <QAbstractListModel>

namespace Ui {
class TableDialog;
}

class TableDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit TableDialog(QWidget *parent = nullptr);
        ~TableDialog();

    public:
        void enableFiltering();
        void setButtonBoxVisible(bool b);
        void setModel(QAbstractItemModel* model);

    private:
        Ui::TableDialog *ui;
};


#pragma once

#include <QAbstractListModel>
#include <QWidget>

namespace Ui {
class TableWidget;
}

class TableWidget : public QWidget
{
    Q_OBJECT

    public:
        explicit TableWidget(QWidget *parent = nullptr);
        ~TableWidget();

    public:
        void enableFiltering();
        void setModel(QAbstractItemModel* model);

    private:
        Ui::TableWidget *ui;
};


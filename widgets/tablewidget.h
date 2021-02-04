#pragma once

#include <QAbstractListModel>
#include <QAbstractItemView>
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
        void setSelectionModel(QAbstractItemView::SelectionMode mode);
        void setSelectionBehavior(QAbstractItemView::SelectionBehavior behavior);
        void setModel(QAbstractItemModel* model);
        QAbstractItemModel* model() const;

    private Q_SLOTS:
        void onTableDoubleClicked(const QModelIndex& index);
        void onTableClicked(const QModelIndex& index);

    Q_SIGNALS:
        void doubleClicked(const QModelIndex& index);
        void clicked(const QModelIndex& index);

    private:
        Ui::TableWidget *ui;
};


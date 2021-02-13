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
        ~TableWidget() override;

    public:
        void enableFiltering();
        void setToggleFilter(bool b);
        void setShowVerticalHeader(bool v);
        void setAlternatingRowColors(bool b);
        void setColumnHidden(int idx);
        void resizeColumn(int idx);
        void resizeColumnsUntil(int offset);
        void moveSection(int from, int to);
        void setSelectionModel(QAbstractItemView::SelectionMode mode);
        void setSelectionBehavior(QAbstractItemView::SelectionBehavior behavior);
        void setModel(QAbstractItemModel* model);
        QAbstractItemModel* model() const;

    public Q_SLOTS:
        void resizeAllColumns();

    protected:
        bool event(QEvent* e) override;

    private Q_SLOTS:
        void onTableDoubleClicked(const QModelIndex& index);
        void onTableClicked(const QModelIndex& index);

    private:
        void clearFilter();
        void showFilter();

    Q_SIGNALS:
        void doubleClicked(const QModelIndex& index);
        void clicked(const QModelIndex& index);
        void resizeColumns();

    private:
        Ui::TableWidget *ui;
        bool m_togglefilter{false};
        QAction* m_actfilter;
};


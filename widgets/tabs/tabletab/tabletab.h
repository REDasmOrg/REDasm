#pragma once

#include <QWidget>
#include <QHeaderView>

namespace Ui {
class TableTab;
}

class ListingItemModel;
class QSortFilterProxyModel;

class TableTab : public QWidget
{
    Q_OBJECT

    public:
        explicit TableTab(ListingItemModel* model, QWidget *parent = nullptr);
        ~TableTab();
        void setSectionResizeMode(int idx, QHeaderView::ResizeMode mode);
        void setColumnHidden(int idx);
        void resizeColumn(int idx);
        void moveSection(int from, int to);
        ListingItemModel* model() const;

    public slots:
        void resizeAllColumns();

    private slots:
        void onTableDoubleClick(const QModelIndex& index);

    protected:
        bool event(QEvent* e) override;

    private:
        void setFilterVisible(bool b);

    signals:
        void resizeColumns();

    private:
        Ui::TableTab *ui;
        ListingItemModel* m_listingitemmodel;
        QSortFilterProxyModel* m_filtermodel;
};


#ifndef LISTINGFILTERMODEL_H
#define LISTINGFILTERMODEL_H

#include <QSortFilterProxyModel>
#include "listingitemmodel.h"

class ListingFilterModel : public QIdentityProxyModel
{
    Q_OBJECT

    public:
        explicit ListingFilterModel(QObject *parent = nullptr);
        const QString& filter() const;
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
        void setFilter(const QString& filter);
        void clearFilter();

    public:
        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        QModelIndex index(int row, int column, const QModelIndex& = QModelIndex()) const override;
        QModelIndex mapFromSource(const QModelIndex& sourceindex) const override;
        QModelIndex mapToSource(const QModelIndex& proxyindex) const override;

    private:
        void updateFiltering();
        bool canFilter() const;

    public:
        template<typename T> static ListingFilterModel* createFilter(QObject* parent);
        template<typename T> static ListingFilterModel* createFilter(size_t filter, QObject* parent);

    private:
        QVector<REDasm::ListingItem*> m_filtereditems;
        QString m_filterstring;
};

template<typename T> ListingFilterModel *ListingFilterModel::createFilter(QObject *parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filtermodel));
    return filtermodel;
}

template<typename T> ListingFilterModel* ListingFilterModel::createFilter(size_t filter, QObject* parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filter, filtermodel));
    return filtermodel;
}

#endif // LISTINGFILTERMODEL_H

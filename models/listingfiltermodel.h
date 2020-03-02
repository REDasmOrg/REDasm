#pragma once

#include <QIdentityProxyModel>
#include "listingitemmodel.h"

class ListingFilterModel : public QIdentityProxyModel
{
    Q_OBJECT

    public:
        explicit ListingFilterModel(QObject *parent = nullptr);
        const QString& filter() const;
        REDasm::ListingItem item(const QModelIndex& index) const;
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
        template<typename T> static ListingFilterModel* createFilter(type_t filter, QObject* parent);

    private:
        QList<address_t> m_filtereditems;
        QString m_filterstring;
};

template<typename T> ListingFilterModel *ListingFilterModel::createFilter(QObject *parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filtermodel));
    return filtermodel;
}

template<typename T> ListingFilterModel* ListingFilterModel::createFilter(type_t filter, QObject* parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filter, filtermodel));
    return filtermodel;
}

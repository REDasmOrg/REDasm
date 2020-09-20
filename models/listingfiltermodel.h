#pragma once

#include <QSortFilterProxyModel>
#include "listingitemmodel.h"

class ListingFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit ListingFilterModel(QObject *parent = nullptr);
        const QString& filter() const;
        const RDDocumentItem& item(const QModelIndex& index) const;
        void setDisassembler(const RDDisassemblerPtr& disassembler);

    public:
        template<typename T> static ListingFilterModel* createFilter(QObject* parent);
        template<typename T> static ListingFilterModel* createFilter(rd_type filter, QObject* parent);
};

template<typename T>
ListingFilterModel *ListingFilterModel::createFilter(QObject *parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filtermodel));
    return filtermodel;
}

template<typename T>
ListingFilterModel* ListingFilterModel::createFilter(rd_type filter, QObject* parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filter, filtermodel));
    return filtermodel;
}

#ifndef LISTINGFILTERMODEL_H
#define LISTINGFILTERMODEL_H

#include <QSortFilterProxyModel>
#include "listingitemmodel.h"

class ListingFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit ListingFilterModel(QObject *parent = nullptr);
        const QString& filter() const;
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void setFilter(const QString& filter);

    protected:
        virtual bool filterAcceptsRow(int source_row, const QModelIndex&) const;

    public:
        template<typename T> static ListingFilterModel* createFilter(QObject* parent);
        template<typename T> static ListingFilterModel* createFilter(u32 filter, QObject* parent);

    private:
        QString m_filterstring;
};

template<typename T> ListingFilterModel *ListingFilterModel::createFilter(QObject *parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filtermodel));
    return filtermodel;
}

template<typename T> ListingFilterModel* ListingFilterModel::createFilter(u32 filter, QObject* parent)
{
    ListingFilterModel* filtermodel = new ListingFilterModel(parent);
    filtermodel->setSourceModel(new T(filter, filtermodel));
    return filtermodel;
}

#endif // LISTINGFILTERMODEL_H

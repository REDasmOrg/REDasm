#include "listingfiltermodel.h"

ListingFilterModel::ListingFilterModel(QObject *parent) : QIdentityProxyModel(parent) { }
const QString &ListingFilterModel::filter() const { return m_filterstring; }

void ListingFilterModel::setDisassembler(REDasm::DisassemblerAPI *disassembler) { reinterpret_cast<ListingItemModel*>(this->sourceModel())->setDisassembler(disassembler); }

void ListingFilterModel::setFilter(const QString &filter)
{
    m_filterstring = filter;
    this->updateFiltering();
}

int ListingFilterModel::rowCount(const QModelIndex& parent) const
{
    if(!m_items.empty())
        return m_items.count();

    return QIdentityProxyModel::rowCount(parent);
}

QModelIndex ListingFilterModel::index(int row, int column, const QModelIndex&) const
{
    if(m_items.empty())
        return QIdentityProxyModel::index(row, column);

    return this->createIndex(row, column, m_items[row]);
}

QModelIndex ListingFilterModel::mapFromSource(const QModelIndex &sourceindex) const
{
    if(m_items.empty())
        return sourceindex;

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(sourceindex.internalPointer());
    int idx = REDasm::Listing::indexOf(&m_items, item);

    if(idx == -1)
        return QModelIndex();

    return this->index(idx, sourceindex.column());
}

QModelIndex ListingFilterModel::mapToSource(const QModelIndex &proxyindex) const
{
    if(m_items.empty())
        return proxyindex;

    ListingItemModel* listingitemmodel = reinterpret_cast<ListingItemModel*>(this->sourceModel());
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(proxyindex.internalPointer());
    int idx = REDasm::Listing::indexOf(&listingitemmodel->m_items, item);

    if(idx == -1)
        return QModelIndex();

    return listingitemmodel->index(idx, proxyindex.column());
}

void ListingFilterModel::updateFiltering()
{
    this->beginResetModel();
    m_items.clear();

    if(m_filterstring.length() >= 2)
    {
        QAbstractItemModel* sourcemodel = this->sourceModel();

        for(int i = 0; i < sourcemodel->rowCount(); i++)
        {
            for(int j = 0; j < sourcemodel->columnCount(); j++)
            {
                QModelIndex index = sourcemodel->index(i, j);
                QVariant data = sourcemodel->data(index);

                if(data.type() != QVariant::String)
                    continue;

                if(data.toString().indexOf(m_filterstring, 0, Qt::CaseInsensitive) != -1)
                    m_items.append(reinterpret_cast<REDasm::ListingItem*>(index.internalPointer()));
            }
        }
    }

    this->endResetModel();
}

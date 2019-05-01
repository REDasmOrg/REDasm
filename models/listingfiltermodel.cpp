#include "listingfiltermodel.h"

#define FILTER_MIN_CHARS 2

ListingFilterModel::ListingFilterModel(QObject *parent) : QIdentityProxyModel(parent) { }
const QString &ListingFilterModel::filter() const { return m_filterstring; }
void ListingFilterModel::setDisassembler(const REDasm::DisassemblerPtr& disassembler) { reinterpret_cast<ListingItemModel*>(this->sourceModel())->setDisassembler(disassembler); }

void ListingFilterModel::setFilter(const QString &filter)
{
    if(m_filterstring == filter)
        return;

    m_filterstring = filter;
    this->updateFiltering();
}

void ListingFilterModel::clearFilter()
{
    if(m_filterstring.isEmpty())
        return;

    m_filterstring.clear();
    this->updateFiltering();
}

int ListingFilterModel::rowCount(const QModelIndex& parent) const
{
    if(!this->canFilter())
        return QIdentityProxyModel::rowCount(parent);

    return m_filtereditems.count();
}

QModelIndex ListingFilterModel::index(int row, int column, const QModelIndex&) const
{
    if(!this->canFilter())
        return QIdentityProxyModel::index(row, column);

    if(m_filtereditems.empty())
        return QModelIndex();

    return this->createIndex(row, column, m_filtereditems[row]);
}

QModelIndex ListingFilterModel::mapFromSource(const QModelIndex &sourceindex) const
{
    if(!this->canFilter() || !sourceindex.isValid())
        return QIdentityProxyModel::mapFromSource(sourceindex);

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(sourceindex.internalPointer());
    size_t idx = m_filtereditems.indexOf(item);

    if(idx == REDasm::ListingItemContainer::npos)
        return QModelIndex();

    return this->index(idx, sourceindex.column());
}

QModelIndex ListingFilterModel::mapToSource(const QModelIndex &proxyindex) const
{
    if(!this->canFilter() || !proxyindex.isValid())
        return QIdentityProxyModel::mapToSource(proxyindex);

    ListingItemModel* listingitemmodel = reinterpret_cast<ListingItemModel*>(this->sourceModel());
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(proxyindex.internalPointer());
    size_t idx = listingitemmodel->m_items.indexOf(item);

    if(idx == REDasm::ListingItemContainer::npos)
        return QModelIndex();

    return listingitemmodel->index(idx, proxyindex.column());
}

void ListingFilterModel::updateFiltering()
{
    this->beginResetModel();
    m_filtereditems.clear();

    if(this->canFilter())
    {
        QAbstractItemModel* sourcemodel = this->sourceModel();

        for(int i = 0; i < sourcemodel->rowCount(); i++)
        {
            for(int j = 0; j < sourcemodel->columnCount(); j++)
            {
                QModelIndex index = sourcemodel->index(i, j);
                QVariant data = sourcemodel->data(index);

                if((data.type() != QVariant::String) || (data.toString().indexOf(m_filterstring, 0, Qt::CaseInsensitive) == -1))
                    continue;

                m_filtereditems.append(reinterpret_cast<REDasm::ListingItem*>(index.internalPointer()));
                break;
            }
        }
    }

    this->endResetModel();
}

bool ListingFilterModel::canFilter() const { return m_filterstring.length() >= FILTER_MIN_CHARS; }

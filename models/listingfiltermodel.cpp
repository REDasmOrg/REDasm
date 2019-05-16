#include "listingfiltermodel.h"

#define FILTER_MIN_CHARS 2

ListingFilterModel::ListingFilterModel(QObject *parent) : QIdentityProxyModel(parent) { }
const QString &ListingFilterModel::filter() const { return m_filterstring; }
const REDasm::ListingItem *ListingFilterModel::item(const QModelIndex &index) const { return static_cast<ListingItemModel*>(this->sourceModel())->item(this->mapToSource(index));  }
void ListingFilterModel::setDisassembler(const REDasm::DisassemblerPtr& disassembler) { static_cast<ListingItemModel*>(this->sourceModel())->setDisassembler(disassembler); }

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

    return this->createIndex(row, column);
}

QModelIndex ListingFilterModel::mapFromSource(const QModelIndex &sourceindex) const
{
    if(!this->canFilter() || !sourceindex.isValid())
        return QIdentityProxyModel::mapFromSource(sourceindex);

    ListingItemModel* listingitemmodel = reinterpret_cast<ListingItemModel*>(this->sourceModel());
    auto location = listingitemmodel->address(sourceindex);

    if(!location.valid)
        return QModelIndex();

    size_t idx = m_filtereditems.indexOf(location);

    if(idx == REDasm::npos)
        return QModelIndex();

    return this->index(idx, sourceindex.column());
}

QModelIndex ListingFilterModel::mapToSource(const QModelIndex &proxyindex) const
{
    if(!this->canFilter() || !proxyindex.isValid())
        return QIdentityProxyModel::mapToSource(proxyindex);

    ListingItemModel* listingitemmodel = reinterpret_cast<ListingItemModel*>(this->sourceModel());
    size_t idx = listingitemmodel->m_items.indexOf(m_filtereditems[proxyindex.row()]);

    if(idx == REDasm::npos)
        return QModelIndex();

    return listingitemmodel->index(idx, proxyindex.column());
}

void ListingFilterModel::updateFiltering()
{
    this->beginResetModel();
    m_filtereditems.clear();

    if(this->canFilter())
    {
        ListingItemModel* listingitemmodel = reinterpret_cast<ListingItemModel*>(this->sourceModel());

        for(int i = 0; i < listingitemmodel->rowCount(); i++)
        {
            for(int j = 0; j < listingitemmodel->columnCount(); j++)
            {
                QModelIndex index = listingitemmodel->index(i, j);
                QVariant data = listingitemmodel->data(index);

                if((data.type() != QVariant::String) || (data.toString().indexOf(m_filterstring, 0, Qt::CaseInsensitive) == -1))
                    continue;

                m_filtereditems.push_back(listingitemmodel->address(index));
                break;
            }
        }
    }

    this->endResetModel();
}

bool ListingFilterModel::canFilter() const { return m_filterstring.length() >= FILTER_MIN_CHARS; }

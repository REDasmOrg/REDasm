#include "listingfiltermodel.h"

ListingFilterModel::ListingFilterModel(QObject *parent) : QSortFilterProxyModel(parent) { this->setDynamicSortFilter(false); }
const QString &ListingFilterModel::filter() const { return m_filterstring; }
void ListingFilterModel::setDisassembler(REDasm::DisassemblerAPI *disassembler) { reinterpret_cast<ListingItemModel*>(this->sourceModel())->setDisassembler(disassembler); }

void ListingFilterModel::setFilter(const QString &filter)
{
    m_filterstring = filter;
    this->invalidateFilter();
}

bool ListingFilterModel::filterAcceptsRow(int source_row, const QModelIndex &) const
{
    if(m_filterstring.length() < 2)
        return true;

    QAbstractItemModel* sourcemodel = this->sourceModel();

    for(int i = 0; i < this->columnCount(); i++)
    {
        QVariant data = sourcemodel->data(sourcemodel->index(source_row, i));

        if(data.type() != QVariant::String)
            continue;

        if(data.toString().indexOf(m_filterstring, 0, Qt::CaseInsensitive) != -1)
            return true;
    }

    return false;
}

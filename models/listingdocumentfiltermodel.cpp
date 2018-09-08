#include "listingdocumentfiltermodel.h"
#include "../redasm/plugins/format.h"
#include <QColor>

ListingDocumentFilterModel::ListingDocumentFilterModel(u32 itemfilter, QObject *parent) : QSortFilterProxyModel(parent), m_filteritem(itemfilter) { this->setSourceModel(new ListingDocumentModel(this)); }
void ListingDocumentFilterModel::setDefaultFont(bool b) { static_cast<ListingDocumentModel*>(this->sourceModel())->setDefaultFont(b); }

void ListingDocumentFilterModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;
    static_cast<ListingDocumentModel*>(this->sourceModel())->setDisassembler(disassembler);
}

void ListingDocumentFilterModel::setFilterName(const QString &filtername)
{
    m_filtername = filtername;
    this->invalidateFilter();
}

const QString &ListingDocumentFilterModel::filterName() const { return m_filtername; }

bool ListingDocumentFilterModel::filterAcceptsRow(int source_row, const QModelIndex &) const
{
    QAbstractItemModel* sourcemodel = this->sourceModel();
    QModelIndex index = sourcemodel->index(source_row, 0);
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());

    if(item->type != m_filteritem)
        return false;

    if(m_filtername.isEmpty())
        return true;

    for(int i = 0; i < this->columnCount(); i++)
    {
        QVariant data = sourcemodel->data(sourcemodel->index(source_row, i));

        if(data.type() != QMetaType::QString)
            continue;

        if(data.toString().indexOf(m_filtername, 0, Qt::CaseInsensitive) != -1)
            return true;
    }

    return false;
}

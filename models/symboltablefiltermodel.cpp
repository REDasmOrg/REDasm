#include "symboltablefiltermodel.h"
#include "../../redasm/disassembler/listing/listingdocument.h"

SymbolTableFilterModel::SymbolTableFilterModel(u32 symbolflags, QObject *parent) : ListingDocumentFilterModel(REDasm::ListingItem::SymbolItem, parent), m_symbolflags(symbolflags)
{

}

bool SymbolTableFilterModel::filterAcceptsRow(int source_row, const QModelIndex & source_parent) const
{
    bool res = ListingDocumentFilterModel::filterAcceptsRow(source_row, source_parent);

    if(!res)
        return false;

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(this->sourceModel()->index(source_row, 0).internalPointer());

    if(!item)
        return false;

    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(item->address);
    return symbol->is(m_symbolflags);
}

#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(u32 symbolflags, QObject *parent) : ListingItemModel(REDasm::ListingItem::SymbolItem, parent), m_symbolflags(symbolflags) { }

bool SymbolTableModel::isItemAllowed(REDasm::ListingItem *item) const
{
    if(!ListingItemModel::isItemAllowed(item))
        return false;

    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(item->address);
    return symbol && symbol->is(m_symbolflags);
}

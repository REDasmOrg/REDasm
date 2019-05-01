#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(size_t itemtype, QObject *parent) : ListingItemModel(itemtype, parent), m_symbolflags(REDasm::SymbolTypes::None) { }
void SymbolTableModel::setSymbolFlags(u32 symbolflags) { m_symbolflags = symbolflags; }

bool SymbolTableModel::isItemAllowed(const REDasm::ListingItem *item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!item->is(REDasm::ListingItem::FunctionItem) && !item->is(REDasm::ListingItem::SymbolItem)))
        return false;

    const REDasm::Symbol* symbol = m_disassembler->document()->symbol(item->address);
    return symbol && symbol->is(m_symbolflags);
}

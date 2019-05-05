#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(size_t itemtype, QObject *parent) : ListingItemModel(itemtype, parent), m_symboltype(REDasm::SymbolType::None) { }
void SymbolTableModel::setSymbolType(REDasm::SymbolType type) { m_symboltype = type; }

bool SymbolTableModel::isItemAllowed(const REDasm::ListingItem *item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!item->is(REDasm::ListingItem::FunctionItem) && !item->is(REDasm::ListingItem::SymbolItem)))
        return false;

    const REDasm::Symbol* symbol = m_disassembler->document()->symbol(item->address);
    return symbol && symbol->is(m_symboltype);
}

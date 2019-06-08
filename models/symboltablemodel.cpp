#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(REDasm::ListingItemType itemtype, QObject *parent) : ListingItemModel(itemtype, parent), m_symboltype(REDasm::SymbolType::None) { }
void SymbolTableModel::setSymbolType(REDasm::SymbolType type) { m_symboltype = type; }

bool SymbolTableModel::isItemAllowed(const REDasm::ListingItem *item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!item->is(REDasm::ListingItemType::FunctionItem) && !item->is(REDasm::ListingItemType::SymbolItem)))
        return false;

    const REDasm::Symbol* symbol = m_disassembler->document()->symbol(item->address());
    return symbol && symbol->is(m_symboltype);
}

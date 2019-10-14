#include "symboltablemodel.h"
#include <redasm/context.h>

SymbolTableModel::SymbolTableModel(REDasm::ListingItemType itemtype, QObject *parent) : ListingItemModel(itemtype, parent) { }
void SymbolTableModel::setSymbolType(REDasm::SymbolType type) { m_symboltype = type; }
void SymbolTableModel::setSymbolFlags(REDasm::SymbolFlags flags) { m_symbolflags = flags; }

bool SymbolTableModel::isItemAllowed(const REDasm::ListingItem& item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!item.is(REDasm::ListingItemType::FunctionItem) && !item.is(REDasm::ListingItemType::SymbolItem)))
        return false;

    const REDasm::Symbol* symbol = r_docnew->symbol(item.address_new);
    if(!symbol || !symbol->typeIs(m_symboltype)) return false;
    if(m_symbolflags == REDasm::SymbolFlags::None) return true;
    return symbol->hasFlag(m_symbolflags);
}

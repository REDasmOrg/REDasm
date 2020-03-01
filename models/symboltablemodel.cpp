#include "symboltablemodel.h"
#include <redasm/context.h>

SymbolTableModel::SymbolTableModel(REDasm::ListingItemType itemtype, QObject *parent): ListingItemModel(itemtype, parent) { }
void SymbolTableModel::setSymbolType(type_t type) { m_symboltype = type; }
void SymbolTableModel::setSymbolFlags(flag_t flags) { m_symbolflags = flags; }

bool SymbolTableModel::isItemAllowed(const REDasm::ListingItem& item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!item.is(REDasm::ListingItemType::FunctionItem) && !item.is(REDasm::ListingItemType::SymbolItem)))
        return false;

    const REDasm::Symbol* symbol = r_doc->symbol(item.address);
    if(!symbol || !REDasm::typeIs(symbol, m_symboltype)) return false;
    if(m_symbolflags == REDasm::SymbolFlags::None) return true;
    return REDasm::hasFlag(symbol, m_symbolflags);
}

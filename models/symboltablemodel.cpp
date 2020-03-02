#include "symboltablemodel.h"
#include <redasm/context.h>

SymbolTableModel::SymbolTableModel(type_t itemtype, QObject *parent): ListingItemModel(itemtype, parent) { }
void SymbolTableModel::setSymbolType(type_t type) { m_symboltype = type; }
void SymbolTableModel::setSymbolFlags(flag_t flags) { m_symbolflags = flags; }

bool SymbolTableModel::isItemAllowed(const REDasm::ListingItem& item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!item.is(REDasm::ListingItem::FunctionItem) && !item.is(REDasm::ListingItem::SymbolItem)))
        return false;

    const REDasm::Symbol* symbol = r_doc->symbol(item.address);
    if(!symbol || !REDasm::typeIs(symbol, m_symboltype)) return false;
    if(m_symbolflags == REDasm::Symbol::T_None) return true;
    return REDasm::hasFlag(symbol, m_symbolflags);
}

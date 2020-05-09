#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(type_t itemtype, QObject *parent): ListingItemModel(itemtype, parent) { }
void SymbolTableModel::setSymbolType(type_t type) { m_symboltype = type; }
void SymbolTableModel::setSymbolFlags(flag_t flags) { m_symbolflags = flags; }

bool SymbolTableModel::isItemAllowed(const RDDocumentItem& item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!IS_TYPE(&item, DocumentItemType_Function) && !IS_TYPE(&item, DocumentItemType_Symbol)))
        return false;

    RDSymbol symbol;

    if(!RDDocument_GetSymbolByAddress(m_document, item.address, &symbol) || (symbol.type != m_symboltype)) return false;
    if(m_symbolflags == SymbolType_None) return true;
    return symbol.flags & m_symbolflags;
}

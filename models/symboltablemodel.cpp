#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(type_t itemtype, QObject *parent): ListingItemModel(itemtype, parent) { }
void SymbolTableModel::setSymbolType(type_t type) { m_symboltype = type; }
void SymbolTableModel::setSymbolFlags(flag_t flags) { m_symbolflags = flags; }

bool SymbolTableModel::isItemAllowed(const RDDocumentItem& item) const
{
    if(!ListingItemModel::isItemAllowed(item) || (!IS_TYPE(&item, DocumentItemType_Function) && !IS_TYPE(&item, DocumentItemType_Symbol)))
        return false;

    auto it = m_symbols.find(item.address);
    if(it == m_symbols.end()) return false;

    if(m_symbolflags == SymbolType_None) return true;
    return it->second.flags & m_symbolflags;
}

void SymbolTableModel::onItemChanged(const RDDocumentEventArgs* e)
{
    RDSymbol symbol;
    if(!RDDocument_GetSymbolByAddress(m_document, e->item.address, &symbol) || (symbol.type != m_symboltype)) return;
    m_symbols[e->item.address] = symbol;

    ListingItemModel::onItemChanged(e);
}

void SymbolTableModel::onItemRemoved(const RDDocumentEventArgs* e)
{
    ListingItemModel::onItemRemoved(e);
    m_symbols.erase(e->item.address);
}

void SymbolTableModel::insertItem(const RDDocumentItem& item)
{
    RDSymbol symbol;
    if(!RDDocument_GetSymbolByAddress(m_document, item.address, &symbol) || (symbol.type != m_symboltype)) return;
    m_symbols[item.address] = symbol;

    ListingItemModel::insertItem(item);
}

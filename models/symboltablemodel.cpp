#include "symboltablemodel.h"

SymbolTableModel::SymbolTableModel(rd_type itemtype, QObject *parent): ListingItemModel(itemtype, parent) { }
void SymbolTableModel::setSymbolType(rd_type type) { m_symboltype = type; }
void SymbolTableModel::setSymbolFlags(rd_flag flags) { m_symbolflags = flags; }
rd_type SymbolTableModel::symbolType() const { return m_symboltype; }
rd_flag SymbolTableModel::symbolFlags() const { return m_symbolflags; }

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

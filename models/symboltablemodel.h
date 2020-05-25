#pragma once

#include <unordered_map>
#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(type_t itemtype, QObject *parent = nullptr);
        void setSymbolType(type_t type);
        void setSymbolFlags(flag_t flags);

    protected:
        bool isItemAllowed(const RDDocumentItem& item) const override;
        void onItemChanged(const RDDocumentEventArgs* e) override;
        void onItemRemoved(const RDDocumentEventArgs* e) override;
        void insertItem(const RDDocumentItem& item) override;

    protected:
        std::unordered_map<address_t, RDSymbol> m_symbols;

    private:
        type_t m_symboltype{SymbolType_None};
        flag_t m_symbolflags{SymbolFlags_None};
};

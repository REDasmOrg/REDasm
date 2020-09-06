#pragma once

#include <unordered_map>
#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(rd_type itemtype, QObject *parent = nullptr);
        void setSymbolType(rd_type type);
        void setSymbolFlags(rd_flag flags);
        rd_type symbolType() const;
        rd_flag symbolFlags() const;

    protected:
        bool isItemAllowed(const RDDocumentItem& item) const override;
        void onItemChanged(const RDDocumentEventArgs* e) override;
        void onItemRemoved(const RDDocumentEventArgs* e) override;
        void insertItem(const RDDocumentItem& item) override;

    private:
        std::unordered_map<rd_address, RDSymbol> m_symbols;
        rd_type m_symboltype{SymbolType_None};
        rd_flag m_symbolflags{SymbolFlags_None};
};

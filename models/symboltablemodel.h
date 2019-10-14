#pragma once

#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(REDasm::ListingItemType itemtype, QObject *parent = nullptr);
        void setSymbolType(REDasm::SymbolType type);
        void setSymbolFlags(REDasm::SymbolFlags flags);

    protected:
        bool isItemAllowed(const REDasm::ListingItem& item) const override;

    private:
        REDasm::SymbolType m_symboltype{REDasm::SymbolType::None};
        REDasm::SymbolFlags m_symbolflags{REDasm::SymbolFlags::None};
};

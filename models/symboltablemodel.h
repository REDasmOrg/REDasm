#pragma once

#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(REDasm::ListingItemType itemtype, QObject *parent = nullptr);
        void setSymbolType(type_t type);
        void setSymbolFlags(flag_t flags);

    protected:
        bool isItemAllowed(const REDasm::ListingItem& item) const override;

    private:
        type_t m_symboltype{REDasm::SymbolType::None};
        flag_t m_symbolflags{REDasm::SymbolFlags::None};
};

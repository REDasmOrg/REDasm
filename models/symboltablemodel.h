#pragma once

#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(REDasm::ListingItemType itemtype, QObject *parent = nullptr);
        void setSymbolType(REDasm::SymbolType type);

    protected:
        bool isItemAllowed(const REDasm::ListingItem& item) const override;

    private:
        REDasm::SymbolType m_symboltype;
};

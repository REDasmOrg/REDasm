#ifndef SYMBOLTABLEMODEL_H
#define SYMBOLTABLEMODEL_H

#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(size_t itemtype, QObject *parent = nullptr);
        void setSymbolType(REDasm::SymbolType type);

    protected:
        virtual bool isItemAllowed(const REDasm::ListingItem *item) const;

    private:
        REDasm::SymbolType m_symboltype;
};

#endif // SYMBOLTABLEMODEL_H

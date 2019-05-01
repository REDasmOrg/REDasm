#ifndef SYMBOLTABLEMODEL_H
#define SYMBOLTABLEMODEL_H

#include "listingitemmodel.h"

class SymbolTableModel : public ListingItemModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(size_t itemtype, QObject *parent = NULL);
        void setSymbolFlags(u32 symbolflags);

    protected:
        virtual bool isItemAllowed(const REDasm::ListingItem *item) const;

    private:
        u32 m_symbolflags;
};

#endif // SYMBOLTABLEMODEL_H

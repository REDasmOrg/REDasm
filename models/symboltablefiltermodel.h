#ifndef SYMBOLTABLEFILTERMODEL_H
#define SYMBOLTABLEFILTERMODEL_H

#include "listingdocumentfiltermodel.h"

class SymbolTableFilterModel : public ListingDocumentFilterModel
{
    Q_OBJECT

    public:
        explicit SymbolTableFilterModel(u32 symbolflags, QObject *parent = nullptr);

    protected:
        virtual bool filterAcceptsRow(int source_row, const QModelIndex&source_parent) const;

    private:
        u32 m_symbolflags;
};

#endif // SYMBOLTABLEFILTERMODEL_H

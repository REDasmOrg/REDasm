#ifndef LISTINGDOCUMENTFILTERMODEL_H
#define LISTINGDOCUMENTFILTERMODEL_H

#include <QSortFilterProxyModel>
#include "listingdocumentmodel.h"

class ListingDocumentFilterModel : public QSortFilterProxyModel
{
    Q_OBJECT

    public:
        explicit ListingDocumentFilterModel(u32 itemfilter, QObject *parent = 0);
        void setDefaultFont(bool b);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void setFilterName(const QString& filtername);
        const QString& filterName() const;

    protected:
        virtual bool filterAcceptsRow(int source_row, const QModelIndex&) const;

    protected:
        REDasm::DisassemblerAPI* m_disassembler;

    private:
        QString m_filtername;
        u32 m_filteritem;
};

#endif // LISTINGDOCUMENTFILTERMODEL_H

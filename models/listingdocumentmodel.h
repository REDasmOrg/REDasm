#ifndef LISTINGDOCUMENTMODEL_H
#define LISTINGDOCUMENTMODEL_H

#include "disassemblermodel.h"
#include "../../redasm/disassembler/listing/listingdocument.h"

class ListingDocumentModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ListingDocumentModel(QObject *parent = 0);
        virtual void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    public:
        virtual QModelIndex index(int row, int column, const QModelIndex &) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual int columnCount(const QModelIndex&) const;
        virtual int rowCount(const QModelIndex&) const;

    protected:
        virtual void onListingChanged(const REDasm::ListingDocumentChanged *ldc);
};

#endif // LISTINGDOCUMENTMODEL_H

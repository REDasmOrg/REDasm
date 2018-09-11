#ifndef LISTINGITEMMODEL_H
#define LISTINGITEMMODEL_H

#include "disassemblermodel.h"
#include "../../redasm/disassembler/listing/listingdocument.h"

class ListingItemModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ListingItemModel(u32 itemtype, QObject *parent = NULL);
        virtual void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    public:
        virtual QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const;
        virtual int rowCount(const QModelIndex& = QModelIndex()) const;
        virtual int columnCount(const QModelIndex& = QModelIndex()) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual QVariant data(const QModelIndex &index, int role) const;

    protected:
        virtual bool isItemAllowed(REDasm::ListingItem* item) const;

    private:
        void onListingChanged(const REDasm::ListingDocumentChanged *ldc);

    private:
        QVector<REDasm::ListingItem*> m_items;
        u32 m_itemtype;

    friend class ListingFilterModel;
};

#endif // LISTINGITEMMODEL_H

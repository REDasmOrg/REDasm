#ifndef LISTINGITEMMODEL_H
#define LISTINGITEMMODEL_H

#include <QList>
#include "disassemblermodel.h"
#include <redasm/disassembler/listing/listingdocument.h>

class ListingItemModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ListingItemModel(size_t itemtype, QObject *parent = NULL);
        virtual void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

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
        QList<REDasm::ListingItem*> m_items;
        size_t m_itemtype;

    friend class ListingFilterModel;
};

#endif // LISTINGITEMMODEL_H

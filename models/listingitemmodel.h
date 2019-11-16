#pragma once

#include <QList>
#include "disassemblermodel.h"
#include <redasm/disassembler/listing/document/listingdocumentnew.h>
#include <redasm/disassembler/listing/backend/listingitems.h>

class ListingItemModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ListingItemModel(REDasm::ListingItemType itemtype, QObject *parent = nullptr);
        ~ListingItemModel();
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler) override;
        REDasm::ListingItem item(const QModelIndex& index) const;
        address_location address(const QModelIndex& index) const;

    public:
        QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    protected:
        virtual bool isItemAllowed(const REDasm::ListingItem& item) const;

    private:
        void onListingChanged(const REDasm::EventArgs* e);

    private:
        REDasm::SortedList m_items;
        REDasm::ListingItemType m_itemtype;

    friend class ListingFilterModel;
};

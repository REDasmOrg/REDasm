#pragma once

#include "../listingitemmodel.h"

class GotoModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit GotoModel(QObject *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler) override;

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;

    private:
        QColor itemColor(const REDasm::ListingItem& item) const;
        QString itemName(const REDasm::ListingItem& item) const;
        QString itemType(const REDasm::ListingItem& item) const;
};

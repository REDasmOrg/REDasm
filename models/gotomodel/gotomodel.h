#pragma once

#include "../listingitemmodel.h"
#include <rdapi/rdapi.h>

class GotoModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit GotoModel(QObject *parent = nullptr);
        void setDisassembler(RDDisassembler* disassembler) override;

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;

    private:
        QColor itemColor(const RDDocumentItem& item) const;
        QString itemName(const RDDocumentItem& item) const;
        QString itemType(const RDDocumentItem& item) const;
};

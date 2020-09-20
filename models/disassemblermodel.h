#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include "../hooks/idisassemblercommand.h"

class DisassemblerModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DisassemblerModel(QObject *parent = nullptr);

    public:
        const RDDisassemblerPtr& disassembler() const;
        virtual void setDisassembler(const RDDisassemblerPtr& disassembler);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    protected:
        RDDisassemblerPtr m_disassembler;
        RDDocument* m_document{nullptr};
};

#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>

class DisassemblerModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DisassemblerModel(QObject *parent = nullptr);

    public:
        const RDDisassembler* disassembler() const;
        virtual void setDisassembler(RDDisassembler* disassembler);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    protected:
        RDDisassembler* m_disassembler;
};

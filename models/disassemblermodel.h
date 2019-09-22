#pragma once

#include <QAbstractListModel>
#include <redasm/disassembler/disassembler.h>

#define S_TO_QS(s) QString::fromUtf8(s.c_str())

class DisassemblerModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DisassemblerModel(QObject *parent = nullptr);

    public:
        const REDasm::DisassemblerPtr& disassembler() const;
        virtual void setDisassembler(const REDasm::DisassemblerPtr& disassembler);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    protected:
        REDasm::DisassemblerPtr m_disassembler;
};

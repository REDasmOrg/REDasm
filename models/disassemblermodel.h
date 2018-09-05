#ifndef DISASSEMBLERMODEL_H
#define DISASSEMBLERMODEL_H

#include <QAbstractListModel>
#include "../redasm/disassembler/disassembler.h"

#define S_TO_QS(s) QString::fromStdString(s)

class DisassemblerModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DisassemblerModel(QObject *parent = 0);
        virtual void setDisassembler(REDasm::Disassembler* disassembler);

    protected:
        REDasm::Disassembler* m_disassembler;
};

#endif // DISASSEMBLERMODEL_H

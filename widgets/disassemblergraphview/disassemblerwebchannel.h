#ifndef DISASSEMBLERWEBCHANNEL_H
#define DISASSEMBLERWEBCHANNEL_H

#include <QObject>
#include "../../redasm/disassembler/disassemblerapi.h"

class DisassemblerWebChannel : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerWebChannel(REDasm::DisassemblerAPI* disassembler, QObject *parent = nullptr);

    public slots:
        void updateLine(int line);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
};

#endif // DISASSEMBLERWEBCHANNEL_H

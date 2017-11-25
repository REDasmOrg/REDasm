#ifndef DISASSEMBLERTHREAD_H
#define DISASSEMBLERTHREAD_H

#include <QThread>
#include "../../redasm/disassembler/disassembler.h"

class DisassemblerThread : public QThread
{
    Q_OBJECT

    public:
        explicit DisassemblerThread(REDasm::Disassembler* disassembler, QObject *parent = 0);

    protected:
        virtual void run();

    private:
        REDasm::Disassembler* _disassembler;
};

#endif // DISASSEMBLERTHREAD_H

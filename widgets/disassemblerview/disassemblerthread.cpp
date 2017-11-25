#include "disassemblerthread.h"

DisassemblerThread::DisassemblerThread(REDasm::Disassembler *disassembler, QObject *parent) : QThread(parent), _disassembler(disassembler)
{

}

void DisassemblerThread::run()
{
    this->_disassembler->disassemble();
}

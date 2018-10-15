#ifndef CONTROLFLOW_H
#define CONTROLFLOW_H

#include "algorithm.h"

namespace REDasm {

class ControlFlowAlgorithm: public AssemblerAlgorithm
{
    public:
        ControlFlowAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void addressTableState(const State* state);
        virtual void onDecoded(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // CONTROLFLOW_H

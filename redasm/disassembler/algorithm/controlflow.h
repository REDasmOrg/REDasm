#ifndef CONTROLFLOW_H
#define CONTROLFLOW_H

#include "../../plugins/disassembler/algorithm.h"

namespace REDasm {

class DisassemblerControlFlow: public DisassemblerAlgorithm
{
    public:
        DisassemblerControlFlow(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void addressTableState(const State* state);
        virtual void onDecoded(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // CONTROLFLOW_H

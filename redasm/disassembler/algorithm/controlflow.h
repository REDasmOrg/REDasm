#ifndef CONTROLFLOW_H
#define CONTROLFLOW_H

#include "../../plugins/disassembler/algorithm.h"

namespace REDasm {

class DisassemblerControlFlow: public DisassemblerAlgorithm
{
    public:
        DisassemblerControlFlow(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onDisassembled(const InstructionPtr& instruction, u32 result);
};

} // namespace REDasm

#endif // CONTROLFLOW_H

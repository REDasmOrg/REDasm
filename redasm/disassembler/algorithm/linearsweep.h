#ifndef LINEARSWEEP_H
#define LINEARSWEEP_H

#include "../../plugins/disassembler/algorithm.h"

namespace REDasm {

class DisassemblerLinearSweep: public DisassemblerAlgorithm
{
    public:
        DisassemblerLinearSweep(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onDisassembled(const InstructionPtr& instruction, u32 result);
};

} // namespace REDasm

#endif // LINEARSWEEP_H

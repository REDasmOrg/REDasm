#ifndef LINEARSWEEP_H
#define LINEARSWEEP_H

#include "../../plugins/disassembler/algorithm.h"

namespace REDasm {

class DisassemblerLinearSweep: public DisassemblerAlgorithm
{
    public:
        DisassemblerLinearSweep(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onDecodeFailed(const InstructionPtr& instruction);
        virtual void onDecoded(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // LINEARSWEEP_H

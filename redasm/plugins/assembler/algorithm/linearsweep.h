#ifndef LINEARSWEEP_H
#define LINEARSWEEP_H

#include "algorithm.h"

namespace REDasm {

class LinearSweepAlgorithm: public AssemblerAlgorithm
{
    public:
        LinearSweepAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onDecodeFailed(const InstructionPtr& instruction);
        virtual void onDecoded(const InstructionPtr& instruction);
};

} // namespace REDasm

#endif // LINEARSWEEP_H

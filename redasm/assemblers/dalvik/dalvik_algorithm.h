#ifndef DALVIK_ALGORITHM_H
#define DALVIK_ALGORITHM_H

#include "../../disassembler/algorithm/controlflow.h"

namespace REDasm {

class DalvikAlgorithm: public ControlFlowAlgorithm
{
    DEFINE_STATES(StringIndexState = UserState, MethodIndexState)

    public:
        DalvikAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onDecodedOperand(const InstructionPtr& instruction, const Operand& op);
        virtual void stringIndexState(const State* state);
        virtual void methodIndexState(const State* state);
};

} // namespace REDasm

#endif // DALVIK_ALGORITHM_H

#ifndef DEX_ALGORITHM_H
#define DEX_ALGORITHM_H

#include "../../disassembler/algorithm/controlflow.h"

namespace REDasm {

class DexAlgorithm: public DisassemblerControlFlow
{
    DEFINE_STATES(StringIndexState = UserState, MethodIndexState)

    public:
        DexAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onDecodedOperand(const InstructionPtr& instruction, const Operand& op);
        virtual void stringIndexState(const State* state);
        virtual void methodIndexState(const State* state);
};

} // namespace REDasm

#endif // DEX_ALGORITHM_H

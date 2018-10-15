#ifndef METAARM_ALGORITHM_H
#define METAARM_ALGORITHM_H

#include "../../plugins/assembler/algorithm/controlflow.h"

namespace REDasm {

class MetaARMAlgorithm : public ControlFlowAlgorithm
{
    DEFINE_STATES(SwitchAssemblerState = AssemblerAlgorithm::UserState)

    public:
        MetaARMAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onEmulatedOperand(const InstructionPtr& instruction, const Operand& op);
        virtual void switchAssemblerState(const State* state);

};

} // namespace REDasm

#endif // METAARM_ALGORITHM_H

#ifndef METAARM_ALGORITHM_H
#define METAARM_ALGORITHM_H

#include "../../plugins/assembler/algorithm/controlflow.h"

namespace REDasm {

class MetaARMAlgorithm : public ControlFlowAlgorithm
{
    public:
        MetaARMAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assemblerplugin);

    protected:
        virtual void onEmulatedOperand(const Operand& op, const InstructionPtr& instruction, u64 value);
        virtual void enqueueTarget(address_t target, const InstructionPtr& instruction);
        virtual void decodeState(State *state);

    private:
        std::unordered_map<address_t, bool> m_armstate;

};

} // namespace REDasm

#endif // METAARM_ALGORITHM_H

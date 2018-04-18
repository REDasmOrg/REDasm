#ifndef ARM_COMMON_H
#define ARM_COMMON_H

#include <capstone.h>
#include "../../redasm.h"

namespace REDasm {

class ARMCommon
{
    public:
        static bool decode(const InstructionPtr& instruction);

    private:
        static bool isPC(register_t reg);
        static void analyzeInstruction(const InstructionPtr& instruction, cs_insn *insn);
};

} // namespace REDasm

#endif // ARM_COMMON_H

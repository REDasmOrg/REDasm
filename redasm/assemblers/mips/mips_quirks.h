#ifndef MIPS_QUIRKS_H
#define MIPS_QUIRKS_H

#include <unordered_map>
#include <functional>
#include "../../redasm.h"

namespace REDasm {

namespace MIPSRegisterTypes
{
    enum {
        Cop2Register = 0x00000001,
    };
}

class MIPSQuirks
{
    private:
        typedef std::function<bool(u32, const InstructionPtr&)> DecodeCallback;
        typedef std::function<void(u32, const InstructionPtr&)> InstructionCallback;

    private:
        MIPSQuirks();
        static void initOpCodes();
        static void decodeCop2(u32 data, const InstructionPtr& instruction);
        static void decodeCtc2(u32 data, const InstructionPtr& instruction);
        static void decodeCfc2(u32 data, const InstructionPtr& instruction);
        static bool decodeCop2Opcode(u32 data, const InstructionPtr& instruction);

    public:
        static bool decode(BufferRef &buffer, const InstructionPtr& instruction);

    private:
        static std::unordered_map<u32, DecodeCallback> m_opcodetypes;
        static std::unordered_map<u32, InstructionCallback> m_cop2map;
};

}

#endif // MIPS_QUIRKS_H

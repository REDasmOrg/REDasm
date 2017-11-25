#ifndef MIPSQUIRKS_H
#define MIPSQUIRKS_H

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
        static void decodeCtc2(u32 data, const InstructionPtr& instruction);
        static bool decodeCop2(u32 data, const InstructionPtr& instruction);

    public:
        static bool decode(Buffer buffer, const InstructionPtr& instruction);

    private:
        static std::unordered_map<u32, DecodeCallback> _opcodemap;
        static std::unordered_map<u32, InstructionCallback> _cop2map;
};

}

#endif // MIPSQUIRKS_H

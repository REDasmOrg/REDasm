#include "mips_quirks.h"

#define COP2_INS_MASK 0x03E00000
#define COP2_OPCODE   0x00000012
#define COP2_INS_CTC2 0x00000006

#define CAPSTONE_REG(r) ((r) + 1) // NOTE: Capstone uses INVALID as 0

namespace REDasm {

std::unordered_map<u32, MIPSQuirks::DecodeCallback> MIPSQuirks::_opcodemap;
std::unordered_map<u32, MIPSQuirks::InstructionCallback> MIPSQuirks::_cop2map;

MIPSQuirks::MIPSQuirks()
{

}

bool MIPSQuirks::decode(Buffer buffer, const InstructionPtr &instruction)
{
    initOpCodes();

    u32 data = *reinterpret_cast<u32*>(buffer.data), opcode = data >> 26;
    auto cb = _opcodemap.find(opcode);

    if(cb != _opcodemap.end())
        return cb->second(data, instruction);

    return false;
}

bool MIPSQuirks::decodeCop2(u32 data, const InstructionPtr &instruction)
{
    u32 ins = (data & COP2_INS_MASK) >> 21;
    auto cb = _cop2map.find(ins);

    if(cb != _cop2map.end())
    {
        cb->second(data, instruction);
        return true;
    }

    return false;
}

void MIPSQuirks::initOpCodes()
{
    if(_opcodemap.empty())
    {
        _opcodemap[COP2_OPCODE] = &MIPSQuirks::decodeCop2;
    }

    if(_cop2map.empty())
    {
        _cop2map[COP2_INS_CTC2] = &MIPSQuirks::decodeCtc2;
    }
}

void MIPSQuirks::decodeCtc2(u32 data, const InstructionPtr &instruction)
{
    instruction->reset();

    instruction->mnemonic = "ctc2";
    instruction->size = 4;

    instruction->reg(CAPSTONE_REG((data & 0x1F0000) >> 16))
                .reg((data & 0xF800) >> 11, MIPSRegisterTypes::Cop2Register);
}

}

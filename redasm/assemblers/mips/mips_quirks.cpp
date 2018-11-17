#include "mips_quirks.h"

#define COP2_MASK        0x03E00000
#define COP2_OPCODE_TYPE 0x48000000

#define COP2_INS_COP2    0x4A000000
#define COP2_INS_CFC2    0x00400000
#define COP2_INS_CTC2    0x00C00000

#define CAPSTONE_REG(r) ((r) + 1) // NOTE: Capstone uses INVALID as 0

namespace REDasm {

std::unordered_map<u32, MIPSQuirks::DecodeCallback> MIPSQuirks::m_opcodetypes;
std::unordered_map<u32, MIPSQuirks::InstructionCallback> MIPSQuirks::m_cop2map;

MIPSQuirks::MIPSQuirks() { }

bool MIPSQuirks::decode(BufferRef& buffer, const InstructionPtr &instruction)
{
    initOpCodes();

    u32 data = static_cast<u32>(buffer), opcode = data & 0xFC000000;
    auto cb = m_opcodetypes.find(opcode);

    if(cb != m_opcodetypes.end())
        return cb->second(data, instruction);

    return false;
}

bool MIPSQuirks::decodeCop2Opcode(u32 data, const InstructionPtr &instruction)
{
    if(data & COP2_INS_COP2)
    {
        instruction->reset();
        decodeCop2(data, instruction);
        return true;
    }

    u32 ins = data & COP2_MASK;
    auto cb = m_cop2map.find(ins);

    if(cb != m_cop2map.end())
    {
        instruction->reset();
        cb->second(data, instruction);
        return true;
    }

    return false;
}

void MIPSQuirks::initOpCodes()
{
    if(m_opcodetypes.empty())
    {
        m_opcodetypes[COP2_OPCODE_TYPE] = &MIPSQuirks::decodeCop2Opcode;
    }

    if(m_cop2map.empty())
    {
        m_cop2map[COP2_INS_CFC2] = &MIPSQuirks::decodeCfc2;
        m_cop2map[COP2_INS_CTC2] = &MIPSQuirks::decodeCtc2;
    }
}

void MIPSQuirks::decodeCop2(u32 data, const InstructionPtr &instruction)
{
    instruction->mnemonic = "cop2";
    instruction->size = 4;
    instruction->imm(data & 0x00FFFFFF);
}

void MIPSQuirks::decodeCtc2(u32 data, const InstructionPtr &instruction)
{
    instruction->mnemonic = "ctc2";
    instruction->size = 4;

    instruction->reg(CAPSTONE_REG((data & 0x1F0000) >> 16))
            .reg((data & 0xF800) >> 11, MIPSRegisterTypes::Cop2Register);
}

void MIPSQuirks::decodeCfc2(u32 data, const InstructionPtr &instruction)
{
    instruction->mnemonic = "cfc2";
    instruction->size = 4;

    instruction->reg(CAPSTONE_REG((data & 0x1F0000) >> 16))
            .reg((data & 0xF800) >> 11, MIPSRegisterTypes::Cop2Register);

}

}

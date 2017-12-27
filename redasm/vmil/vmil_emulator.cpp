#include "vmil_emulator.h"

#define SET_EXECUTE_OPCODE(op) _opmap[VMIL::Opcodes::op] = [this](const InstructionPtr& instruction) { emulate##op(instruction); }
#define SET_NULL_OPCODE(op)    _opmap[VMIL::Opcodes::op] = NULL;

#define EXECUTE_MATH_OPCODE(instruction, mathop) u64 res = this->read(instruction->operands[1]) mathop \
                                                           this->read(instruction->operands[2]); \
                                                 this->write(instruction->operands[0], res)

#define DATA_TRANSFER(instruction, from, to) this->write(instruction->operands[to], this->read(instruction->operands[from]))
#define SET_CONDITION(instruction, from, to) this->write(instruction->operands[to], (this->read(instruction->operands[from]) == 0));

namespace REDasm {
namespace VMIL {

Emulator::Emulator(DisassemblerFunctions *disassembler): _disassembler(disassembler), _defregister(VMIL_REGISTER_ID(0))
{
    SET_EXECUTE_OPCODE(Add);
    SET_EXECUTE_OPCODE(Sub);
    SET_EXECUTE_OPCODE(Mul);
    SET_EXECUTE_OPCODE(Div);
    SET_EXECUTE_OPCODE(Mod);
    SET_EXECUTE_OPCODE(Lsh);
    SET_EXECUTE_OPCODE(Rsh);
    SET_EXECUTE_OPCODE(And);
    SET_EXECUTE_OPCODE(Or);
    SET_EXECUTE_OPCODE(Xor);
    SET_EXECUTE_OPCODE(Str);
    SET_EXECUTE_OPCODE(Ldm);
    SET_EXECUTE_OPCODE(Stm);
    SET_EXECUTE_OPCODE(Bisz);
    SET_EXECUTE_OPCODE(Jcc);

    SET_NULL_OPCODE(Nop);
    SET_NULL_OPCODE(Undef);
    SET_NULL_OPCODE(Unkn);
}

Emulator::~Emulator()
{

}

void Emulator::setDefaultRegister(vmilregister_t reg)
{
    this->_defregister = reg;
}

vmilregister_t Emulator::defaultRegister() const
{
    return this->_defregister;
}

void Emulator::translate(const InstructionPtr &instruction, VMILInstructionList &vminstructions)
{
    instruction_id_t id = this->getInstructionId(instruction);
    VMIL::VMILInstructionPtr vminstruction;

    auto it = this->_translatemap.find(id);

    if(it != this->_translatemap.end())
        it->second(instruction, vminstruction, vminstructions);

    if(!vminstructions.empty())
        return;

    vminstructions.push_back(VMIL::emitUnkn(instruction));
}

void Emulator::emulate(const InstructionPtr &instruction)
{
    VMILInstructionList vminstructions;
    this->translate(instruction, vminstructions);

    std::for_each(vminstructions.begin(), vminstructions.end(), [this](const VMILInstructionPtr& vminstruction) {
        auto it = this->_opmap.find(vminstruction->id);

        if(it == this->_opmap.end()) {
            REDasm::log("Cannot emulate '" + vminstruction->mnemonic + "' instruction");
            return;
        }

        if(it->second)
            it->second(vminstruction);
    });
}

void Emulator::reset()
{
    this->_tempregisters.clear();
    this->_registers.clear();
    this->_memory.clear();
}

instruction_id_t Emulator::getInstructionId(const InstructionPtr &instruction) const
{
    return instruction->id;
}

void Emulator::emitDisplacement(const InstructionPtr &instruction, u32 opidx, VMILInstructionList &vminstructions) const
{
    Operand opmem = instruction->op(opidx);

    VMILInstructionPtr vminstruction = VMIL::emitStr(instruction);
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstruction->reg(opmem.mem.base.r, opmem.type);
    vminstructions.push_back(vminstruction);

    if(opmem.mem.displacement)
    {
        vminstruction = VMIL::emitInstruction(instruction, (opmem.mem.displacement > 0) ? VMIL::Opcodes::Add :
                                                                                          VMIL::Opcodes::Sub, VMIL_INSTRUCTION_I(vminstructions));

        vminstruction->reg(VMIL_DEFAULT_REGISTER);
        vminstruction->reg(VMIL_DEFAULT_REGISTER);
        vminstruction->imm(opmem.mem.displacement);
        vminstructions.push_back(vminstruction);
    }
}

void Emulator::emitEQ(const InstructionPtr& instruction, u32 opidx1, u32 opidx2, VMIL::VMILInstructionList &vminstructions) const
{
    VMILInstructionPtr vminstruction;

    vminstruction = VMIL::emitXor(instruction);
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstruction->op(instruction->op(opidx1));
    vminstruction->op(instruction->op(opidx2));
    vminstructions.push_back(vminstruction);

    vminstruction = VMIL::emitBisz(instruction);
    vminstruction->address = VMIL_INSTRUCTION_ADDRESS_I(instruction, 1);
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstructions.push_back(vminstruction);
}

void Emulator::emitNEQ(const InstructionPtr &instruction, u32 opidx1, u32 opidx2, VMIL::VMILInstructionList &vminstructions) const
{
    VMILInstructionPtr vminstruction;

    vminstruction = VMIL::emitXor(instruction);
    vminstruction->reg(VMIL_DEFAULT_REGISTER);
    vminstruction->op(instruction->op(opidx1));
    vminstruction->op(instruction->op(opidx2));
    vminstructions.push_back(vminstruction);
}

void Emulator::write(const Operand &operand, u64 value)
{
    if(operand.is(OperandTypes::Memory))
    {
        this->writeMemory(operand.u_value, value);
        return;
    }

    if(!operand.is(OperandTypes::Register))
        return;

    if(operand.reg.type == VMIL_REG_OPERAND)
        this->writeT(operand.reg.r, value);
    else
        this->write(operand.reg.r, value);
}

u64 Emulator::read(const Operand &operand)
{
    if(operand.is(OperandTypes::Register))
    {
        if(operand.reg.type == VMIL_REG_OPERAND)
            return this->readT(operand.reg.r);

        return this->read(operand.reg.r);
    }
    else if(operand.is(OperandTypes::Memory))
        return this->readMemory(operand.u_value);

    return operand.u_value;
}

void Emulator::writeT(register_t reg, u64 value)
{
    this->writeRegister(this->_tempregisters, reg, value);
}

void Emulator::write(register_t reg, u64 value)
{
    this->writeRegister(this->_registers, reg, value);
}

u64 Emulator::readT(register_t reg)
{
    return this->readRegister(this->_tempregisters, reg);
}

u64 Emulator::read(register_t reg)
{
    return this->readRegister(this->_registers, reg);
}

void Emulator::writeMemory(address_t address, u64 value)
{
    this->_memory[address] = value;
}

u64 Emulator::readMemory(address_t address)
{
    auto it = this->_memory.find(address);

    if(it != this->_memory.end())
        return it->second;

    u64 value = 0;

    if(!this->_disassembler->readAddress(address, 4, value))  // TODO: Set operand size
        REDasm::log("Cannot read @ " + REDasm::hex(address));

    return value;
}

void Emulator::writeRegister(Emulator::Registers &registers, register_t reg, u64 value)
{
    auto it = registers.find(reg);

    if(it == registers.end())
        registers[reg] = value;
    else
        it->second = value;
}

u64 Emulator::readRegister(Emulator::Registers &registers, register_t reg)
{
    auto it = registers.find(reg);

    if(it == registers.end())
        return 0;

    return it->second;
}

void Emulator::emulateAdd(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, +);  }
void Emulator::emulateSub(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, -);  }
void Emulator::emulateMul(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, *);  }
void Emulator::emulateDiv(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, /);  }
void Emulator::emulateMod(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, %);  }
void Emulator::emulateLsh(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, <<); }
void Emulator::emulateRsh(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, >>); }
void Emulator::emulateAnd(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, &);  }
void Emulator::emulateOr(const VMILInstructionPtr &instruction)   { EXECUTE_MATH_OPCODE(instruction, |);  }
void Emulator::emulateXor(const VMILInstructionPtr &instruction)  { EXECUTE_MATH_OPCODE(instruction, ^);  }
void Emulator::emulateStr(const VMILInstructionPtr &instruction)  { DATA_TRANSFER(instruction, 1, 0); }
void Emulator::emulateLdm(const VMILInstructionPtr &instruction)  { DATA_TRANSFER(instruction, 1, 0); }
void Emulator::emulateStm(const VMILInstructionPtr &instruction)  { DATA_TRANSFER(instruction, 1, 0); }
void Emulator::emulateBisz(const VMILInstructionPtr &instruction) { SET_CONDITION(instruction, 1, 0); }

void Emulator::emulateJcc(const VMILInstructionPtr &instruction)
{
    u64 cond = this->read(instruction->operands[0]);
    instruction->cmt("Jumps condition to " + REDasm::hex(this->read(instruction->operands[1])) + " = " + (cond ? "TRUE" : "FALSE"));
}

} // namespace VMIL
} // namespace REDasm

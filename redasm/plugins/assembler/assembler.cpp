#include "assembler.h"
#include "../format.h"
#include <iomanip>
#include <sstream>

namespace REDasm {

AssemblerPlugin::AssemblerPlugin(): Plugin(), _endianness(Endianness::LittleEndian)
{
}

u32 AssemblerPlugin::flags() const
{
    return AssemblerFlags::None;
}

VMIL::Emulator *AssemblerPlugin::createEmulator(DisassemblerAPI *disassembler) const
{
    RE_UNUSED(disassembler);
    return NULL;
}

Printer *AssemblerPlugin::createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const
{
    return new Printer(disassembler, symboltable);
}

void AssemblerPlugin::analyzeOperand(DisassemblerAPI *disassembler, const InstructionPtr &instruction, const Operand &operand) const
{
    if(operand.is(OperandTypes::Register))
    {
        this->analyzeRegister(disassembler, instruction, operand);
        return;
    }
    else if(!operand.isNumeric())
        return;

    u64 value = operand.u_value;
    const Segment* segment = disassembler->format()->segment(value);

    if(!segment)
        return;

    SymbolTable* symboltable = disassembler->symbolTable();

    if(operand.isRead() && disassembler->dereferenceOperand(operand, &value))
    {
        symboltable->createLocation(operand.u_value, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
        disassembler->pushReference(operand.u_value, instruction);
    }

    if(instruction->is(InstructionTypes::Jump))
    {
        if(!operand.is(OperandTypes::Memory))
        {
            int dir = BRANCH_DIRECTION(instruction, value);

            if(dir < 0)
                instruction->cmt("Possible loop");
            else if(!dir)
                instruction->cmt("Infinite loop");

            disassembler->updateInstruction(instruction);
            symboltable->createLocation(value, SymbolTypes::Code);
        }
        else
            disassembler->checkJumpTable(instruction, operand);

        disassembler->pushReference(value, instruction);
    }
    else if(instruction->is(InstructionTypes::Call) && instruction->hasTargets() && (operand.index == instruction->target_idx))
    {
        disassembler->pushReference(value, instruction);
        disassembler->disassembleFunction(value);
    }
    else
    {
        Segment* segment = disassembler->format()->segment(value);

        if(!segment)
            return;

        if(segment->is(SegmentTypes::Data) || segment->is(SegmentTypes::Bss))
            disassembler->checkLocation(instruction, value); // Create Symbol + XRefs
        else if(segment->is(SegmentTypes::Code))
            disassembler->checkString(instruction, value);   // Create Symbol + XRefs
        else
            return;

        disassembler->pushReference(value, instruction);
    }
}

void AssemblerPlugin::prepare(const InstructionPtr &instruction)
{
    RE_UNUSED(instruction);
}

bool AssemblerPlugin::decode(Buffer buffer, const InstructionPtr &instruction)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for(u64 i = 0; i < instruction->size; i++)
    {
        u8 b = buffer[i];
        ss << std::setw(2) << static_cast<size_t>(b);
    }

    instruction->bytes = ss.str();
    return false;
}

bool AssemblerPlugin::done(const InstructionPtr &instruction)
{
    if(this->_statestack.top().first & AssemblerFlags::DelaySlot)
    {
        this->_statestack.top().first &= ~AssemblerFlags::DelaySlot;
        return this->_statestack.top().second;
    }

    if(instruction->is(InstructionTypes::Jump))
    {
        if(this->flags() & AssemblerFlags::DelaySlot)
        {
            this->_statestack.top().first |= AssemblerFlags::DelaySlot;
            this->_statestack.top().second = !instruction->is(InstructionTypes::Conditional);
            return false;
        }

        return !instruction->is(InstructionTypes::Conditional);
    }

    if(instruction->is(InstructionTypes::Stop))
    {
        this->_statestack.top().first &= ~AssemblerFlags::DelaySlot;
        return true;
    }

    return false;
}

bool AssemblerPlugin::hasFlag(u32 flag) const
{
    return this->flags() & flag;
}

bool AssemblerPlugin::hasVMIL() const
{
    return this->hasFlag(AssemblerFlags::HasVMIL);
}

bool AssemblerPlugin::canEmulateVMIL() const
{
    return this->hasFlag(AssemblerFlags::EmulateVMIL);
}

endianness_t AssemblerPlugin::endianness() const
{
    return this->_endianness;
}

void AssemblerPlugin::setEndianness(endianness_t endianness)
{
    this->_endianness = endianness;
}

void AssemblerPlugin::pushState()
{
    this->_statestack.push(std::make_pair(AssemblerFlags::None, 0));
}

void AssemblerPlugin::popState()
{
    this->_statestack.pop();
}

void AssemblerPlugin::analyzeRegister(DisassemblerAPI *disassembler, const InstructionPtr &instruction, const Operand &operand) const
{
    if(!disassembler->emulator() || !operand.is(OperandTypes::Register))
        return;

    address_t target = 0;

    if(!disassembler->emulator()->read(operand, target))
        return;

    Segment* segment = disassembler->format()->segment(target);

    if(!segment)
        return;

    if(segment->is(SegmentTypes::Data) && operand.isWrite())
    {
        instruction->cmt("VMIL WRITE @ " + segment->name + ":" + REDasm::hex(target));
        disassembler->checkLocation(instruction, target); // Updates instruction
        return;
    }

    if(!segment->is(SegmentTypes::Code))
        return;

    this->analyzeRegisterBranch(target, disassembler, instruction, operand);
}

void AssemblerPlugin::analyzeRegisterBranch(address_t target, DisassemblerAPI *disassembler, const InstructionPtr &instruction, const Operand &operand) const
{
    if(!instruction->is(InstructionTypes::Branch) || (operand.index != instruction->target_idx))
        return;

    REDasm::log("VMIL @ " + REDasm::hex(instruction->address) + " jumps to " + REDasm::hex(target));

    if(!this->canEmulateVMIL())
    {
        instruction->cmt("VMIL = " + REDasm::hex(target));
        disassembler->updateInstruction(instruction);
        return;
    }

    Segment* segment = disassembler->format()->segment(target);

    if(!segment || !segment->is(SegmentTypes::Code))
        return;

    if(instruction->is(InstructionTypes::Call))
        disassembler->symbolTable()->createFunction(target);
    else
        disassembler->symbolTable()->createLocation(target, SymbolTypes::Code);

    SymbolPtr symbol = disassembler->symbolTable()->symbol(target);
    instruction->target(target);
    instruction->cmt("VMIL = " + symbol->name);
    disassembler->pushReference(symbol, instruction); // Updates instruction
}

}

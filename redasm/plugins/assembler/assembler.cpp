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

VMIL::Emulator *AssemblerPlugin::createEmulator(DisassemblerFunctions *disassembler) const
{
    RE_UNUSED(disassembler);
    return NULL;
}

Printer *AssemblerPlugin::createPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable) const
{
    return new Printer(disassembler, symboltable);
}

void AssemblerPlugin::analyzeOperand(DisassemblerFunctions *disassembler, const InstructionPtr &instruction, const Operand &operand) const
{
    if(operand.is(OperandTypes::Register))
    {
        this->analyzeRegister(disassembler, instruction, operand);
        return;
    }

    SymbolTable* symboltable = disassembler->symbolTable();
    u64 value = operand.is(OperandTypes::Displacement) ? operand.mem.displacement : operand.u_value, opvalue = value;
    SymbolPtr symbol = symboltable->symbol(value);

    if(!symbol || (symbol && !symbol->is(SymbolTypes::Import))) // Don't try to dereference imports
    {
        if(operand.is(OperandTypes::Memory) && (operand.isRead() || instruction->is(InstructionTypes::Branch)))
        {
            if(disassembler->dereferencePointer(value, opvalue)) // Try to read pointed memory
                symboltable->createLocation(value, SymbolTypes::Data | SymbolTypes::Pointer); // Create Symbol for pointer
        }
    }
    else if(symbol->is(SymbolTypes::Pointer))
        disassembler->dereferencePointer(value, opvalue); // read pointed memory

    const Segment* segment = disassembler->format()->segment(opvalue);

    if(!segment)
        return;

    if(instruction->is(InstructionTypes::Call) && instruction->hasTargets() && (operand.index == instruction->target_idx))
        disassembler->disassembleFunction(opvalue);
    else if(instruction->is(InstructionTypes::Jump))
    {
        if(!operand.is(OperandTypes::Displacement) || operand.mem.displacementOnly())
        {
            int dir = BRANCH_DIRECTION(instruction, opvalue);

            if(dir < 0)
                instruction->cmt("Possible loop");
            else if(!dir)
                instruction->cmt("Infinite loop");

            disassembler->updateInstruction(instruction);
            symboltable->createLocation(opvalue, SymbolTypes::Code);
        }
        else
            disassembler->checkJumpTable(instruction, operand);
    }
    else if(!segment->is(SegmentTypes::Bss))
    {
        disassembler->checkString(instruction, opvalue);
        return; // checkString() creates xrefs
    }
    else
    {
        disassembler->checkLocation(instruction, opvalue);
        return; // checkLocation() creates xrefs
    }

    symbol = symboltable->symbol(opvalue);

    if(symbol)
        disassembler->pushReference(symbol, instruction->address);
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

void AssemblerPlugin::analyzeRegister(DisassemblerFunctions *disassembler, const InstructionPtr &instruction, const Operand &operand) const
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
        disassembler->updateInstruction(instruction);

        if(!segment->is(SegmentTypes::Bss))
            disassembler->checkLocation(instruction, target);

        return;
    }

    if(!segment->is(SegmentTypes::Code))
        return;

    this->analyzeRegisterBranch(target, disassembler, instruction, operand);
}

void AssemblerPlugin::analyzeRegisterBranch(address_t target, DisassemblerFunctions *disassembler, const InstructionPtr &instruction, const Operand &operand) const
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

    if(instruction->is(InstructionTypes::Call))
        disassembler->symbolTable()->createFunction(target);
    else
        disassembler->symbolTable()->createLocation(target, SymbolTypes::Code);

    SymbolPtr symbol = disassembler->symbolTable()->symbol(target);

    instruction->target(target);
    instruction->cmt("VMIL = " + symbol->name);
    disassembler->updateInstruction(instruction);
    disassembler->pushReference(symbol, instruction->address);
}

}

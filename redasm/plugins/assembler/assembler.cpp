#include "assembler.h"
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
    if(this->_statestack.top() & AssemblerFlags::DelaySlot)
    {
        this->_statestack.top() &= ~AssemblerFlags::DelaySlot;
        return true;
    }

    if((instruction->is(InstructionTypes::Jump) && !instruction->is(InstructionTypes::Conditional)))
    {
        if(this->flags() & AssemblerFlags::DelaySlot)
        {
            this->_statestack.top() |= AssemblerFlags::DelaySlot;
            return false;
        }

        return true;
    }

    if(instruction->is(InstructionTypes::Stop))
    {
        this->_statestack.top() &= ~AssemblerFlags::DelaySlot;
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
    this->_statestack.push(AssemblerFlags::None);
}

void AssemblerPlugin::popState()
{
    this->_statestack.pop();
}

}

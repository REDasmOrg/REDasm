#include "processor.h"
#include <iomanip>
#include <sstream>

namespace REDasm {

ProcessorPlugin::ProcessorPlugin(): Plugin()
{
}

u32 ProcessorPlugin::flags() const
{
    return ProcessorFlags::None;
}

VMIL::Emulator *ProcessorPlugin::createEmulator(DisassemblerFunctions *disassembler) const
{
    RE_UNUSED(disassembler);
    return NULL;
}

Printer *ProcessorPlugin::createPrinter(DisassemblerFunctions *disassembler, SymbolTable *symboltable) const
{
    RE_UNUSED(disassembler);
    RE_UNUSED(symboltable);
    return NULL;
}

bool ProcessorPlugin::decode(Buffer buffer, const InstructionPtr &instruction)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for(u64 i = 0; i < instruction->size; i++)
    {
        u8 b = buffer[i];
        ss << std::setw(2) << static_cast<size_t>(b);
    }

    instruction->bytes = ss.str();
    return true;
}

bool ProcessorPlugin::done(const InstructionPtr &instruction)
{
    if(this->_statestack.top() & ProcessorFlags::DelaySlot)
    {
        this->_statestack.top() &= ~ProcessorFlags::DelaySlot;
        return true;
    }

    if((instruction->is(InstructionTypes::Jump) && !instruction->is(InstructionTypes::Conditional)))
    {
        if(this->flags() & ProcessorFlags::DelaySlot)
        {
            this->_statestack.top() |= ProcessorFlags::DelaySlot;
            return false;
        }

        return true;
    }

    if(instruction->is(InstructionTypes::Stop))
    {
        this->_statestack.top() &= ~ProcessorFlags::DelaySlot;
        return true;
    }

    return false;
}

bool ProcessorPlugin::hasFlag(u32 flag) const
{
    return this->flags() & flag;
}

bool ProcessorPlugin::hasVMIL() const
{
    return this->hasFlag(ProcessorFlags::HasVMIL);
}

bool ProcessorPlugin::canEmulateVMIL() const
{
    return this->hasFlag(ProcessorFlags::EmulateVMIL);
}

void ProcessorPlugin::pushState()
{
    this->_statestack.push(ProcessorFlags::None);
}

void ProcessorPlugin::popState()
{
    this->_statestack.pop();
}

}

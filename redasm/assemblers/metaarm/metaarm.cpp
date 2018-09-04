#include "metaarm.h"
#include "metaarm_emulator.h"

namespace REDasm {

MetaARMAssembler::MetaARMAssembler(): AssemblerPlugin()
{
    this->_armassembler = new ARMAssembler();
    this->_thumbassembler = new ARMThumbAssembler();
}

MetaARMAssembler::~MetaARMAssembler()
{
    delete this->_thumbassembler;
    delete this->_armassembler;
}

u32 MetaARMAssembler::flags() const
{
    return this->_armassembler->flags();
}

const char *MetaARMAssembler::name() const
{
    return "Meta ARM";
}

bool MetaARMAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    AssemblerPlugin* assemblerplugin = this->_armassembler;

    if(instruction->address & 0x1)
        assemblerplugin = this->_thumbassembler;

    return assemblerplugin->decode(buffer, instruction);
}

VMIL::Emulator *MetaARMAssembler::createEmulator(DisassemblerAPI *disassembler) const
{
    return new MetaARMEmulator(disassembler);
}

Printer *MetaARMAssembler::createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const
{
    return new MetaARMPrinter(this->_armassembler->handle(), disassembler, symboltable);
}

} // namespace REDasm

#include "metaarm.h"
#include "metaarm_emulator.h"

namespace REDasm {

MetaARMAssembler::MetaARMAssembler(): AssemblerPlugin(), _currentassembler(NULL)
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

void MetaARMAssembler::prepare(const InstructionPtr &instruction) // Switch ARM <-> Thumb (http://www.davespace.co.uk/arm/introduction-to-arm/pc.html)
{
    if(instruction->address & 0x1) // THUMB mode
    {
        this->_currentassembler = this->_thumbassembler;
        instruction->address &= -1ull ^ 0x1;
        return;
    }

    // ARM Mode
    this->_currentassembler = this->_armassembler;
    instruction->address &= -1ull ^ 0x3;
}

bool MetaARMAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    return this->_currentassembler->decode(buffer, instruction);
}

VMIL::Emulator *MetaARMAssembler::createEmulator(DisassemblerAPI *disassembler) const
{
    return new MetaARMEmulator(disassembler);
}

Printer *MetaARMAssembler::createPrinter(DisassemblerAPI *disassembler, SymbolTable *symboltable) const
{
    csh csh = this->_currentassembler == this->_armassembler ? this->_armassembler->handle() :
                                                               this->_thumbassembler->handle();

    return new MetaARMPrinter(csh, disassembler, symboltable);
}

} // namespace REDasm

#include "metaarm.h"

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

const char *MetaARMAssembler::name() const
{
    return "Meta ARM";
}

bool MetaARMAssembler::decode(Buffer buffer, const InstructionPtr &instruction)
{
    this->selectAssembler(instruction);
    return this->_currentassembler->decode(buffer, instruction);
}

void MetaARMAssembler::selectAssembler(const InstructionPtr &instruction) // http://www.davespace.co.uk/arm/introduction-to-arm/pc.html
{
    if(instruction->address & 0x1) // THUMB mode
    {
        this->_currentassembler = this->_thumbassembler;
        instruction->address ^= 0x1;
        return;
    }

    // ARM Mode
    this->_currentassembler = this->_armassembler;
    instruction->address ^= 0x3;
}

} // namespace REDasm

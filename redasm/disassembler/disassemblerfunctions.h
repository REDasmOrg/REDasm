#ifndef DISASSEMBLERFUNCTIONS_H
#define DISASSEMBLERFUNCTIONS_H

#include "../redasm.h"
#include "types/symboltable.h"

namespace REDasm {

class DisassemblerFunctions
{
    public:
        DisassemblerFunctions();
        virtual u64 locationIsString(address_t address, bool *wide = NULL) const = 0;
        virtual std::string readString(const SymbolPtr& symbol) const = 0;
        virtual std::string readWString(const SymbolPtr& symbol) const = 0;
        virtual std::string readHex(address_t address, u32 count) const = 0;
        virtual bool readAddress(address_t address, size_t size, u64 &value) const = 0;
        virtual bool readOffset(offset_t offset, size_t size, u64 &value) const = 0;
        virtual bool getBuffer(address_t address, Buffer& data) const = 0;
        virtual bool dataToString(address_t address) = 0;
        virtual SymbolPtr dereferenceSymbol(const SymbolPtr& symbol, u64* value = NULL) = 0;
        virtual InstructionPtr disassembleInstruction(address_t address) = 0;
        virtual bool disassemble(address_t address) = 0;
};

} // namespace REDasm

#endif // DISASSEMBLERFUNCTIONS_H

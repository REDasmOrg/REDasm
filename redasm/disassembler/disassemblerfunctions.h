#ifndef DISASSEMBLERFUNCTIONS_H
#define DISASSEMBLERFUNCTIONS_H

#define MIN_STRING       4
//#define MAX_STRING       200

#include "../redasm.h"
#include "types/symboltable.h"
#include "types/referencetable.h"

namespace REDasm {

class FormatPlugin;
class AssemblerPlugin;

namespace VMIL {
class Emulator;
}

class DisassemblerFunctions
{
    public:
        DisassemblerFunctions();
        virtual FormatPlugin* format() = 0;
        virtual AssemblerPlugin* assembler() = 0;
        virtual SymbolTable* symbolTable() = 0;
        virtual VMIL::Emulator* emulator() = 0;
        virtual ReferenceVector getReferences(address_t address) = 0;
        virtual ReferenceVector getReferences(const SymbolPtr &symbol) = 0;
        virtual u64 getReferencesCount(address_t address) = 0;
        virtual u64 getReferencesCount(const SymbolPtr &symbol) = 0;
        virtual bool hasReferences(const SymbolPtr &symbol) = 0;
        virtual void pushReference(const SymbolPtr& symbol, address_t address) = 0;
        virtual void updateInstruction(const InstructionPtr& instruction) = 0;
        virtual void checkJumpTable(const InstructionPtr& instruction, const Operand &operand) = 0;
        virtual void checkLocation(const InstructionPtr& instruction, address_t address) = 0;
        virtual bool checkString(const InstructionPtr& instruction, address_t address) = 0;
        virtual u64 locationIsString(address_t address, bool *wide = NULL) const = 0;
        virtual std::string readString(const SymbolPtr& symbol) const = 0;
        virtual std::string readString(address_t address) const = 0;
        virtual std::string readWString(const SymbolPtr& symbol) const = 0;
        virtual std::string readWString(address_t address) const = 0;
        virtual std::string readHex(address_t address, u32 count) const = 0;
        virtual bool readAddress(address_t address, size_t size, u64 &value) const = 0;
        virtual bool readOffset(offset_t offset, size_t size, u64 &value) const = 0;
        virtual bool getBuffer(address_t address, Buffer& data) const = 0;
        virtual bool dataToString(address_t address) = 0;
        virtual bool dereferencePointer(address_t address, u64& value) const = 0;
        virtual SymbolPtr dereferenceSymbol(const SymbolPtr& symbol, u64* value = NULL) = 0;
        virtual InstructionPtr disassembleInstruction(address_t address) = 0;
        virtual void disassembleFunction(address_t address, const std::string& name = std::string()) = 0;
        virtual bool disassemble(address_t address) = 0;
};

} // namespace REDasm

#endif // DISASSEMBLERFUNCTIONS_H

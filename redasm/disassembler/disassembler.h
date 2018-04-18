#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include "../plugins/plugins.h"
#include "types/listing.h"
#include "disassemblerbase.h"

namespace REDasm {

class Disassembler: public DisassemblerBase
{
    public:
        Disassembler(Buffer buffer, AssemblerPlugin* assembler, FormatPlugin* format);
        virtual ~Disassembler();
        Listing &listing();
        bool canBeJumpTable(address_t address) const;
        size_t walkJumpTable(const InstructionPtr &instruction, address_t address);
        void disassemble();

    public: // Primitive functions
        virtual AssemblerPlugin* assembler();
        virtual VMIL::Emulator* emulator();
        virtual void checkJumpTable(const InstructionPtr& instruction, const Operand &operand);
        virtual void updateInstruction(const InstructionPtr& instruction);
        virtual bool dataToString(address_t address);
        virtual InstructionPtr disassembleInstruction(address_t address);
        virtual void disassembleFunction(address_t address, const std::string& name = std::string());
        virtual bool disassemble(address_t address);

    public:
        std::string comment(const InstructionPtr& instruction) const;
        bool iterateVMIL(address_t address, Listing::InstructionCallback cbinstruction, Listing::SymbolCallback cbstart, Listing::InstructionCallback cbend, Listing::SymbolCallback cblabel);

    private:
        void disassembleUnexploredCode();
        void searchCode(const Segment &segment);
        void searchStrings(const Segment& segment);
        bool skipExploredData(address_t& address);
        bool skipPadding(address_t& address);
        bool maybeValidCode(address_t& address);
        void analyzeInstruction(const InstructionPtr& instruction);
        void makeInvalidInstruction(const InstructionPtr& instruction, Buffer &b);

    private:
        AssemblerPlugin* _assembler;
        VMIL::Emulator* _emulator;
        PrinterPtr _printer;
        Listing _listing;
};

}

#endif // DISASSEMBLER_H

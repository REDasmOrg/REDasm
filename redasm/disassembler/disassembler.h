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
        InstructionsPool &instructions();
        void disassemble();

    public: // Primitive functions
        virtual AssemblerPlugin* assembler();
        virtual VMIL::Emulator* emulator();
        virtual bool checkJumpTable(const InstructionPtr& instruction, address_t address);
        virtual void updateInstruction(const InstructionPtr& instruction);
        virtual bool dataToString(address_t address);
        virtual InstructionPtr disassembleInstruction(address_t address);
        virtual bool disassembleFunction(address_t address, const std::string& name = std::string());
        virtual void disassemble(address_t address);

    public:
        std::string comment(const InstructionPtr& instruction) const;
        bool iterateVMIL(address_t address, InstructionsPool::InstructionCallback cbinstruction, InstructionsPool::SymbolCallback cbstart, InstructionsPool::InstructionCallback cbend, InstructionsPool::SymbolCallback cblabel);

    private:
        void disassemble(DisassemblerAlgorithm *algorithm);
        void disassembleUnexploredCode();
        void searchCode(const Segment &segment);
        void searchStrings(const Segment& segment);
        bool skipExploredData(address_t& address);
        bool skipPadding(address_t& address);
        bool maybeValidCode(address_t& address);
        void createInvalid(const InstructionPtr& instruction, Buffer &b);
        void calculateBounds();
        size_t walkJumpTable(const InstructionPtr &instruction, address_t address);

    private:
        AssemblerPlugin* _assembler;
        VMIL::Emulator* _emulator;
        PrinterPtr _printer;
        InstructionsPool _listing;
};

}

#endif // DISASSEMBLER_H

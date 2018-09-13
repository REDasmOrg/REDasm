#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include "../plugins/plugins.h"
#include "../support/timer.h"
#include "listing/listingdocument.h"
#include "disassemblerbase.h"

namespace REDasm {

class Disassembler: public DisassemblerBase
{
    public:
        Disassembler(AssemblerPlugin* assembler, FormatPlugin* format);
        virtual ~Disassembler();
        ListingDocument* document();
        void disassemble();

    public: // Primitive functions
        virtual AssemblerPlugin* assembler();
        virtual bool checkJumpTable(const InstructionPtr& instruction, address_t address);
        virtual InstructionPtr disassembleInstruction(address_t address);
        virtual void disassemble(address_t address);

    private:
        void disassembleStep(DisassemblerAlgorithm *algorithm);
        void disassembleUnexploredCode();
        void searchCode(const Segment &segment);
        void searchStrings(const Segment& segment);
        bool skipExploredData(address_t& address);
        bool skipPadding(address_t& address);
        bool maybeValidCode(address_t& address);
        size_t walkJumpTable(const InstructionPtr &instruction, address_t address);

    private:
        std::unique_ptr<AssemblerPlugin> m_assembler;
        std::unique_ptr<DisassemblerAlgorithm> m_algorithm;
        Timer m_timer;
};

}

#endif // DISASSEMBLER_H

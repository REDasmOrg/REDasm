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
        virtual void disassemble();

    public: // Primitive functions
        virtual AssemblerPlugin* assembler();
        virtual InstructionPtr disassembleInstruction(address_t address);
        virtual void disassemble(address_t address);
        virtual void pause();
        virtual void resume();
        virtual size_t state() const;
        virtual bool busy() const;

    private:
        void disassembleStep(AssemblerAlgorithm *algorithm);

    private:
        std::unique_ptr<AssemblerPlugin> m_assembler;
        std::unique_ptr<AssemblerAlgorithm> m_algorithm;
        Timer m_timer;
};

}

#endif // DISASSEMBLER_H

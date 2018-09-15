#ifndef DISASSEMBLERALGORITHM_H
#define DISASSEMBLERALGORITHM_H

#include <stack>
#include <set>
#include "../../redasm.h"
#include "../../redasm/analyzer/analyzer.h"
#include "../assembler/assembler.h"

namespace REDasm {

class DisassemblerAlgorithm
{
    public:
        enum: u32 { OK, SKIP, FAIL };

    private:
        typedef std::set<address_t> DecodedAddresses;

    protected:
        DisassemblerAlgorithm(DisassemblerAPI* disassembler, AssemblerPlugin* assembler);

    public:
        u32 disassemble(address_t address, const InstructionPtr& instruction);
        u32 disassembleSingle(address_t address, const InstructionPtr& instruction);
        void push(address_t address);
        bool analyze();
        bool hasNext() const;
        address_t next();

    protected:
        virtual void onDisassembled(const InstructionPtr& instruction, u32 result);
        virtual void checkOperands(const InstructionPtr& instruction);

    private:
        bool canBeDisassembled(address_t address);
        void createInvalidInstruction(const InstructionPtr& instruction, const Buffer &buffer);

    protected:
        DisassemblerAPI* m_disassembler;
        AssemblerPlugin* m_assembler;
        ListingDocument* m_document;
        FormatPlugin* m_format;

    private:
        DecodedAddresses m_disassembled;
        std::stack<address_t> m_pending;
        std::unique_ptr<Analyzer> m_analyzer;
        const Segment* m_currentsegment;
        bool m_analyzed;
};

} // namespace REDasm

#endif // DISASSEMBLERALGORITHM_H
